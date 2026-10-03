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

/// §5.3 — which genesis family does this certificate belong to?
///
/// Returns the SPHINCS+ public key of the genesis validator it descends from,
/// or `None` if the certificate carries no lineage and is not itself a genesis
/// certificate.
///
/// ⚠ COMPARES `subject_pubkey_sphincs`, NOT `validator_id`. `GENESIS_VALIDATORS`
/// holds PUBLIC KEYS; `validator_id` is their BLAKE3. Passing the id can never
/// match — a mistake already present at three other call sites when this was
/// written (see the ⚠ on `is_approval_mature` below).
pub fn effective_genesis_lineage(vbc: &VBC) -> Option<[u8; 32]> {
    if vbc.genesis_lineage != [0u8; 32] {
        return Some(vbc.genesis_lineage);
    }
    // A genesis validator IS its own lineage, derived rather than stored so the
    // twenty deployed genesis certificates keep a byte-identical signing
    // pre-image and their existing signatures stay valid.
    if crate::genesis::is_genesis_validator(&vbc.subject_pubkey_sphincs) {
        let mut out = [0u8; 32];
        out.copy_from_slice(&vbc.subject_pubkey_sphincs);
        return Some(out);
    }
    None
}

/// Check whether a VBC holder is mature enough to approve new validators.
/// Genesis validators are always mature. Others must wait VBC_APPROVAL_MATURITY_SECS.
pub fn is_approval_mature(vbc: &VBC, current_time: u64) -> bool {
    // ⚠ WAS `&vbc.validator_id` until 2026-09-04, WHICH COULD NEVER MATCH.
    // `GENESIS_VALIDATORS` holds SPHINCS+ PUBLIC KEYS; `validator_id` is their
    // BLAKE3 — a different 32 bytes, and nothing about the shape says so. The
    // effect was that genesis validators were never treated as mature, i.e.
    // the exemption on the line below was dead. Inert in practice only because
    // this function has no production caller on the VBC path.
    if crate::genesis::is_genesis_validator(&vbc.subject_pubkey_sphincs) {
        return true;
    }
    current_time.saturating_sub(vbc.issued_at) >= crate::types::VBC_APPROVAL_MATURITY_SECS
}

/// Required number of issuer signatures per VBC (always k=3).
/// This is a protocol constant, not a dev convenience — even dev builds
/// must verify the full issuer chain. The `dev-mode` feature only gates
/// the WALLET_IDENTITY_KEY compile guard, not VBC validation.
pub const VBC_REQUIRED_ISSUERS: usize = 3;

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
// ⚠ `verify_vbc_bundle_with_tick` WAS HERE AND WAS DELETED 2026-09-04.
//
// It took the attested tick as a PARAMETER, and not one production call site
// ever passed one — every verifier in the SDK, Lambda and the send-proof path
// went through the no-tick entry below. §5.3 fails closed without a tick, so a
// freshly-issued depth>0 certificate was refused EVERYWHERE, including by the
// validator loading its own cert at startup. A RULE 3 shape-3 ghost: an API
// that looked like the answer and had no caller.
//
// RULED (the owner, 2026-09-04): the tick comes from THE CERTIFICATE'S OWN OODS
// STAMP — see `issuing_tick_for`.

/// §5.3 — the attested tick a certificate is judged on: its OWN OODS stamp.
///
/// RULED (the owner, 2026-09-04). The issuing bar asks "was this issuer fit to
/// admit anyone AT THE MOMENT IT ACTED", and the certificate records that
/// moment — `baseline_tick`, stamped from the Nabla reading the round carried,
/// covered by the issuer signatures, and BOUND BY CORE at issuance
/// (`execute_cl8` refuses a stamp that disagrees with the attestation it was
/// given). The answer is in the artifact, so a third party can verify offline
/// and forever, and no verifier needs a live reading.
///
/// The two rejected alternatives, recorded so this is not re-litigated:
///
///   - A verifier's OWN fresh tick would make the bar RETROACTIVE: an issuer
///     that has since aged would invalidate certificates it validly issued.
///     That is the exact failure §5.2.2a's lifetime-not-remaining-life rule
///     exists to prevent, and it would make offline verification impossible.
///   - Enforcing §5.3 only at issuance would move a consensus rule out of the
///     artifact and into the issuers' good behaviour (RULE 5 forbids it).
///
/// `0` is the YPX-021 §7 genesis-exempt sentinel and means NO stamp. Returned
/// as `None` so §5.3 fails closed on it: a depth>0 newcomer does not get to be
/// excused from the health judgement the record exists for.
#[inline]
pub fn issuing_tick_for(vbc: &VBC) -> Option<u64> {
    if vbc.baseline_tick == 0 { None } else { Some(vbc.baseline_tick) }
}

/// Q2-b (the owner ruled 2026-09-21) — detect a VBC RENEWAL in-guest.
///
/// A renewal request carries the requester's CURRENT certificate in
/// `supporting_vbcs` (the SDK appends `previous_vbc`), alongside the issuers'
/// certs. It is distinguished by SUBJECT identity: the prior cert shares the
/// target's SPHINCS+ subject key — the SAME discriminator Lambda's renewal gate
/// uses (`consensus.rs::commit_vbc_sign`). Moved into Core because the
/// proof-of-validation rule it gates must be enforced by Core, not Lambda
/// (RULE 5). Returns the prior cert (whose `baseline_tick` is the freshness
/// reference), or `None` on a FIRST issuance (no same-subject supporting cert).
///
/// The issuers' own certs never match: an issuer's subject is its own key, not
/// the candidate's, so a first-issuance bundle returns `None` and the CL8 gate
/// is skipped.
pub fn find_renewal_prev(bundle: &VBCProofBundle) -> Option<&VBC> {
    let subject = bundle.target_vbc.subject_pubkey_sphincs.as_slice();
    bundle
        .supporting_vbcs
        .iter()
        .find(|c| c.subject_pubkey_sphincs.as_slice() == subject)
}

/// Q2-b — verify a VBC renewal's PROOF-OF-VALIDATION receipt.
///
/// The renewing validator must present ONE k-signed receipt it CO-SIGNED during
/// the current cert's term — proof the identity did real witnessing work, so
/// that maintaining N Sybil identities is expensive (each must actually
/// participate). Everything is client-carried + verified here in-guest; no Nabla
/// (RULE 7). Orthogonal to the per-key candidacy Pulse (the machine cost).
///
/// `renewer_ed25519_pk` = the renewing cert's `subject_pubkey_ed25519` (the
/// validator's witness key; == the ban-target key the peer-audit uses).
/// `min_tick` = the current cert's `baseline_tick` (its OODS stamp). The three
/// checks, each its own error (RULE 3):
///   (a) FRESH: `oods_flag = Some(f)` with `f.tick > min_tick`. A `None`
///       oods_flag (heal / genesis / offline redeem) carries no tick and cannot
///       prove work THIS term → `VbcRenewalWorkReceiptStale`.
///   (b) REAL QUORUM: >=3 DISTINCT validators produced a valid
///       `receipt_commitment_sig` over the recomputed commitment — reuse the
///       Core-owned `crypto::verify_receipt_witness_quorum` (RULE 1, the same
///       verifier `validate_witnesses` uses) → `VbcRenewalWorkReceiptSubQuorum`.
///   (c) CO-SIGNED: the renewer's own key produced a VALID
///       `receipt_commitment_sig` over that commitment. Being merely LISTED in
///       `witness_sigs` proves nothing → `VbcRenewalNotCoSigned`.
pub fn verify_renewal_work_receipt(
    receipt: &crate::types::Receipt,
    renewer_ed25519_pk: &[u8],
    min_tick: u64,
) -> CoreResult<()> {
    // (a) FRESH — an online witnessed receipt from THIS term.
    let flag = match receipt.oods_flag.as_ref() {
        Some(f) => f,
        None => return Err(ValidationError::VbcRenewalWorkReceiptStale),
    };
    if flag.tick <= min_tick {
        return Err(ValidationError::VbcRenewalWorkReceiptStale);
    }

    // (b) REAL QUORUM — absolute floor 3 (YP §17.1.2). Count first (cheap +
    // clear), then the Core-owned quorum verifier (recompute + >=3 distinct
    // valid receipt_commitment_sigs). A zero commitment_hash never anchors.
    let floor = crate::types::NORMAL_WITNESS_FLOOR as usize;
    if receipt.witness_sigs.len() < floor || receipt.commitment_hash == [0u8; 32] {
        return Err(ValidationError::VbcRenewalWorkReceiptSubQuorum);
    }
    let quorum_ok = crate::crypto::verify_receipt_witness_quorum(
        &receipt.txid,
        &receipt.state_hash,
        receipt.new_wallet_seq,
        &receipt.commitment_hash,
        receipt.epoch,
        receipt.is_dev_class,
        receipt.oods_flag.as_ref(),
        receipt.confidence_index.as_ref(),
        receipt.sender_state.as_ref(),
        receipt.witness_sigs.iter().filter_map(|w| {
            w.receipt_commitment_sig
                .as_ref()
                .map(|s| (w.validator_pk.as_slice(), s.as_slice()))
        }),
        floor,
    );
    if !quorum_ok {
        return Err(ValidationError::VbcRenewalWorkReceiptSubQuorum);
    }

    // (c) CO-SIGNED — the renewer's key produced a VALID sig over this receipt's
    // commitment. Recompute the commitment once (the SAME pre-image the quorum
    // verifier used) and require the renewer's own receipt_commitment_sig to
    // verify. Merely appearing in witness_sigs is not proof (a fabricated entry).
    let commitment = crate::crypto::compute_receipt_commitment(
        &receipt.txid,
        &receipt.state_hash,
        receipt.new_wallet_seq,
        &receipt.commitment_hash,
        receipt.epoch,
        receipt.is_dev_class,
        receipt.oods_flag.as_ref(),
        receipt.confidence_index.as_ref(),
        receipt.sender_state.as_ref(),
    );
    let renewer_cosigned = receipt.witness_sigs.iter().any(|w| {
        w.validator_pk.as_slice() == renewer_ed25519_pk
            && w
                .receipt_commitment_sig
                .as_ref()
                .is_some_and(|s| crate::crypto::verify_ed25519(&w.validator_pk, &commitment, s).is_ok())
    });
    if !renewer_cosigned {
        return Err(ValidationError::VbcRenewalNotCoSigned);
    }

    Ok(())
}

pub fn verify_vbc_bundle(bundle: &VBCProofBundle, current_time: u64) -> CoreResult<()> {
    verify_vbc_bundle_inner(bundle, current_time, true)
}

/// §6b.5a — verify a certificate READ OUT OF PAST EVIDENCE (a receipt's witness
/// bundles, a cheque's signer bundle): the full chain, WITHOUT the Nabla
/// stamp. RULED B (the owner, 2026-09-08): that evidence was minted before a stamp
/// existed and the stamp sits outside the issuer signature, so history cannot
/// be upgraded; the stamp is a property of a credential PRESENTED NOW, which is
/// what `verify_vbc_bundle` checks. Use this ONLY where the bundle came out of
/// a receipt or cheque — never for a certificate a party presents about itself.
pub fn verify_vbc_bundle_historical(bundle: &VBCProofBundle, current_time: u64) -> CoreResult<()> {
    verify_vbc_bundle_inner(bundle, current_time, false)
}

/// YP §26.17.6.5 B2 — the REFERENCE a FACT witness carries to its certificate:
/// `BLAKE3("AXIOM_VBC_REF" || the certificate's signed pre-image)`. Keyed on the
/// SIGNED bytes rather than the bundle's serde layout, so a reference written
/// into a chain today still resolves after any wire-layout change, and two
/// bundles carrying the same signed certificate (with or without a Nabla stamp
/// or a candidacy Pulse beside it) share one reference — either verifies it.
pub fn vbc_reference_hash(vbc: &VBC) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_VBC_REF");
    hasher.update(&crate::crypto::compute_vbc_signing_payload_bytes(vbc));
    *hasher.finalize().as_bytes()
}

fn verify_vbc_bundle_inner(
    bundle: &VBCProofBundle,
    current_time: u64,
    require_stamp: bool,
) -> CoreResult<()> {
    let mut verified_pks: BTreeSet<Vec<u8>> = BTreeSet::new();
    verify_chain_recursive(
        &bundle.target_vbc,
        &bundle.supporting_vbcs,
        current_time,
        0,
        &mut verified_pks,
        VBC_REQUIRED_ISSUERS,
        root_authority_check,
        // §5.3 (2026-09-04) — depth>0 VBC chains are ENABLED. The SEC-10
        // deferral existed because no anti-Sybil admission rule had been
        // decided; the genesis-lineage rule below IS that rule, and it is
        // enforced by the `true` on the next line.
        true,
        true, // enforce §5.3 genesis lineage — VBC path only
    )?;
    // Reserved-name check runs only after the issuer chain verifies, so it bites
    // exactly the dangerous case: a root-authority-signed VBC that carries a
    // reserved Greek name illegitimately (mis-issuance / name-squat).
    enforce_genesis_name_reservation(&bundle.target_vbc)?;
    // ╔═══════════════════════════════════════════════════════════════════╗
    // ║  §6b.5 — A VBC IS NOT USABLE UNTIL NABLA STAMPS IT (flag day)      ║
    // ╚═══════════════════════════════════════════════════════════════════╝
    // Issuance produces a CANDIDATE; the stamp (`nabla_registration`) is what
    // makes it usable, and CORE checks it here — every production reliance
    // site (CL2/CL3 witness credential, CL8's previous/supporting certs,
    // Lambda's startup check, the SDK's send-proof verify) enters through
    // `verify_vbc_bundle`. Applies to the target AND every supporting VBC: an
    // issuer must itself be a stamped validator. Provisional certificates are
    // exempt (they cannot serve by §5.2.2a and exist only to bind a claim;
    // unstaked, Nabla could not stamp them), and this runs only on the
    // three-issuer (VBC) path — NBCs are never stamped (§6b.6).
    // `require_stamp == false` is the §6b.5a HISTORICAL path (ruled B): a
    // certificate read out of a receipt or cheque is verified by chain only.
    if require_stamp {
        for vbc in core::iter::once(&bundle.target_vbc).chain(bundle.supporting_vbcs.iter()) {
            if vbc.issuer_set.len() == VBC_REQUIRED_ISSUERS
                && !crate::validation::vbc_is_provisional(vbc.issued_at, vbc.expires_at)
            {
                crate::validation::verify_vbc_stamp(vbc)?;
            }
        }
    }
    Ok(())
}

/// Shared reserved-name enforcement. Compares a cert's `identity` bytes against
/// the pinned genesis key-set for whichever layer. A reserved Greek name
/// (`genesis::GREEK_NAMES`, short or formal form):
///   - ASSIGNED (slot < assigned_keys.len()) may ride ONLY its pinned key;
///   - UNASSIGNED (slot beyond, lambda..omega) may ride NO key.
/// Either violation → `GenesisNameReserved`. Stateless; `node_name` and the
/// compared identity field are both bound into the signed cert pre-image
/// (`crypto::compute_vbc_signing_payload_bytes`), so this compares
/// signature-covered fields.
///
/// ⚠ The two genesis tables are in DIFFERENT representations, so each caller
/// passes the matching `identity` field:
///   - `GENESIS_VALIDATORS` holds the raw SPHINCS+ **public keys** (the
///     post-quantum anchor, baked as pubkeys by the ceremony) → pass
///     `subject_pubkey_sphincs`.
///   - `NABLA_GENESIS_VALIDATORS` holds blake3 **node ids** → pass `validator_id`.
/// (Reconciling the two representations + the dead `is_genesis_validator` call
/// sites is tracked as its own KI — see KnownIssues.)
fn enforce_reserved_name(node_name: &str, identity: &[u8], assigned_keys: &[[u8; 32]]) -> CoreResult<()> {
    if let Some(i) = crate::genesis::reserved_name_index(node_name) {
        let allowed = i < assigned_keys.len() && identity == assigned_keys[i].as_slice();
        if !allowed {
            return Err(ValidationError::GenesisNameReserved);
        }
    }
    Ok(())
}

/// Validator side: `GENESIS_VALIDATORS` holds the raw SPHINCS+ PUBLIC KEYS (the
/// post-quantum anchor), so compare the VBC's own `subject_pubkey_sphincs` — NOT
/// `validator_id` (which is `blake3(sphincs_pk)`). A reserved genesis name can
/// therefore only ride the pinned genesis SPHINCS+ key.
pub fn enforce_genesis_name_reservation(vbc: &VBC) -> CoreResult<()> {
    enforce_reserved_name(&vbc.node_name, &vbc.subject_pubkey_sphincs, &crate::genesis::GENESIS_VALIDATORS)
}

/// Nabla side: `NABLA_GENESIS_VALIDATORS` holds blake3 node IDS, so compare the
/// NBC's `validator_id`. Same reserved names, separate (key-isolated) key-set — a
/// penguin's nabla-node "alpha" is a different key than its validator "alpha".
pub fn enforce_nabla_name_reservation(nbc: &VBC) -> CoreResult<()> {
    enforce_reserved_name(&nbc.node_name, &nbc.validator_id, &crate::nabla_genesis::NABLA_GENESIS_VALIDATORS)
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
        root_authority_check,
        // §5.3 lifted the SEC-10 deferral for VBC chains (see `verify_vbc_bundle_inner`);
        // this check must agree, or a community validator's whole bundle is refused at load
        // (ValidatorJoin §6b.12, measured 2026-09-15).
        true,
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
        true, // NBC citizen chains recurse depth>0 (validator-issued, no maturity concept)
        // §5.3 does NOT apply: an NBC is a Nabla citizen certificate with its
        // own root set and no genesis-family concept. Enforcing it here would
        // reject every legitimate citizen chain.
        false,
    )?;
    // Reserved Greek names are forbidden on the nabla side too — bound to the
    // nabla genesis key-set (NABLA_GENESIS_VALIDATORS), a separate isolation.
    enforce_nabla_name_reservation(&bundle.target_vbc)?;
    Ok(())
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
        true, // NBC citizen chains recurse depth>0
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
    use crate::types::CoreLogicMode;
    let tx_epoch = inputs.transaction.epoch;
    // HIGH-1 fix: epoch=0 bypass REMOVED. Dev-mode uses the dev-mode feature flag,
    // not epoch=0. An attacker could craft epoch=0 TXs to use expired VBCs.
    #[cfg(feature = "dev-mode")]
    if tx_epoch == 0 {
        return Ok(()); // Dev-mode only: skip time checks for testing
    }

    // ── KI#130: expiry "now" is the ATTESTED tick on the authoritative validator
    // paths, never the client-supplied `tx.epoch` ──────────────────────────────
    // RULING (the owner 2026-09-21): `tx.epoch` is client-supplied and BACKDATABLE — an
    // attacker sets it before a cert's expiry to keep witnessing with a dead VBC. On
    // CL2 (pre-sign) and CL3 (finalize) — the only two modes that reach this check
    // (CL1 client self-check / CL5 redeem / Ark do NOT call it) — judge expiry
    // against the round's Nabla-attested tick (`oods_attestation.tick`), which is
    // Nabla-signed and Core-verified. The attestation is verified HERE (option 1:
    // verify before its tick is trusted) because the surrounding CL3 verify runs
    // later; the shared `verify_oods_attestation` is reused (RULE 1). If a VBC is
    // being judged on an attested path but no valid attestation is present → fail
    // closed (`VBCNoAttestedTick`). Everything is SECONDS (the attested tick's
    // value); this is the twin of the KI#131 seconds fix. The ISSUING bar is
    // untouched — it uses the cert's OWN `baseline_tick` by a separate ruling.
    // ⚠ ARK EXEMPTION (HARD REQUIREMENT, the owner 2026-09-21): the Ark profile is the
    // OFFLINE tier — it carries `oods_attestation: None` BY DESIGN (ark_trade.rs /
    // ark_finalize.rs) and an Ark trade/unload can ride THROUGH CL3. So the attested
    // requirement must NOT be scoped by mode alone, or it would fail-closed every
    // Ark tx and render Ark useless. Detect Ark by the K_ARK tier of EITHER endpoint
    // (the same `extract_security_level` signal `both_endpoints_ark` /
    // validate_witnesses use — RULE 1) and, for it, behave exactly as before:
    // tx.epoch, no OODS requirement, no unusable window.
    let ark_involved = matches!(
        crate::wallet_id::extract_security_level(&inputs.transaction.sender_wallet_id),
        Ok((crate::wallet_id::K_ARK, _))
    ) || matches!(
        crate::wallet_id::extract_security_level(&inputs.transaction.receiver_wallet_id),
        Ok((crate::wallet_id::K_ARK, _))
    );
    let attested_mode =
        matches!(inputs.mode, CoreLogicMode::CL2 | CoreLogicMode::CL3) && !ark_involved;
    let judges_a_vbc = inputs
        .prev_receipts
        .iter()
        .flat_map(|r| r.witness_sigs.iter())
        .any(|w| w.vbc_bundle.is_some());

    let (now, now_is_attested): (u64, bool) = if attested_mode && judges_a_vbc {
        match inputs.oods_attestation.as_ref() {
            Some(att) => {
                crate::validation::verify_oods_attestation(att)
                    .map_err(|_| crate::types::ValidationError::OodsAttestationInvalid)?;
                (att.tick, true)
            }
            None => return Err(crate::types::ValidationError::VBCNoAttestedTick),
        }
    } else {
        (tx_epoch, false)
    };

    // KI#130 "loses usefulness N ticks before expiry" — LOCUS A (the owner ruling
    // 2026-09-21): the SERVING validator refuses to witness near its OWN expiry, so
    // this window is judged ONLY on the serving cert (`inputs.vbc_bundle`), never on
    // prev-receipt witnesses. Renewal-pressure HYGIENE (the cert is still valid; hard
    // expiry below is the real gate), so it runs only when we already hold an ATTESTED
    // `now` — a forgeable tx.epoch must not decide it — and is skipped when there is
    // no serving cert (k=0 offline trade) or on the Ark/non-attested path.
    // NOTE: the serving cert gets BOTH its hard expiry and the near-expiry window
    // checked here. Hard expiry FIRST so a genuinely-dead serving cert returns
    // VBCExpired (recovery: re-issue), not VBCUnusableSoon (recovery: renew) — the
    // unusable check below would also catch an expired cert (remaining 0 < window)
    // but with the wrong recovery hint. The prev-receipt hard-expiry loop still
    // covers a cert once it appears as a PRIOR witness (`verify_vbc_bundle_historical`,
    // modes.rs:666); this is the serving-round check (Locus A), new behaviour with no
    // prior owner. Runs only on the attested path — a forgeable tx.epoch must not
    // decide it — and is skipped when there is no serving cert (k=0 offline / Ark).
    if now_is_attested {
        // KI#130 Gap B — carrier-latency OODS FRESHNESS gate. The round's attested
        // tick T (`now`) must not be staler than the wallet's LAST round's OODS tick
        // X by more than the buffer, or it is a REPLAY of an old reading. X = the max
        // `oods_flag.tick` across prev_receipts; if no prev receipt carries one, skip
        // (nothing to compare). NO upper bound — an idle wallet legitimately has
        // T >> X and must pass. Tick VALUE and the buffer are the same unit (the owner:
        // "tick is tick"), compared directly.
        let prev_max_oods_tick = inputs
            .prev_receipts
            .iter()
            .filter_map(|r| r.oods_flag.as_ref().map(|f| f.tick))
            .max();
        if let Some(x) = prev_max_oods_tick {
            if now.saturating_add(crate::validation::protocol_gen::VBC_OODS_FRESHNESS_BUFFER_TICKS)
                < x
            {
                return Err(crate::types::ValidationError::VBCStaleAttestation {
                    attested_tick: now,
                    prev_tick: x,
                });
            }
        }

        if let Some(bundle) = &inputs.vbc_bundle {
            let vbc = &bundle.target_vbc;
            if vbc.expires_at != 0 && vbc.expires_at < now {
                return Err(crate::types::ValidationError::VBCExpired {
                    expires_at: vbc.expires_at,
                    current_tick: now,
                });
            }
            // Near-expiry window compared DIRECTLY in tick VALUE units (the owner: "tick
            // is tick") — no ticks_to_secs; the tick VALUE and `expires_at` are the
            // same unit (both unix-second stamps).
            if vbc.expires_at != 0
                && vbc.expires_at.saturating_sub(now)
                    < crate::validation::protocol_gen::VBC_UNUSABLE_REMAINING_TICKS
            {
                return Err(crate::types::ValidationError::VBCUnusableSoon {
                    expires_at: vbc.expires_at,
                    current_tick: now,
                });
            }
        }
    }

    // Hard expiry + not-yet-valid on the prev-receipt witness VBCs, judged against
    // the attested `now`. (No unusable-window here any more — Locus A moved it to the
    // serving cert above.)
    for receipt in &inputs.prev_receipts {
        for witness in &receipt.witness_sigs {
            if let Some(bundle) = &witness.vbc_bundle {
                let vbc = &bundle.target_vbc;
                if vbc.expires_at != 0 && vbc.expires_at < now {
                    return Err(crate::types::ValidationError::VBCExpired {
                        expires_at: vbc.expires_at,
                        current_tick: now,
                    });
                }
                if vbc.issued_at > now {
                    return Err(crate::types::ValidationError::VBCNotYetValid {
                        issued_at: vbc.issued_at,
                        current_tick: now,
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
    // `true` only on the NBC (k=1 citizen) path: a chain_depth>0 target recurses
    // to its issuer's cert. `false` on the VBC (k=3 validator) path, where
    // multi-level issuance stays DEFERRED (SEC-10 — see the depth>0 arm below).
    allow_multilevel: bool,
    // §5.3 — enforce the GENESIS LINEAGE admission rule on this chain. True on
    // the VBC (k=3 validator) path ONLY: an NBC is a Nabla citizen certificate
    // with a different root set and no genesis-family concept, so applying it
    // there would reject every legitimate citizen chain.
    enforce_genesis_lineage: bool,
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

    // Step 2: bound the cert's declared depth.
    //
    // RULE 0/RULE 3 (2026-08-16): this used to be `vbc.chain_depth != depth`,
    // which conflated two OPPOSITE-direction counters. The cert's `chain_depth`
    // field is its signed distance FROM THE ROOT (root-signed = 0, Gen-1 = 1;
    // see the module header), while `depth` here is the recursion's hop count
    // FROM THE ENTRY. They coincide ONLY for a genesis (chain_depth == 0) entry,
    // so every validator-issued NBC (chain_depth == 1) failed here with
    // InvalidVBC — a ghost that made the doc's "Non-genesis (chain_depth=1+)"
    // promise unreachable and blocked every Nabla citizen join (the Pi, 2026-08-16:
    // gamma ISSUED an NBC then rejected it as InvalidVBC). Termination is now
    // decided by the cert's own signature-covered chain_depth in Step 9/10;
    // `depth` only bounds the walk (via MAX_CHAIN_DEPTH, above and here).
    if vbc.chain_depth > MAX_CHAIN_DEPTH {
        #[cfg(feature = "std")]
        eprintln!("[VBC_DIAG] FAIL step 2: chain_depth={} exceeds MAX_CHAIN_DEPTH={}", vbc.chain_depth, MAX_CHAIN_DEPTH);
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

    // Step 8: Verify the SPHINCS+ signatures, and IDENTIFY EACH SIGNER BY KEY
    //
    // ╔═══════════════════════════════════════════════════════════════════╗
    // ║  THE SIGNER IS WHOEVER'S KEY VERIFIES — NOT WHOEVER SITS AT [i]    ║
    // ╚═══════════════════════════════════════════════════════════════════╝
    // This used to pair strictly by index: `signatures[i]` against
    // `issuer_set[i]`. That made a certificate round RIGID. If the third meta
    // refused — or never answered — the client could not redirect the request
    // to another validator, because `issuer_set` is inside the signed payload:
    // changing the list changed the document, and the two signatures already
    // collected stopped verifying. A whole round thrown away over one refusal.
    //
    // the owner, 2026-09-04: *"The third should just reject and client just find
    // another one to finalise. Why waste?"* and *"just don't use it to identify
    // meta. We use public key."*
    //
    // So `issuer_set` STAYS in the signed payload — which is what lets the
    // twenty already-deployed certificates keep verifying, with no re-signing
    // ceremony — but it is no longer WHO SIGNED. Each signature is matched to
    // the key that actually verifies it, drawn from the certificate's own
    // issuer list plus the supporting certificates that travel with it.
    //
    // ⚠ NOTHING IS WEAKENED. A signature still has to verify under a real key,
    // and that key still has to survive every check below — root authority or a
    // valid chain, and for a VBC the §5.3 lineage rule. What is dropped is only
    // the assumption that the candidate correctly PREDICTED the running order
    // before the round started, which is not a security property and never was.
    // As a bonus the client no longer has to sort collected signatures into
    // issuer order — arrival order is now harmless.
    let signing_payload = compute_vbc_signing_payload(vbc);

    // Candidate signer keys: the declared issuers, plus the subjects of any
    // supporting certificates (a substituted meta appears only there).
    let mut candidate_keys: alloc::vec::Vec<&[u8]> = alloc::vec::Vec::new();
    for k in &vbc.issuer_set {
        candidate_keys.push(k.as_slice());
    }
    for c in supporting {
        candidate_keys.push(c.subject_pubkey_sphincs.as_slice());
    }

    // The identified signers, in signature order. DISTINCT by construction —
    // one key may not stand in for two signatures, which is what keeps
    // "k issuers" a real count of k separate parties rather than one party
    // signing k times.
    let mut signer_keys: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
    for i in 0..required_issuers {
        if i >= vbc.signatures.len() {
            #[cfg(feature = "std")]
            eprintln!("[VBC_DIAG] FAIL step 8: only {} signature(s), need {}",
                      vbc.signatures.len(), required_issuers);
            return Err(ValidationError::InvalidVBC);
        }
        let sig = &vbc.signatures[i];
        let found = candidate_keys.iter().find(|k| {
            !signer_keys.iter().any(|used| used.as_slice() == **k)
                && verify_sphincs(k, &signing_payload, sig).is_ok()
        });
        match found {
            Some(k) => signer_keys.push(k.to_vec()),
            None => {
                #[cfg(feature = "std")]
                eprintln!("[VBC_DIAG] FAIL step 8: signature {} matches no eligible \
                           signer key (sig_len={})", i, sig.len());
                return Err(ValidationError::InvalidVBC);
            }
        }
    }

    // Mark this VBC as verified
    verified_pks.insert(vbc.subject_pubkey_sphincs.clone());

    // Step 9: termination vs recursion is decided by the cert's OWN chain_depth
    // (Step 8 verified the SPHINCS+ signature that COVERS chain_depth, so it is
    // now trusted). A depth-0 cert is root-signed and terminates here; a
    // depth-N cert must trace to an issuer that holds depth N-1 (Step 10).
    let all_issuers_are_root = vbc.issuer_set.iter()
        .all(|pk| root_check(pk));

    if vbc.chain_depth == 0 {
        // Genesis cert — MUST be signed by root authority keys.
        if all_issuers_are_root {
            return Ok(());
        }
        // Issuers don't match the root keys compiled into this Core: either a
        // stale Core build or a mirror universe cert. DO NOT ACCEPT.
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

    // chain_depth > 0.
    if !allow_multilevel {
        // Multi-level issuance not enabled on this path. For the VBC (k=3
        // validator) path this WAS the SEC-10 deferral: fail-closed because no
        // anti-Sybil admission rule existed. §5.3 is that rule, so the VBC
        // caller now opts in; this arm remains for any caller that has not.
        #[cfg(feature = "std")]
        eprintln!("[VBC_DIAG] FAIL: depth>0 chain not enabled on this path, chain_depth={}", vbc.chain_depth);
        return Err(ValidationError::InvalidVBC);
    }

    // ── §5.3 GENESIS LINEAGE ADMISSION RULE (VBC path only) ─────────────
    //
    // Enforced HERE, verifying the FINISHED certificate, and deliberately NOT
    // in the witness round. Only a round's last hop sees all three signatures
    // — non-final hops dispatch in parallel with empty signature sets and never
    // see each other — so enforcing at the finalizer would hand a consensus
    // rule to whichever validator happened to go last, and a patched one would
    // simply skip it (RULE 5).
    //
    // Everything needed is in the artifact: the certificate names its three
    // issuers, and the recursion below is exactly what supplies those issuers'
    // own certificates, each carrying its genesis lineage.
    if enforce_genesis_lineage {
        // ⚠ Reads `signer_keys` — the metas that ACTUALLY signed, identified in
        // Step 8 by which key verifies — and NOT `issuer_set`, which is only
        // what the candidate predicted before the round ran. If the third meta
        // refused and the client redirected to another validator, the declared
        // list is stale and the substituted meta is the one whose lineage must
        // be counted.
        // ⚠ Every arm in this block answered a bare `InvalidVBC` until
        // 2026-09-04, so a rejected certificate could not be told apart from
        // any other VBC failure — and the VBC_DIAG lines below are
        // `#[cfg(feature = "std")]`, i.e. compiled out in the guest, which is
        // where CL8's twin of this rule runs. The variants are the only
        // diagnosis that survives; they match CL8's one-for-one.
        let mut lineages: alloc::vec::Vec<[u8; 32]> = alloc::vec::Vec::new();
        for issuer_pk in &signer_keys {
            let issuer_cert = supporting.iter()
                .find(|c| c.subject_pubkey_sphincs.as_slice() == issuer_pk.as_slice())
                .ok_or(ValidationError::VBCIssuerCertMissing)?;

            // (a) The issuer must have enough life LEFT to admit anyone.
            //     Present-tense, asked of the issuer as it acts — see
            //     `validation::vbc_can_issue` for why remaining life is right
            //     here and wrong at a reliance site. `current_time == 0` is the
            //     no-time sentinel; skip, as every other time check here does.
            // Judged on an ATTESTED tick, never on `current_time`. Fails
            // closed when no tick is present: an admission control that falls
            // back to a sender-supplied clock is not a control.
            // ⚠ NOT `current_time`. That is `tx.epoch` — signed, so every
            // validator agrees on it, but CHOSEN BY THE SENDER and unbounded
            // (KI#130). Backdating it would make a nearly-expired issuer look
            // fresh, which is exactly the control an attacker wants to defeat.
            //
            // The tick is THIS CERTIFICATE'S OWN OODS STAMP (RULED 2026-09-04,
            // `issuing_tick_for`): the moment its issuers acted, recorded in
            // the artifact and bound by Core at issuance. A zero stamp is the
            // genesis-exempt sentinel and FAILS CLOSED here — a depth>0
            // newcomer does not get to be excused from that judgement.
            let tick = match issuing_tick_for(vbc) {
                Some(t) => t,
                None => {
                    #[cfg(feature = "std")]
                    eprintln!("[VBC_DIAG] FAIL 5.3: certificate carries no OODS stamp \
                               (baseline_tick=0) — the issuing bar cannot be judged");
                    return Err(ValidationError::VBCNoAttestedTick);
                }
            };
            if !crate::validation::vbc_can_issue(issuer_cert.expires_at, tick) {
                #[cfg(feature = "std")]
                eprintln!("[VBC_DIAG] FAIL 5.3: issuer expires_at={} below issuing minimum at attested tick={}",
                          issuer_cert.expires_at, tick);
                return Err(ValidationError::VBCIssuerCannotIssue);
            }

            // (b) Every issuer must belong to a known genesis family.
            match effective_genesis_lineage(issuer_cert) {
                Some(l) => lineages.push(l),
                None => {
                    #[cfg(feature = "std")]
                    eprintln!("[VBC_DIAG] FAIL 5.3: an issuer belongs to no genesis lineage");
                    return Err(ValidationError::VBCIssuerNoLineage);
                }
            }
        }

        // (c) THE RULE: three issuers, three DIFFERENT families. This is what
        //     stops one family admitting itself over and over.
        for i in 0..lineages.len() {
            for j in (i + 1)..lineages.len() {
                if lineages[i] == lineages[j] {
                    #[cfg(feature = "std")]
                    eprintln!("[VBC_DIAG] FAIL 5.3: two issuers share a genesis lineage");
                    return Err(ValidationError::VBCIssuersShareLineage);
                }
            }
        }

        // (d) The certificate's OWN family must be one of its issuers'. The
        //     newcomer is ADOPTED into a sponsoring family; it does not found
        //     an eleventh. Without this a candidate could name any family and
        //     inherit standing nobody granted it.
        match effective_genesis_lineage(vbc) {
            Some(mine) if lineages.contains(&mine) => {}
            _ => {
                #[cfg(feature = "std")]
                eprintln!("[VBC_DIAG] FAIL 5.3: cert lineage is not one of its issuers'");
                return Err(ValidationError::VBCLineageNotAdopted);
            }
        }
    }

    // Step 10: NBC multi-level — every issuer must present a cert exactly one
    // level closer to the root (chain_depth - 1), and that cert must itself
    // verify. A root key appearing as the issuer of a depth>0 cert is
    // inconsistent (a root-signed cert is depth 0) and is rejected: it has no
    // supporting cert at depth-1.
    for issuer_pk in &vbc.issuer_set {
        // Already verified?
        if verified_pks.contains(issuer_pk) {
            continue;
        }

        // Find issuer's cert in supporting set (match on SPHINCS+ PK)
        let issuer_vbc = supporting.iter()
            .find(|v| v.subject_pubkey_sphincs == *issuer_pk)
            .ok_or(ValidationError::VBCMissingIssuer)?;

        // The issuer must sit exactly one level closer to the root than this
        // cert. This binds the walk length to the SIGNED chain_depth and blocks
        // a forged cert claiming a deeper level than its issuer actually holds.
        if issuer_vbc.chain_depth + 1 != vbc.chain_depth {
            #[cfg(feature = "std")]
            eprintln!("[VBC_DIAG] FAIL step 10: issuer chain_depth={} != target chain_depth {}-1",
                issuer_vbc.chain_depth, vbc.chain_depth);
            return Err(ValidationError::InvalidVBC);
        }

        // Recurse toward root. `current_time` is already threaded, so Step 7
        // enforces issuer EXPIRY at each hop. (Historical SEC-10 note: when the
        // VBC k=3 path is eventually enabled for depth>0, the issuer-maturity
        // gate belongs HERE too — the `!allow_multilevel` guard above keeps it
        // fail-closed until that "mature when issued" vs "mature now" decision
        // is made; see the SEC-10 report note.)
        verify_chain_recursive(issuer_vbc, supporting, current_time, depth + 1,
                               verified_pks, required_issuers, root_check,
                               allow_multilevel, enforce_genesis_lineage)?;
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
    // See verify_chain_recursive: NBC (k=1) recurses depth>0; VBC (k=3) does not.
    allow_multilevel: bool,
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
    // See verify_chain_recursive Step 2 (2026-08-16): chain_depth is distance
    // from root, not the recursion hop counter — bound it, don't equate it.
    if vbc.chain_depth > MAX_CHAIN_DEPTH {
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
    if vbc.chain_depth == 0 {
        if all_issuers_are_root {
            return Ok(());
        }
        return Err(ValidationError::VBCRootKeyMismatch);
    }
    if !allow_multilevel {
        // VBC depth>0 stays fail-closed (SEC-10) — mirrors verify_chain_recursive.
        return Err(ValidationError::InvalidVBC);
    }
    for issuer_pk in &vbc.issuer_set {
        if verified_pks.contains(issuer_pk) {
            continue;
        }
        let issuer_vbc = supporting.iter()
            .find(|v| v.subject_pubkey_sphincs == *issuer_pk)
            .ok_or(ValidationError::VBCMissingIssuer)?;
        if issuer_vbc.chain_depth + 1 != vbc.chain_depth {
            return Err(ValidationError::InvalidVBC);
        }
        verify_structure_recursive(issuer_vbc, supporting, depth + 1, verified_pks, required_issuers, root_check, allow_multilevel)?;
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
            genesis_lineage: [0u8; 32],
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
            nabla_registration: None,
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // G1 discontinuity — pre-G1 credentials cannot survive the ceremony
    // ═══════════════════════════════════════════════════════════════════

    /// Stand-in for the root-authority predicate that `genesis-ceremony`
    /// will emit at G1. `lambda/src/bin/genesis_ceremony.rs:420-450`
    /// regenerates `genesis.rs` wholesale, writing fresh
    /// `ROOT_AUTHORITY_PKS` and a matching `is_root_authority`. Post-G1
    /// that predicate recognises the ceremony keys and nothing else.
    fn is_root_authority_post_g1(pk: &[u8]) -> bool {
        pk == POST_G1_ROOT_A || pk == POST_G1_ROOT_B || pk == POST_G1_ROOT_C
    }
    const POST_G1_ROOT_A: &[u8] = &[0xA1; 32];
    const POST_G1_ROOT_B: &[u8] = &[0xB2; 32];
    const POST_G1_ROOT_C: &[u8] = &[0xC3; 32];

    /// Build a depth-0 VBC issued by the three keys given.
    fn root_signed_vbc(subject: &[u8], issuers: [&[u8]; 3]) -> VBC {
        make_test_vbc(
            subject,
            &[0x11u8; 32],
            0,
            issuers.iter().map(|p| p.to_vec()).collect(),
            vec![vec![0u8; 64]; 3],
            0,
            u64::MAX,
        )
    }

    /// **The G1 discontinuity.** A validator credential is anchored to the
    /// root-authority key set compiled into Core. G1 replaces that set, so
    /// the cut is total and symmetric in both directions:
    ///
    ///   - every pre-G1 VBC fails `VBCRootKeyMismatch` under post-G1 Core;
    ///   - every post-G1 VBC fails it under pre-G1 Core.
    ///
    /// A witness receipt is only as good as the VBC of the validator that
    /// signed it, so no pre-G1 witnessed value can be presented to a post-G1
    /// mesh: the supporting credential no longer verifies. This is what
    /// separates today's test AXC from mainnet AXC — NOT FACT class
    /// isolation, which quarantines the dev-AXC pool (`@axiom.internal`)
    /// and deliberately classifies `@axiom` as *public*
    /// (`wallet_id.rs::is_dev_wallet`, `AXIOM_DESIGN_FactClassIsolation.md` §2).
    ///
    /// Structure-only verification is used deliberately: it exercises the
    /// root-anchor branch in isolation, without needing real SPHINCS+
    /// signatures. Signature verification is covered by the full-bundle
    /// tests; conflating the two would weaken both.
    #[test]
    fn g1_ceremony_severs_pre_g1_credentials() {
        use crate::genesis::ROOT_AUTHORITY_PKS;

        // Guard: a table of zero/duplicate placeholders would make every
        // assertion below pass for the wrong reason (is_root_authority
        // rejects all-zero keys outright, genesis.rs:447).
        assert_eq!(ROOT_AUTHORITY_PKS.len(), 3, "VBC anchor is a 3-key set");
        for (i, r) in ROOT_AUTHORITY_PKS.iter().enumerate() {
            assert_ne!(r, &[0u8; 32], "ROOT_AUTHORITY_PKS[{i}] is a placeholder");
            assert!(is_root_authority(r), "ROOT_AUTHORITY_PKS[{i}] must self-recognise");
        }
        let distinct: BTreeSet<&[u8; 32]> = ROOT_AUTHORITY_PKS.iter().collect();
        assert_eq!(distinct.len(), 3, "root keys must be distinct");

        let pre_g1 = root_signed_vbc(
            &[0x77u8; 32],
            [&ROOT_AUTHORITY_PKS[0], &ROOT_AUTHORITY_PKS[1], &ROOT_AUTHORITY_PKS[2]],
        );
        let post_g1 = root_signed_vbc(
            &[0x88u8; 32],
            [POST_G1_ROOT_A, POST_G1_ROOT_B, POST_G1_ROOT_C],
        );

        let verify = |vbc: &VBC, root_check: fn(&[u8]) -> bool| {
            let mut seen = BTreeSet::new();
            verify_structure_recursive(
                vbc, &[], 0, &mut seen, VBC_REQUIRED_ISSUERS, root_check, false,
            )
        };

        // Control: each credential verifies under its OWN era. Without this
        // the two rejections below could come from any structural defect.
        assert!(
            verify(&pre_g1, is_root_authority).is_ok(),
            "pre-G1 VBC must verify under the pre-G1 anchor (else this test proves nothing)",
        );
        assert!(
            verify(&post_g1, is_root_authority_post_g1).is_ok(),
            "post-G1 VBC must verify under the post-G1 anchor",
        );

        // The cut, forwards: pre-G1 value cannot be carried into mainnet.
        assert!(
            matches!(
                verify(&pre_g1, is_root_authority_post_g1),
                Err(ValidationError::VBCRootKeyMismatch)
            ),
            "a pre-G1 VBC MUST be rejected by post-G1 Core",
        );

        // The cut, backwards: no one can pre-mint against the new anchor.
        assert!(
            matches!(
                verify(&post_g1, is_root_authority),
                Err(ValidationError::VBCRootKeyMismatch)
            ),
            "a post-G1 VBC MUST be rejected by pre-G1 Core",
        );
    }

    /// The anchor is compiled INTO Core, so replacing it necessarily moves
    /// the CoreID — the discontinuity is publicly checkable, not a promise.
    /// `ROOT_AUTHORITY_PKS` lives in `core/logic/src/genesis.rs`, which is
    /// part of the `axiom-core-logic` crate compiled into the RISC-V guest
    /// ELF whose BLAKE3 hash IS the CoreID. This test pins the coupling so
    /// that moving the anchor out of the hashed crate breaks the build.
    #[test]
    fn root_anchor_is_inside_the_hashed_core() {
        let src = include_str!("genesis.rs");
        assert!(
            src.contains("pub const ROOT_AUTHORITY_PKS"),
            "ROOT_AUTHORITY_PKS must stay in core/logic/src/genesis.rs — \
             if it moves outside the crate compiled into the ELF, changing \
             it would no longer change the CoreID and the G1 discontinuity \
             would stop being externally verifiable",
        );
        assert!(
            src.contains("pub fn is_root_authority"),
            "is_root_authority must be generated alongside the key table",
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // Genesis-name reservation
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn greek_names_reserved_assigned_and_unassigned() {
        use crate::genesis::{GENESIS_VALIDATORS, GREEK_NAMES};
        assert_eq!(GREEK_NAMES.len(), 24, "full Greek alphabet");
        // Base cert; only (node_name, validator_id) matter to the reservation.
        let mut vbc = make_test_vbc(&[1u8; 32], &[2u8; 32], 0, vec![], vec![], 0, u64::MAX);

        for (i, name) in GREEK_NAMES.iter().enumerate() {
            let assigned = i < GENESIS_VALIDATORS.len(); // 0..10 = genesis
            // Both the short ("alpha") and formal ("axiom-first-penguin-alpha") forms.
            for form in [name.to_string(), format!("axiom-first-penguin-{name}")] {
                vbc.node_name = form.clone();
                if assigned {
                    // Allowed ONLY on its own pinned genesis SPHINCS+ pubkey.
                    vbc.subject_pubkey_sphincs = GENESIS_VALIDATORS[i].to_vec();
                    assert!(
                        enforce_genesis_name_reservation(&vbc).is_ok(),
                        "{form} on its own genesis sphincs pubkey must be allowed"
                    );
                }
                // Foreign key (assigned) OR any key (unassigned lambda..omega) → reject.
                vbc.subject_pubkey_sphincs = vec![0xAA; 32];
                assert!(
                    matches!(
                        enforce_genesis_name_reservation(&vbc),
                        Err(ValidationError::GenesisNameReserved)
                    ),
                    "{form} on a non-owning pubkey must be rejected (assigned={assigned})"
                );
            }
        }

        // A non-Greek name is unconstrained (any key may use it).
        vbc.node_name = "not-a-greek-name".to_string();
        vbc.subject_pubkey_sphincs = vec![0xCC; 32];
        assert!(enforce_genesis_name_reservation(&vbc).is_ok());

        // Empty name (the make_test_vbc default) is not reserved.
        vbc.node_name = String::new();
        assert!(enforce_genesis_name_reservation(&vbc).is_ok());
    }

    #[test]
    fn greek_names_reserved_nabla_side_and_key_isolated() {
        use crate::genesis::GENESIS_VALIDATORS;
        use crate::nabla_genesis::NABLA_GENESIS_VALIDATORS;
        let mut nbc = make_test_vbc(&[3u8; 32], &[4u8; 32], 0, vec![], vec![], 0, u64::MAX);
        nbc.node_name = "alpha".to_string();

        // Nabla side compares the NBC's validator_id (blake3 id form).
        // Allowed only on its own nabla genesis id.
        nbc.validator_id = NABLA_GENESIS_VALIDATORS[0];
        assert!(
            enforce_nabla_name_reservation(&nbc).is_ok(),
            "nabla alpha on its own nabla id must be allowed"
        );
        nbc.validator_id = [0xAA; 32];
        assert!(
            matches!(enforce_nabla_name_reservation(&nbc), Err(ValidationError::GenesisNameReserved)),
            "nabla alpha on a foreign id must be rejected"
        );

        // Unassigned Greek name (omega) rejected on the nabla side for any id.
        nbc.node_name = "omega".to_string();
        nbc.validator_id = NABLA_GENESIS_VALIDATORS[0];
        assert!(
            matches!(enforce_nabla_name_reservation(&nbc), Err(ValidationError::GenesisNameReserved)),
            "unassigned nabla name rejected for every id"
        );

        // Key isolation: the nabla genesis id is NOT the validator genesis SPHINCS+
        // pubkey, so a cert named "alpha" carrying the nabla id as its sphincs pubkey
        // is rejected by the VALIDATOR reservation.
        assert_ne!(
            NABLA_GENESIS_VALIDATORS[0], GENESIS_VALIDATORS[0],
            "validator and nabla genesis keys are isolated"
        );
        let mut vbc = make_test_vbc(&[5u8; 32], &[6u8; 32], 0, vec![], vec![], 0, u64::MAX);
        vbc.node_name = "alpha".to_string();
        vbc.subject_pubkey_sphincs = NABLA_GENESIS_VALIDATORS[0].to_vec();
        assert!(
            matches!(enforce_genesis_name_reservation(&vbc), Err(ValidationError::GenesisNameReserved)),
            "a nabla key must not wear the validator alpha name"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // Approval maturity tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_approval_maturity_genesis_always_true() {
        // ⚠ GENESIS_VALIDATORS holds SPHINCS+ PUBLIC KEYS, not validator ids.
        // This test used to put one into `validator_id` and leave the sphincs
        // key zeroed — encoding the very confusion that made
        // `is_genesis_validator` unable to match in production (fixed
        // 2026-09-04). The key goes where the key goes.
        use crate::genesis::GENESIS_VALIDATORS;
        let vbc = VBC {
            genesis_lineage: [0u8; 32],
            network_size_baseline: 0,
            baseline_tick: 0,
            version: EXPECTED_VERSION,
            validator_id: *blake3::hash(&GENESIS_VALIDATORS[0]).as_bytes(),
            subject_pubkey_sphincs: GENESIS_VALIDATORS[0].to_vec(),
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
            nabla_registration: None,
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
            genesis_lineage: [0u8; 32],
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
            nabla_registration: None,
        };
        let maturity = crate::types::VBC_APPROVAL_MATURITY_SECS;
        // Before 30 days
        assert!(!is_approval_mature(&vbc, 1_000_000 + maturity - 1));
        // At exactly 30 days
        assert!(is_approval_mature(&vbc, 1_000_000 + maturity));
        // After 30 days
        assert!(is_approval_mature(&vbc, 1_000_000 + maturity + 1));
    }

    /// ValidatorJoin §6b.12 — a depth-1 certificate with its three root-issued issuers in the
    /// bundle passes the structure check; without them it is refused (the chain is required).
    #[test]
    fn structure_check_accepts_a_depth_one_chain_and_requires_the_issuers() {
        let roots = crate::genesis::ROOT_AUTHORITY_PKS;
        let issuer = |k: u8| make_test_vbc(&[k; 32], &[0xAAu8; 32], 0,
            roots.iter().map(|r| r.to_vec()).collect(), vec![vec![]; 3], 0, u64::MAX);
        let issuers = [issuer(0x11), issuer(0x12), issuer(0x13)];
        let target = make_test_vbc(&[0xFFu8; 32], &[0xAAu8; 32], 1,
            issuers.iter().map(|i| i.subject_pubkey_sphincs.clone()).collect(), vec![vec![]; 3], 0, u64::MAX);
        let whole = VBCProofBundle { target_vbc: target.clone(), supporting_vbcs: issuers.to_vec(), candidacy_pulse: None, renewal_work_receipt: None };
        assert_eq!(verify_vbc_bundle_structure_only_DANGER_no_sig(&whole), Ok(()));
        let chainless = VBCProofBundle { target_vbc: target, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
        assert_eq!(verify_vbc_bundle_structure_only_DANGER_no_sig(&chainless), Err(ValidationError::VBCMissingIssuer));
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
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
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
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
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
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
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
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
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
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
        assert!(matches!(verify_vbc_bundle_no_time(&bundle), Err(ValidationError::InvalidVBC)));
    }
    
    #[test]
    fn test_without_issuers_rejected() {
        let vbc = make_test_vbc(
            &[0xFFu8; 32], &[0xAAu8; 32], 0,
            vec![], vec![],
            0, u64::MAX,
        );
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
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
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
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
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
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
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
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
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
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
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
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
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
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
        let bundle = VBCProofBundle { target_vbc: nbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
        assert!(matches!(verify_nbc_bundle_no_time(&bundle), Err(ValidationError::InvalidVBC)));
    }

    #[test]
    fn test_nbc_no_issuers_rejected() {
        let nbc = make_test_vbc(
            &[0xFFu8; 32], &[0xAAu8; 32], 0,
            vec![], vec![],
            0, u64::MAX,
        );
        let bundle = VBCProofBundle { target_vbc: nbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
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
        let bundle = VBCProofBundle { target_vbc: nbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
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
        let bundle = VBCProofBundle { target_vbc: nbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
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
        let bundle = VBCProofBundle { target_vbc: nbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
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
        let bundle = VBCProofBundle { target_vbc: nbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
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
        let bundle = VBCProofBundle { target_vbc: nbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
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
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
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
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };

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

    /// 2026-08-16 regression: a validator-issued (chain_depth=1) NBC must verify.
    ///
    /// Before the depth-semantics fix, `verify_chain_recursive` step 2 compared
    /// the cert's `chain_depth` (distance-from-root) to the recursion hop counter,
    /// so a chain_depth=1 NBC — the shape gamma issues every Nabla citizen — always
    /// failed InvalidVBC. gamma ISSUED the Pi's NBC then rejected it (both logs,
    /// 2026-08-16). This builds the real 2-level chain with the pinned nabla root
    /// key and asserts accept + the security-negative cases still reject.
    /// §6b.5a (ruled B) — an unstamped, NON-provisional, root-signed VBC is
    /// refused as a LIVE credential (`VbcNotRegistered`) and accepted as
    /// HISTORICAL evidence (chain only). Mutation: make the historical path
    /// require the stamp and the second assertion goes red; drop the live
    /// requirement and the first does.
    #[test]
    fn test_unstamped_vbc_is_historical_evidence_but_not_a_live_credential() {
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
        let (pk_b, _sk) = slh_dsa_sha2_128s::try_keygen().unwrap();
        let pk_b = pk_b.into_bytes().to_vec();
        // Lifetime far above PROVISIONAL_VBC_EXPIRY_SECS: a FULL certificate.
        let mut vbc = make_test_vbc(&pk_b, &[0xBB; 32], 0, root_pk, vec![], 1_000, 1_000 + 10 * 365 * 86_400);
        let payload = compute_vbc_signing_payload(&vbc);
        vbc.signatures = root_sk.iter().map(|sk| crate::crypto::sign_sphincs(sk, &payload).unwrap()).collect();
        assert!(vbc.nabla_registration.is_none());
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
        assert!(matches!(verify_vbc_bundle(&bundle, 1_500), Err(ValidationError::VbcNotRegistered)),
            "a full VBC with no stamp is a CANDIDATE, not a live credential");
        assert!(verify_vbc_bundle_historical(&bundle, 1_500).is_ok(),
            "the same certificate read out of past evidence verifies by chain (ruled B)");
    }

    #[test]
    fn test_nbc_chain_depth1_validator_issued_verifies() {
        use fips205::slh_dsa_sha2_128s;
        use fips205::traits::SerDes;
        use crate::nabla_genesis::is_nabla_root_authority;

        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let nabla_keys = manifest.join("../../root-keys/nabla");
        if !nabla_keys.join("root_1.key").exists() {
            eprintln!("SKIP: root-keys/nabla/ not found — cannot build a signed NBC chain");
            return;
        }
        let root_sk = std::fs::read(nabla_keys.join("root_1.key")).unwrap();
        let root_pk = std::fs::read(nabla_keys.join("root_1.pub")).unwrap();
        assert!(is_nabla_root_authority(&root_pk),
            "root_1.pub must be a pinned NABLA root authority key");

        // Issuer (gamma-like) cert: chain_depth 0, signed by the nabla root.
        let (g_pk, g_sk) = slh_dsa_sha2_128s::try_keygen().unwrap();
        let g_pk_b = g_pk.into_bytes().to_vec();
        let g_sk_b = g_sk.into_bytes().to_vec();
        let mut issuer = make_test_vbc(&g_pk_b, &[0xB0; 32], 0, vec![root_pk.clone()], vec![], 1000, u64::MAX);
        let ip = compute_vbc_signing_payload(&issuer);
        issuer.signatures = vec![crate::crypto::sign_sphincs(&root_sk, &ip).unwrap()];

        // Leaf NBC (citizen): chain_depth 1, signed by the issuer (gamma).
        let (l_pk, _l_sk) = slh_dsa_sha2_128s::try_keygen().unwrap();
        let l_pk_b = l_pk.into_bytes().to_vec();
        let mut leaf = make_test_vbc(&l_pk_b, &[0xC0; 32], 1, vec![g_pk_b.clone()], vec![], 1000, u64::MAX);
        let lp = compute_vbc_signing_payload(&leaf);
        leaf.signatures = vec![crate::crypto::sign_sphincs(&g_sk_b, &lp).unwrap()];

        // ACCEPT: the depth-1 chain with the issuer's cert in the supporting set.
        let bundle = VBCProofBundle { target_vbc: leaf.clone(), supporting_vbcs: vec![issuer.clone()], candidacy_pulse: None, renewal_work_receipt: None };
        assert!(verify_nbc_bundle_no_time(&bundle).is_ok(),
            "chain_depth=1 NBC issued by a root-signed nabla node must verify (was InvalidVBC pre-fix)");

        // REJECT: issuer cert missing from the supporting set.
        let bundle_missing = VBCProofBundle { target_vbc: leaf.clone(), supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
        assert!(matches!(verify_nbc_bundle_no_time(&bundle_missing), Err(ValidationError::VBCMissingIssuer)),
            "a deep NBC with no supporting issuer cert must reject");

        // REJECT: issuer cert at the wrong depth (parent must be leaf.depth - 1 = 0).
        let mut issuer_bad = make_test_vbc(&g_pk_b, &[0xB0; 32], 3, vec![root_pk.clone()], vec![], 1000, u64::MAX);
        let ibp = compute_vbc_signing_payload(&issuer_bad);
        issuer_bad.signatures = vec![crate::crypto::sign_sphincs(&root_sk, &ibp).unwrap()];
        let bundle_baddepth = VBCProofBundle { target_vbc: leaf.clone(), supporting_vbcs: vec![issuer_bad], candidacy_pulse: None, renewal_work_receipt: None };
        assert!(matches!(verify_nbc_bundle_no_time(&bundle_baddepth), Err(ValidationError::InvalidVBC)),
            "issuer whose depth != target_depth-1 must reject");

        // REJECT: forged leaf signature (Step 8 still runs).
        let mut leaf_forged = leaf.clone();
        leaf_forged.signatures = vec![vec![0u8; leaf.signatures[0].len()]];
        let bundle_forged = VBCProofBundle { target_vbc: leaf_forged, supporting_vbcs: vec![issuer.clone()], candidacy_pulse: None, renewal_work_receipt: None };
        assert!(verify_nbc_bundle_no_time(&bundle_forged).is_err(),
            "forged leaf signature must reject");

        // REJECT: mirror-universe leaf (depth 0 but issuer is NOT a nabla root).
        let mut leaf_d0 = make_test_vbc(&l_pk_b, &[0xC0; 32], 0, vec![g_pk_b.clone()], vec![], 1000, u64::MAX);
        let lp0 = compute_vbc_signing_payload(&leaf_d0);
        leaf_d0.signatures = vec![crate::crypto::sign_sphincs(&g_sk_b, &lp0).unwrap()];
        let bundle_d0 = VBCProofBundle { target_vbc: leaf_d0, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
        assert!(matches!(verify_nbc_bundle_no_time(&bundle_d0), Err(ValidationError::VBCRootKeyMismatch)),
            "a depth-0 NBC whose issuer is not a nabla root must reject (mirror universe)");
    }

    /// The VBC (k=3) path must STAY fail-closed on depth>0 (SEC-10 deferred),
    /// even though the sibling NBC path now recurses. A depth-1 VBC that would
    /// have failed the old `chain_depth == depth` step 2 must still reject.
    #[test]
    fn test_vbc_depth1_still_rejected_sec10_deferred() {
        use fips205::slh_dsa_sha2_128s;
        use fips205::traits::SerDes;
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let keys_dir = manifest.join("../../root-keys/authority");
        if !keys_dir.join("root_1.key").exists() {
            eprintln!("SKIP: root-keys/authority/ not found");
            return;
        }
        let root_sk: Vec<Vec<u8>> = (1..=3)
            .map(|i| std::fs::read(keys_dir.join(format!("root_{i}.key"))).unwrap()).collect();
        let root_pk: Vec<Vec<u8>> = (1..=3)
            .map(|i| std::fs::read(keys_dir.join(format!("root_{i}.pub"))).unwrap()).collect();

        // A genesis (depth-0) VBC signed by the 3 real root keys.
        let (g_pk, g_sk) = slh_dsa_sha2_128s::try_keygen().unwrap();
        let g_pk_b = g_pk.into_bytes().to_vec();
        let g_sk_b = g_sk.into_bytes().to_vec();
        let mut issuer = make_test_vbc(&g_pk_b, &[0xB0; 32], 0, root_pk.clone(), vec![], 1000, u64::MAX);
        let ip = compute_vbc_signing_payload(&issuer);
        issuer.signatures = root_sk.iter().map(|sk| crate::crypto::sign_sphincs(sk, &ip).unwrap()).collect();

        // A depth-1 VBC signed by three copies of the genesis validator (k=3).
        let (l_pk, _l_sk) = slh_dsa_sha2_128s::try_keygen().unwrap();
        let l_pk_b = l_pk.into_bytes().to_vec();
        let mut leaf = make_test_vbc(&l_pk_b, &[0xC0; 32], 1,
            vec![g_pk_b.clone(), g_pk_b.clone(), g_pk_b.clone()], vec![], 1000, u64::MAX);
        let lp = compute_vbc_signing_payload(&leaf);
        leaf.signatures = (0..3).map(|_| crate::crypto::sign_sphincs(&g_sk_b, &lp).unwrap()).collect();
        // Distinct-issuer check fires first here (3 identical issuers) — the point
        // is only that a depth>0 VBC never verifies. Use 3 distinct genesis certs
        // would still hit the SEC-10 fail-closed arm; either way: not Ok.
        let bundle = VBCProofBundle { target_vbc: leaf, supporting_vbcs: vec![issuer], candidacy_pulse: None, renewal_work_receipt: None };
        assert!(verify_vbc_bundle_no_time(&bundle).is_err(),
            "a depth>0 VBC must not verify while SEC-10 multi-level issuance is deferred");
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
            candidacy_pulse: None, renewal_work_receipt: None,
        };

        // Create PublicInputs with epoch=0 and a prev_receipt carrying the expired VBC
        let inputs = PublicInputs {
            fact_certificates: alloc::vec::Vec::new(),
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
                oods_flag: None, confidence_index: None, sender_state: None, // 2026-09-11: un-rotted (fields added after this non-dev-only test was written)
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
            receiver_current_wallet_format: None,
            ..Default::default() // 2026-09-11: un-rotted — PublicInputs derives Default under cfg(test); this test is non-dev-only and rotted unseen since the attestation fields were added
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

    /// Verify that an expired VBC is caught even when epoch > 0, on the
    /// NON-attested path (CL1 client self-check / any mode that is not CL2/CL3).
    /// KI#130: CL2/CL3 now judge on the attested tick and would fail closed here
    /// (no oods_attestation); the attested-path expiry/fail-closed/unusable tests
    /// live in `modes.rs` where a valid attestation helper exists
    /// (`verify_vbc_expiry_cl3_*`). This one pins the tx.epoch fallback still
    /// rejects an expired cert (the HIGH-1 regression guard).
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
            candidacy_pulse: None, renewal_work_receipt: None,
        };

        let inputs = PublicInputs {
            zkq_request: None,
            fact_certificates: alloc::vec::Vec::new(),
            receiver_witness: None,
            receiver_signing_key: None,
            oods_attestation: None,
            recall_attestation: None,
            fob_claim_attestation: None,
            claimant_vbc: None,
            mode: CoreLogicMode::CL1, // KI#130: non-attested path → judges on tx.epoch
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
            receiver_current_wallet_format: None,
        };

        let result = verify_vbc_expiry(&inputs);
        assert!(result.is_err(), "Expired VBC must be rejected");
        assert!(matches!(result, Err(ValidationError::VBCExpired { .. })),
            "Expected VBCExpired, got: {:?}", result);
    }
}

#[cfg(test)]
mod genesis_lineage_tests {
    use super::*;
    use crate::genesis::GENESIS_VALIDATORS;

    fn cert(sphincs_pk: &[u8], lineage: [u8; 32], depth: u8, expires: u64) -> VBC {
        VBC {
            genesis_lineage: lineage,
            network_size_baseline: 0,
            baseline_tick: 0,
            version: EXPECTED_VERSION,
            validator_id: *blake3::hash(sphincs_pk).as_bytes(),
            subject_pubkey_sphincs: sphincs_pk.to_vec(),
            subject_pubkey_dilithium: alloc::vec![],
            subject_pubkey_ed25519: alloc::vec![0u8; 32],
            pgp_fingerprint: alloc::vec![],
            node_name: "t".into(),
            issued_at: 0,
            expires_at: expires,
            chain_depth: depth,
            issuer_set: alloc::vec![],
            signatures: alloc::vec![],
            proof_cap: "dmap".into(),
            max_tx: 0,
            founding_vbc_hash: [0u8; 32],
            nabla_registration: None,
        }
    }

    /// A genesis validator IS its own lineage, derived not stored — which is
    /// what lets the twenty deployed genesis certificates keep a byte-identical
    /// signing pre-image (their field is zero) and stay valid.
    #[test]
    fn a_genesis_validator_is_its_own_lineage_without_storing_it() {
        let g = cert(&GENESIS_VALIDATORS[0], [0u8; 32], 0, 0);
        assert_eq!(
            effective_genesis_lineage(&g),
            Some(GENESIS_VALIDATORS[0]),
            "a genesis cert carries NO stored lineage; it must be derived from \
             its subject key, or every deployed genesis cert breaks",
        );
    }

    /// ⚠ THE IDENTITY TRAP. `GENESIS_VALIDATORS` holds SPHINCS+ PUBLIC KEYS;
    /// `validator_id` is their BLAKE3. Both are 32 bytes, so nothing about the
    /// shape distinguishes them — which is how three production call sites came
    /// to compare the wrong one and could never match (fixed 2026-09-04).
    #[test]
    fn the_validator_id_is_not_the_lineage_key() {
        let g = &GENESIS_VALIDATORS[0];
        let id = *blake3::hash(g).as_bytes();
        assert_ne!(&id, g, "blake3(pk) must differ from pk — else the trap is invisible");
        assert!(crate::genesis::is_genesis_validator(g), "the KEY is recognised");
        assert!(
            !crate::genesis::is_genesis_validator(&id),
            "the ID must NOT be recognised — a call site passing validator_id \
             can never match, which is exactly the bug this pins",
        );
    }

    /// A non-genesis certificate with no stored lineage belongs to no family,
    /// and must not be allowed to sponsor anyone.
    #[test]
    fn a_stranger_belongs_to_no_lineage() {
        let s = cert(&[0x77u8; 32], [0u8; 32], 1, 0);
        assert_eq!(effective_genesis_lineage(&s), None);
    }

    /// A stored lineage is returned as-is — that is what makes a later check a
    /// single lookup instead of an ancestry walk that grows every generation.
    #[test]
    fn a_stored_lineage_is_returned_without_walking_ancestry() {
        let c = cert(&[0x88u8; 32], GENESIS_VALIDATORS[3], 1, 0);
        assert_eq!(effective_genesis_lineage(&c), Some(GENESIS_VALIDATORS[3]));
    }

    /// §5.3's issuing bar is SEPARATE from the serving bar, and the ordering
    /// matters: a certificate can still be good enough to witness while already
    /// too close to expiry to admit anyone.
    #[test]
    fn the_issuing_bar_is_stricter_than_the_serving_bar() {
        use crate::validation::{vbc_can_issue, vbc_can_serve,
                                VBC_ISSUING_MIN_REMAINING_SECS,
                                VBC_UNUSABLE_REMAINING_SECS};
        assert!(
            VBC_ISSUING_MIN_REMAINING_SECS > VBC_UNUSABLE_REMAINING_SECS,
            "admitting a validator must demand MORE remaining life than \
             witnessing a transaction",
        );
        let now = 1_000_000;
        // Between the two bars: may still serve, must NOT issue.
        let between = now + VBC_UNUSABLE_REMAINING_SECS + 1;
        assert!(vbc_can_serve(between, now), "still good enough to witness");
        assert!(
            !vbc_can_issue(between, now),
            "a cert this close to expiry must NOT be able to admit a validator",
        );
    }
}

#[cfg(test)]
mod signer_identity_tests {
    use super::*;
    use fips205::slh_dsa_sha2_128s;
    use fips205::traits::{KeyGen, SerDes, Signer};

    fn keypair() -> (alloc::vec::Vec<u8>, slh_dsa_sha2_128s::PrivateKey) {
        let mut rng = rand_core::OsRng;
        let (pk, sk) = slh_dsa_sha2_128s::try_keygen_with_rng(&mut rng).expect("keygen");
        (pk.into_bytes().to_vec(), sk)
    }

    /// ⚠ THE PROPERTY THIS EXISTS FOR: a client whose third meta refused can
    /// redirect the request to ANOTHER validator, and the two signatures it
    /// already holds stay good.
    ///
    /// `issuer_set` remains inside the signed payload — that is what lets the
    /// already-deployed certificates keep verifying without a re-signing
    /// ceremony — so the substituted meta is NOT in that list. It is identified
    /// by the key that verifies its signature.
    ///
    /// Pair strictly by index (the old behaviour) and this goes red, because
    /// D's signature would be checked against C's key.
    #[test]
    fn a_substituted_third_meta_still_verifies() {
        let (pk_a, sk_a) = keypair();
        let (pk_b, sk_b) = keypair();
        let (pk_c, _sk_c) = keypair();   // declared, then refused
        let (pk_d, sk_d) = keypair();    // the stand-in

        let mut vbc = VBC {
            genesis_lineage: [0u8; 32],
            network_size_baseline: 0,
            baseline_tick: 0,
            version: EXPECTED_VERSION,
            validator_id: [1u8; 32],
            subject_pubkey_sphincs: alloc::vec![2u8; 32],
            subject_pubkey_dilithium: alloc::vec![],
            subject_pubkey_ed25519: alloc::vec![0u8; 32],
            pgp_fingerprint: alloc::vec![],
            node_name: "cand".into(),
            issued_at: 0,
            expires_at: u64::MAX,
            chain_depth: 0,
            // What the candidate PREDICTED before the round ran. C never signed.
            issuer_set: alloc::vec![pk_a.clone(), pk_b.clone(), pk_c.clone()],
            signatures: alloc::vec![],
            proof_cap: "dmap".into(),
            max_tx: 0,
            founding_vbc_hash: [0u8; 32],
            nabla_registration: None,
        };

        // A and B signed the ORIGINAL document; D signs the SAME bytes, because
        // the payload never changed — that is the whole point.
        let payload = compute_vbc_signing_payload(&vbc);
        let sign = |sk: &slh_dsa_sha2_128s::PrivateKey| {
            sk.try_sign(&payload, b"", false).expect("sign").to_vec()
        };
        vbc.signatures = alloc::vec![sign(&sk_a), sign(&sk_b), sign(&sk_d)];

        // D's certificate travels with the bundle, which is where its key is found.
        let d_cert = VBC { subject_pubkey_sphincs: pk_d.clone(), ..vbc.clone() };
        let supporting = alloc::vec![d_cert];

        let payload_check = compute_vbc_signing_payload(&vbc);
        assert_eq!(payload, payload_check, "the signed document must not have changed");

        // Step 8 in isolation: every signature must find a distinct signer key.
        let mut candidates: alloc::vec::Vec<&[u8]> = alloc::vec::Vec::new();
        for k in &vbc.issuer_set { candidates.push(k.as_slice()); }
        for c in &supporting { candidates.push(c.subject_pubkey_sphincs.as_slice()); }
        let mut used: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
        for sig in &vbc.signatures {
            let f = candidates.iter().find(|k| {
                !used.iter().any(|u| u.as_slice() == **k)
                    && verify_sphincs(k, &payload, sig).is_ok()
            });
            used.push(f.expect("every signature must match an eligible key").to_vec());
        }
        assert_eq!(used.len(), 3);
        assert!(used.iter().any(|k| k.as_slice() == pk_d.as_slice()),
                "the SUBSTITUTED meta must be recognised as a signer");
        assert!(!used.iter().any(|k| k.as_slice() == pk_c.as_slice()),
                "the meta that refused must NOT be counted — it never signed");
    }

    /// One key may not stand in for two signatures — otherwise "three issuers"
    /// stops being a count of three separate parties.
    #[test]
    fn one_key_cannot_satisfy_two_signature_slots() {
        let (pk_a, sk_a) = keypair();
        let vbc = VBC {
            genesis_lineage: [0u8; 32],
            network_size_baseline: 0,
            baseline_tick: 0,
            version: EXPECTED_VERSION,
            validator_id: [1u8; 32],
            subject_pubkey_sphincs: alloc::vec![2u8; 32],
            subject_pubkey_dilithium: alloc::vec![],
            subject_pubkey_ed25519: alloc::vec![0u8; 32],
            pgp_fingerprint: alloc::vec![],
            node_name: "cand".into(),
            issued_at: 0,
            expires_at: u64::MAX,
            chain_depth: 0,
            issuer_set: alloc::vec![pk_a.clone(), pk_a.clone(), pk_a.clone()],
            signatures: alloc::vec![],
            proof_cap: "dmap".into(),
            max_tx: 0,
            founding_vbc_hash: [0u8; 32],
            nabla_registration: None,
        };
        let payload = compute_vbc_signing_payload(&vbc);
        let sig = sk_a.try_sign(&payload, b"", false).expect("sign").to_vec();

        let candidates: alloc::vec::Vec<&[u8]> = alloc::vec![pk_a.as_slice()];
        let mut used: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
        let mut matched = 0;
        for _ in 0..3 {
            let f = candidates.iter().find(|k| {
                !used.iter().any(|u| u.as_slice() == **k)
                    && verify_sphincs(k, &payload, &sig).is_ok()
            });
            match f { Some(k) => { used.push(k.to_vec()); matched += 1; } None => break }
        }
        assert_eq!(matched, 1,
            "the same key must satisfy at most ONE slot — three signatures from \
             one party is not three issuers");
    }
}

#[cfg(test)]
mod issuing_tick_tests {
    use super::*;
    use crate::validation::{vbc_can_issue, VBC_ISSUING_MIN_REMAINING_SECS};

    /// ⚠ THE ISSUING BAR IS JUDGED ON AN ATTESTED TICK, NEVER ON tx.epoch.
    ///
    /// `tx.epoch` is signed — so every validator agrees on it — but it is
    /// CHOSEN BY THE SENDER and unbounded (KI#130). A candidate could backdate
    /// it and make a nearly-expired issuer look fresh, defeating the exact
    /// control §5.3 exists to impose. A TARDIS tick is attested by the mesh.
    ///
    /// the owner, 2026-09-04: "use tick".
    #[test]
    fn a_backdated_epoch_cannot_rescue_an_expiring_issuer() {
        let bar = VBC_ISSUING_MIN_REMAINING_SECS;
        let real_now = 10_000_000u64;
        // An issuer one hour from expiry: far below the bar.
        let expires = real_now + 3_600;

        assert!(
            !vbc_can_issue(expires, real_now),
            "against real time this issuer is plainly unfit to admit anyone",
        );
        // The candidate backdates by more than the whole bar.
        let backdated = real_now - bar;
        assert!(
            vbc_can_issue(expires, backdated),
            "sanity: a backdated clock DOES make it look fit — which is why the \
             value must not be sender-chosen",
        );
        // Therefore the check must consume an attested tick, and refuse when
        // none is present, rather than fall back. Asserted at the call site by
        // `verify_chain_recursive`'s `attested_tick: None` arm.
    }

    /// No attested tick ⇒ a validator-issued (depth>0) certificate is REFUSED.
    /// Falling back to a sender-supplied clock would make the control optional,
    /// and an optional control is not one.
    #[test]
    fn no_attested_tick_refuses_a_validator_issued_certificate() {
        let mut vbc = VBC {
            genesis_lineage: crate::genesis::GENESIS_VALIDATORS[0],
            network_size_baseline: 0,
            baseline_tick: 0,
            version: EXPECTED_VERSION,
            validator_id: [1u8; 32],
            subject_pubkey_sphincs: alloc::vec![2u8; 32],
            subject_pubkey_dilithium: alloc::vec![],
            subject_pubkey_ed25519: alloc::vec![0u8; 32],
            pgp_fingerprint: alloc::vec![],
            node_name: "cand".into(),
            issued_at: 0,
            expires_at: u64::MAX,
            chain_depth: 1,
            issuer_set: alloc::vec![alloc::vec![9u8; 32]; 3],
            signatures: alloc::vec![alloc::vec![0u8; 64]; 3],
            proof_cap: "dmap".into(),
            max_tx: 0,
            founding_vbc_hash: [0u8; 32],
            nabla_registration: None,
        };
        vbc.signatures = alloc::vec![alloc::vec![0u8; 64]; 3];
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: alloc::vec![], candidacy_pulse: None, renewal_work_receipt: None };

        // Plain entry point supplies no tick — a depth>0 cert must not verify.
        assert!(
            verify_vbc_bundle(&bundle, 1_000_000).is_err(),
            "a validator-issued certificate must NOT verify without an attested \
             tick to judge its issuers' fitness against",
        );
    }
}

/// The root-authority predicate the certificate verifier uses: the compiled
/// `ROOT_AUTHORITY_PKS` — plus, under `cfg(test)` only, the roots a unit test
/// authorized through `genesis::test_roots` so fixtures can carry REAL
/// certificates (YP §26.17.6.5 B2). Lives here, not in `genesis.rs`, because
/// the genesis-ceremony tool regenerates `is_root_authority` verbatim
/// (rehearsal finding F20).
/// In every non-test build this IS `genesis::is_root_authority` — the same
/// function pointer as before, so the production ELF (CoreID) is unchanged.
#[cfg(not(test))]
use crate::genesis::is_root_authority as root_authority_check;
#[cfg(test)]
fn root_authority_check(pk: &[u8]) -> bool {
    if let Ok(arr) = <[u8; 32]>::try_from(pk) {
        if crate::genesis::test_roots::is_authorized(&arr) {
            return true;
        }
    }
    is_root_authority(pk)
}

// ── Q2-b renewal proof-of-validation (the owner ruled 2026-09-21) ─────────────
#[cfg(test)]
mod q2b_renewal_proof_tests {
    use super::*;
    use crate::types::{OodsFlag, Receipt, WitnessSig, VBC, VBCProofBundle};
    use ed25519_dalek::{Signer, SigningKey};
    use alloc::string::String;

    fn minimal_vbc(subject_sphincs: alloc::vec::Vec<u8>, baseline_tick: u64) -> VBC {
        VBC {
            genesis_lineage: [0u8; 32],
            network_size_baseline: 0,
            baseline_tick,
            version: 9,
            validator_id: *blake3::hash(&subject_sphincs).as_bytes(),
            subject_pubkey_sphincs: subject_sphincs,
            subject_pubkey_dilithium: alloc::vec![0u8; 1952],
            subject_pubkey_ed25519: alloc::vec![0u8; 32],
            pgp_fingerprint: alloc::vec![],
            node_name: String::new(),
            proof_cap: String::new(),
            issued_at: 0,
            expires_at: u64::MAX,
            chain_depth: 1,
            issuer_set: alloc::vec![],
            signatures: alloc::vec![],
            max_tx: 0,
            founding_vbc_hash: [0u8; 32],
            nabla_registration: None,
        }
    }

    /// Build a k-signed receipt. `renewer_seed` seeds one witness's Ed25519 key
    /// (so that key co-signed) unless `include_renewer` is false. `tick` sets the
    /// OODS reading; `oods` false makes oods_flag None. `n` = witness count.
    fn mk_work_receipt(
        renewer_seed: u8,
        tick: u64,
        oods: bool,
        include_renewer: bool,
        n: usize,
    ) -> (Receipt, alloc::vec::Vec<u8>) {
        let txid = [0xAA; 32];
        let state_hash = [0xBB; 32];
        let commitment_hash = [0xCC; 32];
        let new_wallet_seq: u64 = 1;
        let epoch: u64 = 1;
        let oods_flag = if oods {
            Some(OodsFlag { tick, oods_size: 10, healthy: true })
        } else {
            None
        };
        let receipt_commitment = crate::crypto::compute_receipt_commitment(
            &txid, &state_hash, new_wallet_seq, &commitment_hash, epoch,
            false, oods_flag.as_ref(), None, None,
        );
        // Seeds: the first witness is the renewer when include_renewer; the rest
        // are distinct others. When !include_renewer, all are others.
        let mut seeds: alloc::vec::Vec<u8> = alloc::vec![];
        if include_renewer { seeds.push(renewer_seed); }
        let mut other = 0x50u8;
        while seeds.len() < n {
            if other != renewer_seed { seeds.push(other); }
            other = other.wrapping_add(1);
        }
        let mk = |seed: u8| -> WitnessSig {
            let sk = SigningKey::from_bytes(&[seed; 32]);
            let pk = sk.verifying_key().to_bytes().to_vec();
            WitnessSig {
                validator_id: *blake3::hash(&pk).as_bytes(),
                validator_pk: pk,
                vbc_bundle: None,
                carrier_type: String::new(),
                carrier_address: String::new(),
                signature: sk.sign(&commitment_hash).to_bytes().to_vec(),
                execution_proof: alloc::vec![],
                proof_type: 1,
                availability_attestation: None,
                validator_hints: alloc::vec![],
                fact_signature: None,
                checkpoint_sig: None,
                receipt_signature: None,
                receipt_commitment_sig: Some(sk.sign(&receipt_commitment).to_bytes().to_vec()),
                rate_bps: 0,
                slot_amount: 0,
            }
        };
        let witness_sigs: alloc::vec::Vec<WitnessSig> = seeds.iter().map(|s| mk(*s)).collect();
        let receipt = Receipt {
            oods_flag,
            confidence_index: None,
            sender_state: None,
            txid, state_hash, produced_state_id: [0xDD; 32], new_wallet_seq,
            commitment_hash, sdid: [0u8; 32], lineage_hash: [0u8; 32],
            witness_sigs,
            core_version: String::new(), core_id: [0u8; 32], epoch,
            fact_proof: None, required_k: 3, receipt_commitment,
            fee_breakdown: alloc::vec::Vec::new(), is_dev_class: false,
        };
        // The renewer's Ed25519 pk (for the co-signed match).
        let renewer_pk = SigningKey::from_bytes(&[renewer_seed; 32]).verifying_key().to_bytes().to_vec();
        (receipt, renewer_pk)
    }

    #[test]
    fn valid_cosigned_fresh_receipt_ok() {
        let (r, pk) = mk_work_receipt(0x01, 5000, true, true, 3);
        assert_eq!(verify_renewal_work_receipt(&r, &pk, 4000), Ok(()));
    }

    #[test]
    fn stale_none_oods_rejected() {
        // No OODS reading (heal/genesis/offline) — no tick to judge this term.
        let (r, pk) = mk_work_receipt(0x01, 5000, false, true, 3);
        assert_eq!(verify_renewal_work_receipt(&r, &pk, 4000), Err(ValidationError::VbcRenewalWorkReceiptStale));
    }

    #[test]
    fn stale_old_tick_rejected() {
        // tick == min_tick is NOT newer; must strictly post-date the cert.
        let (r, pk) = mk_work_receipt(0x01, 4000, true, true, 3);
        assert_eq!(verify_renewal_work_receipt(&r, &pk, 4000), Err(ValidationError::VbcRenewalWorkReceiptStale));
    }

    #[test]
    fn not_cosigned_rejected() {
        // The renewer's key is NOT among the witnesses.
        let (r, _pk) = mk_work_receipt(0x01, 5000, true, false, 3);
        let renewer_pk = SigningKey::from_bytes(&[0x01u8; 32]).verifying_key().to_bytes().to_vec();
        assert_eq!(verify_renewal_work_receipt(&r, &renewer_pk, 4000), Err(ValidationError::VbcRenewalNotCoSigned));
    }

    #[test]
    fn sub_quorum_rejected() {
        // Only 2 witnesses — below the absolute floor of 3.
        let (r, pk) = mk_work_receipt(0x01, 5000, true, true, 2);
        assert_eq!(verify_renewal_work_receipt(&r, &pk, 4000), Err(ValidationError::VbcRenewalWorkReceiptSubQuorum));
    }

    #[test]
    fn listed_but_forged_cosig_rejected() {
        // MUTATION GUARD for check (c): the renewer's key IS listed, but its
        // receipt_commitment_sig is garbage. Being listed must not pass — the
        // signature has to verify. (Drop the sig-verify in check (c) and this
        // goes from NotCoSigned to Ok — the test catches it.)
        let (mut r, pk) = mk_work_receipt(0x01, 5000, true, true, 3);
        // Corrupt the renewer's receipt_commitment_sig (index 0 is the renewer).
        r.witness_sigs[0].receipt_commitment_sig = Some(alloc::vec![0u8; 64]);
        // With one sig now invalid, the quorum drops to 2 valid → SubQuorum fires
        // first (still a reject; the point is it is NOT Ok).
        let res = verify_renewal_work_receipt(&r, &pk, 4000);
        assert!(res.is_err(), "a forged renewer co-sig must never pass, got {:?}", res);
    }

    #[test]
    fn find_renewal_prev_detects_same_subject() {
        let subject = alloc::vec![0x77u8; 32];
        let target = minimal_vbc(subject.clone(), 0);
        let prev = minimal_vbc(subject.clone(), 4000); // same subject = the renewal's prior cert
        let issuer = minimal_vbc(alloc::vec![0x11u8; 32], 0); // different subject
        let bundle = VBCProofBundle {
            target_vbc: target,
            supporting_vbcs: alloc::vec![issuer, prev],
            candidacy_pulse: None,
            renewal_work_receipt: None,
        };
        let found = find_renewal_prev(&bundle);
        assert!(found.is_some(), "a same-subject supporting cert marks a renewal");
        assert_eq!(found.unwrap().baseline_tick, 4000);
    }

    #[test]
    fn find_renewal_prev_none_on_first_issuance() {
        let target = minimal_vbc(alloc::vec![0x77u8; 32], 0);
        // Only issuer certs (different subjects) — a first issuance, not a renewal.
        let bundle = VBCProofBundle {
            target_vbc: target,
            supporting_vbcs: alloc::vec![
                minimal_vbc(alloc::vec![0x11u8; 32], 0),
                minimal_vbc(alloc::vec![0x22u8; 32], 0),
                minimal_vbc(alloc::vec![0x33u8; 32], 0),
            ],
            candidacy_pulse: None,
            renewal_work_receipt: None,
        };
        assert!(find_renewal_prev(&bundle).is_none(), "no same-subject cert = first issuance, gate skipped");
    }
}
