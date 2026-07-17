//! FACT Chain verification — Money Provenance (YPX-001)
//!
//! Every wallet carries a FACT chain proving its money traces back to genesis.
//! Same trust model as VBC: genesis validators are the root of trust.
//!
//! Core verifies:
//!   1. Chain continuity (state_id links connect)
//!   2. Witness signatures on each link
//!   3. Genesis origin (first link traces to genesis state)
//!   4. Checkpoint integrity (if present)
//!   5. Max depth (≤5 uncompressed links)
//!
//! Core does NOT reject scarred links. Whether to accept scarred money
//! is the receiver's decision. Core only verifies cryptographic integrity.
//!
//! # Execution Modes
//!
//! FACT verification runs inside Core (AVM interpreter, DMAP-attested).
//! All FACT operations are deterministic and produce verifiable attestations:
//!   - DMAP path (default): AVM memory attestation proves correct execution
//!   - ZKP path (premium): RISC Zero STARK proof (future — zkVM guest already
//!     handles FactCargo for fact_commitment computation)
//!
//! Lambda NEVER builds FACT proofs — it only signs commitments computed by Core.
//! FACT is a Core-layer construct; Lambda is merely a witness that signs.

// CONSENSUS_CRITICAL

use alloc::vec;
use alloc::vec::Vec;
use crate::types::{ChequeBundle, FactChain, FactCheckpoint, FactLink, FactWitness, NablaConfirmation};
use crate::errors::ValidationError;
use crate::crypto::ct_eq;

/// Minimum links to keep as the live tail after a checkpoint is FINALIZED.
/// SEC-07 (2026-06-13): lowered 5→3 to bound chain depth ~6–8 (was ~10–14),
/// which roughly halves wallet size + the soak's lock-hold/FLOCK contention.
pub const FACT_KEEP: usize = 3;

/// Maximum uncompressed FACT links before compression required.
/// Allows headroom for client-side bridging links (redeem, etc.)
/// that accumulate between server visits. Any Core compresses when > SOFT_MAX.
pub const FACT_COMPRESS_TRIGGER: usize = 5;
pub const MAX_FACT_DEPTH: usize = 8;

// ── SEC-07 travel-model checkpoint (AXIOM Origin 2026-06-12) ──────────────────────
// docs/security_review_20260612/SEC-07_RESOLUTION.md
//
// A checkpoint is a PROPOSAL that travels with the wallet's chain and accumulates
// distinct validator co-signatures across rounds. The covered links are RETAINED
// (provisional) until the proposal reaches CHECKPOINT_SIG_THRESHOLD distinct sigs,
// then they are deleted (finalized). All tunable — test empirically.

/// Chain depth (total link count — consensus-agreed, since every link is signed)
/// at which the FIRST validator writes the checkpoint proposal. A *start* signal,
/// NOT "compress now". The chain keeps growing past this while sigs accumulate.
/// SEC-07 (2026-06-13): lowered 7→4 (with FACT_KEEP=3) so chains finalize shallower.
pub const FACT_PROPOSE_TRIGGER: usize = 4;

/// Distinct validator co-signatures a checkpoint PROPOSAL must accumulate before it
/// FINALIZES (covered links deleted). Global, = MIN_FACT_WITNESSES (k=3). Only the TX
/// finalizer compresses, and only once the proposal carries this many distinct sigs;
/// sigs accumulate across rounds via S-ABR overlap (~1 new sig/tx). Kept global (not
/// per-k) deliberately: a verifier can't cross-check a per-k threshold after the
/// covered links are deleted, so per-k would let colluding validators forge it
/// downward. See advance_fact_checkpoint + verify_checkpoint.
pub const CHECKPOINT_SIG_THRESHOLD: usize = 3;

/// Anti-abuse ceiling ONLY — never the compression trigger. With S-ABR overlap the
/// proposal gains ~1 sig per TX, so a chain peaks around depth 11-12 before
/// finalizing; this generous bound just caps a pathological non-converging chain.
pub const FACT_HARD_CEILING: usize = 32;

/// Minimum witnesses per FACT link (same as k=3 requirement)
pub const MIN_FACT_WITNESSES: usize = 3;

/// Verify a complete FACT chain.
/// Returns Ok(scar_count) on success, Err on integrity failure.
///
/// This runs in CL2 during redeem: receiver's validators verify the sender's
/// money provenance before accepting the cheque.
/// Rejects chains that exceed MAX_FACT_DEPTH resolved links (must compress first).
///
/// Runs inside AVM (DMAP-attested). ZKP premium path: future RISC Zero guest integration.
pub fn verify_fact_chain(chain: &FactChain) -> Result<usize, ValidationError> {
    verify_fact_chain_inner(chain, true)
}

/// Pure structural continuity check — NO Dilithium witness verification,
/// NO depth enforcement, NO scar accounting. Validates ONLY:
///   - empty chain + no checkpoint → OK (genesis wallet)
///   - if checkpoint present: `links[0].previous_state_id ==
///     checkpoint.final_state_id`
///   - for every i ≥ 1: `links[i].previous_state_id == links[i-1].new_state_id`
///   - class-lock: every i ≥ 1: `links[i].is_dev_class == links[i-1].is_dev_class`
///
/// Returns the same `FactChainBreak` / `DomainMismatch` error codes
/// `verify_fact_chain` returns for the corresponding structural failures,
/// so callers that already dispatch on those codes work unchanged.
///
/// Existence rationale: the SDK's `set_fact_chain` must REJECT a
/// continuity-broken chain at storage time (silent corruption is a
/// Tier 1 fund-loss class, see CLAUDE.md §15 and `wallet.rs` for the
/// uj-class repro). Running the full `verify_fact_chain` there is
/// wrong because:
///   1. SDK unit-test fixtures use synthetic links without Dilithium
///      witnesses — every test would fail `FactInsufficientWitnesses`.
///   2. The SDK is NOT the crypto authority (CLAUDE.md §1); witness-
///      sig validation runs at Core via Lambda's CL2/CL3/CL5 pass on
///      the next protocol op. The SDK's job at this boundary is
///      structural integrity, not crypto re-verification.
///
/// This is the targeted no_std structural check: catches the uj
/// silent-persist hole without forcing the SDK to carry crypto
/// authority it shouldn't have.
pub fn check_fact_chain_continuity(chain: &FactChain) -> Result<(), ValidationError> {
    // Empty chain is valid only when no checkpoint anchors it (genesis
    // wallets). Mirrors the early-out in verify_fact_chain_inner.
    if chain.links.is_empty() && chain.checkpoint.is_none() {
        return Ok(());
    }

    // Checkpoint anchor (SEC-07): only for a FINALIZED checkpoint, whose covered
    // links are gone — the first remaining link must chain from final_state_id.
    // A PROVISIONAL checkpoint still RETAINS its covered links at the front, so
    // final_state_id sits mid-chain (at covered[pending_links-1]) and the
    // first_link is a covered link chaining from genesis/prior — the anchor check
    // does NOT apply. Without this skip, set_fact_chain rejects every provisional
    // chain as "structurally broken" and the wallet drops the travelling
    // checkpoint (so it never accumulates co-signatures). Mirrors
    // verify_fact_chain_inner's provisional/finalized split.
    if let Some(ref checkpoint) = chain.checkpoint {
        if checkpoint.pending_links == 0 {
            if let Some(first_link) = chain.links.first() {
                if !ct_eq(&first_link.previous_state_id, &checkpoint.final_state_id) {
                    return Err(ValidationError::FactChainBreak);
                }
            }
        }
    }

    // Continuity + class-lock walk. Same rules + same errors as
    // verify_fact_chain_inner; just no Dilithium pass.
    for i in 1..chain.links.len() {
        let prev = &chain.links[i - 1];
        let link = &chain.links[i];
        if !ct_eq(&link.previous_state_id, &prev.new_state_id) {
            return Err(ValidationError::FactChainBreak);
        }
        if link.is_dev_class != prev.is_dev_class {
            return Err(ValidationError::DomainMismatch);
        }
    }

    Ok(())
}

/// Verify AND auto-compress a FACT chain.
///
/// Any Core instance (validator or client) can call this. Core verifies all
/// links, then compresses resolved links into a checkpoint if depth > MAX_FACT_DEPTH.
/// The compression is transparent — callers get back a valid, possibly shorter chain.
///
/// When running inside RISC Zero, the ZKP receipt proves the compression was
/// performed by legitimate Core, so other Core instances trust it.
///
/// Arguments:
/// - chain: The FACT chain (takes ownership)
/// - validators: Slice of (validator_id, dilithium_pk, dilithium_sk) for k=3 checkpoint signing
///
/// Returns: (compressed_chain, scar_count)
pub fn verify_and_compress_fact_chain(
    mut chain: FactChain,
    validators: &[([u8; 32], &[u8], &[u8])],
) -> Result<(FactChain, usize), ValidationError> {
    // Verify integrity first (skip depth rejection — we compress below).
    let scar_count = verify_fact_chain_inner(&chain, false)?;

    // Compress if resolved prefix exceeds soft max.
    // Only RESOLVED links (Nabla-confirmed or burned) are compressible.
    // Scarred links are NEVER compressed — they stay visible forever.
    let resolved_prefix = chain.links.iter()
        .take_while(|l| l.is_resolved())
        .count();
    if resolved_prefix > FACT_COMPRESS_TRIGGER {
        chain = compress_fact_chain(chain, validators)?;
    }

    // Post-compression depth check: ensure the result would pass standalone verify.
    // Handles edge case: [scar, resolved×9] has resolved_count=9 but prefix=0,
    // so compression doesn't trigger, yet total resolved exceeds MAX_FACT_DEPTH.
    // The chain is cryptographically valid but structurally over-depth — reject.
    let resolved_count = chain.links.iter()
        .filter(|l| l.is_resolved())
        .count();
    if resolved_count > MAX_FACT_DEPTH {
        return Err(ValidationError::FactChainTooDeep);
    }

    Ok((chain, scar_count))
}

/// SEC-07 travel model: APPEND distinct validator co-signatures to the chain's
/// (provisional) checkpoint. Each co-sign is over the STORED checkpoint's
/// commitment — the bytes already on the chain, identical for every co-signer, so
/// there is nothing to diverge (this is what the abandoned "fresh per-witness
/// recompute" got wrong). Co-signs that don't verify over the stored commitment,
/// or whose validator_id already signed, are dropped. Returns the number newly
/// appended. `None` checkpoint → no-op (Ok(0)).
///
/// Used by the finalizer to fold in the k witnesses' co-signs
/// (`WitnessSig.checkpoint_sig`) that arrived this round, accumulating toward
/// `CHECKPOINT_SIG_THRESHOLD`. See `docs/security_review_20260612/SEC-07_RESOLUTION.md`.
pub fn merge_checkpoint_endorsements(
    chain: &mut FactChain,
    cosigns: &[FactWitness],
) -> Result<usize, ValidationError> {
    let checkpoint = match chain.checkpoint.as_mut() {
        Some(cp) => cp,
        None => return Ok(0),
    };
    let commitment = compute_checkpoint_commitment(checkpoint);
    let mut appended = 0usize;
    for c in cosigns {
        // Skip a validator that already signed this proposal (dedup).
        if checkpoint.validator_sigs.iter().any(|s| ct_eq(&s.validator_id, &c.validator_id)) {
            continue;
        }
        // Only append a co-sign that verifies over the STORED commitment.
        if crate::crypto::verify_dilithium(&c.validator_pk, &commitment, &c.signature).is_ok() {
            checkpoint.validator_sigs.push(FactWitness {
                validator_id: c.validator_id,
                validator_pk: c.validator_pk.clone(),
                signature: c.signature.clone(),
                vbc_genesis_anchor: None,
            });
            appended += 1;
        }
    }
    Ok(appended)
}

/// SEC-07 travel model: produce THIS validator's co-signature of the STORED
/// provisional checkpoint on `chain`, if there is one it hasn't already signed.
/// The validator re-verifies the retained covered links against the proposal's
/// `root_hash` before signing — so a co-sign genuinely attests "I checked the real
/// history and this summary is honest." Returns None when there's no provisional
/// checkpoint, the validator already signed, or the retained links don't match.
///
/// Lambda calls this at witness time; the finalizer folds the collected co-signs
/// in via `merge_checkpoint_endorsements`. Core remains the signing authority.
pub fn cosign_provisional_checkpoint(
    chain: &FactChain,
    validator_id: [u8; 32],
    dilithium_pk: &[u8],
    dilithium_sk: &[u8],
) -> Result<Option<FactWitness>, ValidationError> {
    let cp = match chain.checkpoint.as_ref() {
        Some(cp) if cp.pending_links > 0 => cp,
        _ => return Ok(None), // no provisional checkpoint to co-sign
    };
    let m = cp.pending_links as usize;
    if m > chain.links.len() {
        return Ok(None);
    }
    // Re-verify the retained covered links against the committed root_hash.
    if !ct_eq(&compute_checkpoint_root(&chain.links[..m]), &cp.root_hash) {
        return Ok(None);
    }
    // Don't co-sign twice.
    if cp.validator_sigs.iter().any(|s| ct_eq(&s.validator_id, &validator_id)) {
        return Ok(None);
    }
    let commitment = compute_checkpoint_commitment(cp);
    let sig = crate::crypto::sign_dilithium(dilithium_sk, &commitment)
        .map_err(|_| ValidationError::FactInvalidSignature)?;
    Ok(Some(FactWitness {
        validator_id,
        validator_pk: dilithium_pk.to_vec(),
        signature: sig,
        vbc_genesis_anchor: None,
    }))
}

// ─────────────────────────────────────────────────────────────────────────
// KI#13 RELAX — narrow exception to CLAUDE.md "Core is sole crypto authority".
// We deliberately skip Ed25519/Dilithium verification of the SCARRED link's
// fact_signature when it is being retired by a burn TX. Approved by AXIOM Origin
// 2026-06-08 with explicit discomfort recorded; see
// docs/AXIOM_REPORT_KnownIssues.md #13 and CLAUDE.md "Exceptional non-verify
// carve-out (KI#13)" for the economic-safety analysis. This is the ONLY site
// where verification is relaxed. DO NOT generalize. DO NOT add a sibling
// `skip_*_verify` flag for any other flow. If you are tempted to copy this
// pattern, the answer is no — talk to AXIOM Origin first.
//
// Safety is bound by the burn flow's economic gate at validation.rs:
// validate_burn_target enforces (a) the burn-target link exists in the chain,
// (b) it is genuinely scarred, (c) tx.amount == link.amount, AND
// verify_balance enforces the cap at available_balance. Together these mean
// a fake-scar burn can at most self-destroy the wallet's real available
// funds — no inflation, no minting, no double-spend, no cross-wallet impact.
// ─────────────────────────────────────────────────────────────────────────

/// Verify a FACT chain, skipping the Dilithium witness-sig check on the
/// SCARRED link being retired by a burn TX (the link whose `tx_id` matches
/// `burn_target_tx_id`). All other links and all other structural checks
/// (chain continuity, k-witness count, duplicate-validator gate, burn_proof
/// structural integrity, VBC genesis anchors, NablaConfirmation Ed25519,
/// FACT class lock, depth limits) still verify at full strength.
///
/// See the KI#13 RELAX comment block above this function for the
/// load-bearing economic-safety argument. Use this entry point ONLY when
/// validating a burn TX that retires the link identified by
/// `burn_target_tx_id`.
pub fn verify_fact_chain_burn_retire(
    chain: &FactChain,
    burn_target_tx_id: &[u8; 32],
) -> Result<usize, ValidationError> {
    verify_fact_chain_inner_with_burn_skip(chain, true, Some(burn_target_tx_id))
}

/// Verify-and-compress variant of [`verify_fact_chain_burn_retire`]. Use ONLY
/// when validating a burn TX. See KI#13 RELAX comment above
/// `verify_fact_chain_burn_retire` for the load-bearing safety argument.
pub fn verify_and_compress_fact_chain_burn_retire(
    mut chain: FactChain,
    validators: &[([u8; 32], &[u8], &[u8])],
    burn_target_tx_id: &[u8; 32],
) -> Result<(FactChain, usize), ValidationError> {
    // Verify integrity first (skip depth rejection — we compress below).
    let scar_count = verify_fact_chain_inner_with_burn_skip(&chain, false, Some(burn_target_tx_id))?;

    // Compress logic mirrors verify_and_compress_fact_chain exactly — only the
    // verify step differs (the scarred-link sig is skipped above). Compression
    // never touches scarred links (take_while on resolved prefix), so it is
    // unaffected by whether the scar was sig-verified.
    let resolved_prefix = chain.links.iter()
        .take_while(|l| l.is_resolved())
        .count();
    if resolved_prefix > FACT_COMPRESS_TRIGGER {
        chain = compress_fact_chain(chain, validators)?;
    }
    let resolved_count = chain.links.iter()
        .filter(|l| l.is_resolved())
        .count();
    if resolved_count > MAX_FACT_DEPTH {
        return Err(ValidationError::FactChainTooDeep);
    }

    Ok((chain, scar_count))
}

/// Internal verification logic shared by verify and verify_and_compress.
///
/// `enforce_depth`: when true, reject chains with more than MAX_FACT_DEPTH resolved links.
/// verify_fact_chain sets true (standalone verify — client must compress first).
/// verify_and_compress sets false (will compress after verification succeeds).
pub(crate) fn verify_fact_chain_inner(chain: &FactChain, enforce_depth: bool) -> Result<usize, ValidationError> {
    verify_fact_chain_inner_with_burn_skip(chain, enforce_depth, None)
}

/// Real workhorse. When `burn_skip` is `Some(target_tx_id)`, the Dilithium
/// witness-sig verification on the matching link is skipped. All other
/// structural checks on that link still run, and ALL checks on every other
/// link run at full strength. See KI#13 RELAX comment block above
/// `verify_fact_chain_burn_retire`.
pub(crate) fn verify_fact_chain_inner_with_burn_skip(chain: &FactChain, enforce_depth: bool, burn_skip: Option<&[u8; 32]>) -> Result<usize, ValidationError> {
    // Empty chain is valid only for genesis wallets (no history yet)
    if chain.links.is_empty() && chain.checkpoint.is_none() {
        return Ok(0);
    }

    // Hard absolute protocol limit on total links (consensus-level ceiling).
    // All validators agree on this — it's a protocol constant, not configurable.
    // 64 links × ~80KB ≈ 5MB CBOR — ~60s in interpreter, ~3s with JIT.
    // Supports Ark mode / extended partitions (72h at 1 TX/h = 72 links).
    // Operators set a LOWER soft limit in Lambda config (default 16) to reject
    // before AVM execution on weaker hardware. See lambda.toml max_fact_links.
    const MAX_TOTAL_LINKS: usize = 64;
    if chain.links.len() > MAX_TOTAL_LINKS {
        return Err(ValidationError::FactChainTooDeep);
    }

    // SECURITY-SCAR (Scarred FACT / Money Provenance Integrity):
    // Scars are PERMANENT marks on money that passed through unconfirmed transactions.
    // A FACT link is "scarred" when it has NO Nabla confirmation and NO burn proof.
    // CLEAN = confirmed by Nabla. SCARRED = unconfirmed. BURNED = intentionally destroyed.
    //
    // Key rule: scarred links grow UNLIMITED — they are NEVER compressed away.
    // This prevents "wash-out" attacks where money launderers transact repeatedly
    // to push scars off the chain until the depth limit forces trimming.
    // Only RESOLVED (clean or burned) links count toward MAX_FACT_DEPTH.
    //
    // Core does NOT reject scarred money — that is the RECEIVER's decision.
    // Core only verifies chain integrity. The scar is visible to everyone.
    //
    // To remove a scar: either HEAL (Nabla confirms the original TX was legitimate)
    // or BURN (destroy the tainted amount, send to BURN_ADDRESS).
    //
    // Ref: Yellow Paper §26.17, YPX-001 §1.5 (scar_passcode), §1.5.4 (burn address),
    //      §1.5.6 (scar heal), White Paper §5.7.
    // See also: SECURITY-FACT markers for chain continuity checks.
    // SEC-07 travel model: depth is no longer a hard compression deadline. A
    // proposal accumulates ~1 sig/TX (S-ABR overlap), so a chain legitimately
    // grows to ~11-12 before it has 5 sigs and finalizes. Keep only a generous
    // anti-abuse ceiling so a pathological non-converging chain can't grow forever.
    if enforce_depth {
        let resolved_count = chain.links.iter()
            .filter(|link| link.nabla_confirmation.is_some() || link.burn_proof.is_some()
                || link.recall_proof.is_some())
            .count();
        if resolved_count > FACT_HARD_CEILING {
            return Err(ValidationError::FactChainTooDeep);
        }
    }

    // Verify checkpoint if present — provisional vs finalized (SEC-07).
    if let Some(ref checkpoint) = chain.checkpoint {
        if checkpoint.pending_links > 0 {
            // PROVISIONAL: the covered links are RETAINED at the front of the
            // chain. Verify they are present and hash to the proposal's root_hash;
            // the chain then verifies through those real links below (continuity +
            // full Dilithium on every link). Signatures are still accumulating, so
            // the k=5 threshold does NOT apply yet — but the sigs present must be
            // distinct and valid (a malicious proposer can't pad with junk sigs).
            let m = checkpoint.pending_links as usize;
            if m > chain.links.len() {
                return Err(ValidationError::FactChainBreak);
            }
            let covered_root = compute_checkpoint_root(&chain.links[..m]);
            if !ct_eq(&covered_root, &checkpoint.root_hash) {
                // Retained links don't match the proposal — forged pending_links
                // or tampered covered links.
                return Err(ValidationError::FactInvalidSignature);
            }
            verify_checkpoint_sigs(checkpoint)?;
            // No final_state_id anchor check here: while provisional, final_state_id
            // sits MID-chain at links[m-1], and continuity is verified over all links.
        } else {
            // FINALIZED: covered links deleted; the summary is the sole provenance.
            // Enforce the k=5 distinct-sig gate + the anchor to the live tail.
            verify_checkpoint(checkpoint)?;
            if let Some(first_link) = chain.links.first() {
                if !ct_eq(&first_link.previous_state_id, &checkpoint.final_state_id) {
                    return Err(ValidationError::FactChainBreak);
                }
            }
        }
    }
    
    // SECURITY-FACT (Financial Audit & Compliance Trail):
    // Chain continuity — each link[i].previous_state_id must equal link[i-1].new_state_id.
    // This is the core provenance guarantee: every AXC atom traces back to genesis
    // through an unbreakable cryptographic chain. Forging a link requires breaking BLAKE3.
    // Ref: Yellow Paper §1A Anchor 2, §26.17 RULE FACT-1.
    // Verify each link (full Dilithium) and chain continuity.
    // ALL links get full Dilithium verification — the FACT chain is
    // client-provided and untrusted. Chain continuity (state_id chaining)
    // does NOT prove link content integrity because the FACT commitment
    // includes fields (amount, tx_id) not in the state_id hash. Skipping
    // Dilithium on older links would allow a malicious client to forge
    // intermediate link content (scar washing, audit trail forgery).
    let mut scar_count = 0;
    for (i, link) in chain.links.iter().enumerate() {
        // KI#13 RELAX (see comment block above verify_fact_chain_burn_retire):
        // skip the witness-sig verify ONLY when this link is the scarred link
        // being retired by a burn TX. All other links and all other structural
        // checks on THIS link still run at full strength.
        let skip_witness_sigs = burn_skip.map_or(false, |target| ct_eq(target, &link.tx_id));
        if let Err(e) = verify_fact_link_internal(link, skip_witness_sigs) {
            #[cfg(feature = "std")]
            { extern crate std; std::eprintln!("[verify_fact_chain DIAG] link[{}] failed verify_fact_link: {:?}", i, e); }
            return Err(e);
        }

        // Chain continuity: link[i].previous_state_id == link[i-1].new_state_id
        if i > 0 {
            let prev = &chain.links[i - 1];
            if !ct_eq(&link.previous_state_id, &prev.new_state_id) {
                return Err(ValidationError::FactChainBreak);
            }
            // FACT chain class lock — sticky invariant
            // (`AXIOM_DESIGN_FactChainClassLock.md`). The class is set
            // ONCE at the genesis link and inherited unchanged on
            // every subsequent link. A break here means the chain
            // crossed a class boundary — reject as `DomainMismatch`
            // (same error as Rule R1's per-TX check, just at a deeper
            // structural level).
            if link.is_dev_class != prev.is_dev_class {
                #[cfg(feature = "std")]
                { extern crate std; std::eprintln!(
                    "[verify_fact_chain DIAG] link[{}] class break: prev={} new={}",
                    i, prev.is_dev_class, link.is_dev_class,
                ); }
                return Err(ValidationError::DomainMismatch);
            }
        }

        // BurnProof.burn_tx_id must reference an actual link in this chain
        // (YPX-001 §1.5.4). Without this check the burn_tx_id could point
        // anywhere — at a forged value, or at a link in some other wallet's
        // chain — and the structural sig-count check above would still pass.
        if let Some(ref burn_proof) = link.burn_proof {
            let burn_link_present = chain.links.iter()
                .any(|l| ct_eq(&l.tx_id, &burn_proof.burn_tx_id));
            if !burn_link_present {
                return Err(ValidationError::BurnTxIdNotInChain);
            }
        }

        // YPX-022 RECALL: a scarred link is ALSO resolved if it carries a valid
        // recall_proof — a Nabla-signed RecallAttestation whose txid == this link's
        // tx_id, proving the sub-quorum send here was reclaimed (no value moved). This
        // replaces the earlier Lambda-side scar-passcode exemption for is_recall with a
        // real, verified resolution: the scar is cleared, not skipped. Forgery-proof —
        // the attestation is Nabla Ed25519 + NBC-root anchored (verify_recall_attestation),
        // so an attacker can't wash out a genuine scar by attaching a fake proof.
        let recall_resolved = link.recall_proof.as_ref().is_some_and(|att| {
            ct_eq(&att.txid, &link.tx_id)
                && crate::validation::verify_recall_attestation(att).is_ok()
        });

        // Track scars: own transition unresolved (no Nabla confirmation AND
        // no burn proof AND not recall-resolved) OR any inherited scar
        // unresolved (YPX-001 §1.5.1a — inherited taint keeps the link
        // scarred no matter how the link's own transition resolved).
        if (link.nabla_confirmation.is_none() && link.burn_proof.is_none() && !recall_resolved)
            || link.inherited_unresolved() > 0
        {
            scar_count += 1;
        }
    }

    Ok(scar_count)
}

/// Verify a `NablaConfirmation` cryptographically binds to the link it
/// claims to confirm.
///
/// This is the SINGLE canonical authority (CLAUDE.md §12) for "is this
/// confirmation valid for this state transition?". `verify_fact_link_internal`
/// calls it for the confirmation on a stored link; the SDK calls it as an
/// ingest gate BEFORE splicing a freshly-received confirmation onto a link,
/// so a confirmation that doesn't bind (e.g. spliced onto the wrong, scarred
/// link under fork/divergence) is left as `None` (valid-but-scarred, burnable)
/// instead of stored present-but-invalid (which permanently wedges the wallet —
/// the heal→burn re-verify here returns `FactInvalidSignature`, the burn is
/// rejected, the scar never clears).
///
/// Three checks, byte-identical to the historical inline block in
/// `verify_fact_link_internal`:
///   1. Forged-stub reject: empty `nabla_signature` or zero `nabla_node_id`.
///   2. V2 Ed25519: `verify_ed25519(nabla_node_id, payload, nabla_signature)`
///      where
///        `tx_hash  = BLAKE3("AXIOM_TXHASH" || previous_state_id || new_state_id)`
///        `payload  = BLAKE3("AXIOM_FACT_CONFIRM_V2" || tx_hash || new_state_id
///                            || committed_at_tick.to_le_bytes())`
///      (V2 — includes `committed_at_tick` so Core CL5 can enforce the
///       same-tick redeem block, YP §17.10.5.3).
///   3. NBC trust-anchor sub-check: when any of the three NBC fields is
///      present, require the SPHINCS+ bundle to verify against
///      `NABLA_ROOT_AUTHORITY_PKS` (KI#8). All-empty = out-of-band trust,
///      accepted pre-mainnet.
///
/// Any failure returns `ValidationError::FactInvalidSignature`. no_std-clean.
pub fn verify_nabla_confirmation(
    previous_state_id: &[u8; 32],
    new_state_id: &[u8; 32],
    conf: &NablaConfirmation,
) -> Result<(), ValidationError> {
    // Empty signature = forged confirmation. Reject unconditionally.
    if conf.nabla_signature.is_empty() || conf.nabla_node_id == [0u8; 32] {
        #[cfg(feature = "std")]
        {
            extern crate std;
            std::eprintln!(
                "[verify_fact_link DIAG] FAIL: nabla_confirmation forged (sig_empty={} node_id_zero={})",
                conf.nabla_signature.is_empty(),
                conf.nabla_node_id == [0u8; 32],
            );
        }
        return Err(ValidationError::FactInvalidSignature);
    }
    {
        // V2 payload (2026-05-15): includes committed_at_tick so
        // Core CL5 can enforce the same-tick redeem block (YP
        // §17.10.5.3).  Domain tag bumped to "AXIOM_FACT_CONFIRM_V2";
        // any pre-V2 confirmation that survived the upgrade gets
        // rejected here.  Pre-mainnet, no compat shim per CLAUDE.md §13.
        let tx_hash = {
            let mut h = blake3::Hasher::new();
            h.update(b"AXIOM_TXHASH");
            h.update(previous_state_id);
            h.update(new_state_id);
            *h.finalize().as_bytes()
        };
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AXIOM_FACT_CONFIRM_V2");
        hasher.update(&tx_hash);
        hasher.update(new_state_id);
        hasher.update(&conf.committed_at_tick.to_le_bytes());
        let payload = hasher.finalize();

        if crate::crypto::verify_ed25519(
            &conf.nabla_node_id,
            payload.as_bytes(),
            &conf.nabla_signature,
        ).is_err() {
            #[cfg(feature = "std")]
            {
                extern crate std;
                let hex8 = |b: &[u8]| -> std::string::String {
                    let n = b.len().min(8);
                    let mut s = std::string::String::new();
                    for byte in &b[..n] {
                        s.push_str(&std::format!("{:02x}", byte));
                    }
                    s
                };
                std::eprintln!(
                    "[verify_fact_link DIAG] FAIL: nabla_confirmation Ed25519 verify failed — prev={} new={} tick={} payload={} node_id={} sig_len={} sig[..8]={}",
                    hex8(previous_state_id),
                    hex8(new_state_id),
                    conf.committed_at_tick,
                    hex8(payload.as_bytes()),
                    hex8(&conf.nabla_node_id),
                    conf.nabla_signature.len(),
                    hex8(&conf.nabla_signature),
                );
            }
            return Err(ValidationError::FactInvalidSignature);
        }
    }

    // ── NBC trust-anchor check (KI#8 strengthening, 2026-05-15) ──
    //
    // The Ed25519 check above proves "someone with the private key for
    // `nabla_node_id` signed this payload" — but NOT that `nabla_node_id`
    // belongs to an authorized Nabla node. An attacker could fabricate
    // a fresh keypair, sign with it, and pass the math.
    //
    // The NBC bundle (`nbc_issuer_pk`/`nbc_signature`/`nbc_commitment`,
    // added to NablaConfirmation 2026-05-15) anchors `nabla_node_id`
    // to `NABLA_ROOT_AUTHORITY_PKS` via a SPHINCS+ signature — same
    // pattern as `verify_nbc_for_txid_attestation` /
    // `verify_nbc_for_cheque_claim_proof` / `verify_nbc_for_clara_attestation`.
    //
    // **Pre-mainnet semantics:** legacy wallet.cbor files carry confs
    // with empty NBC fields (the plumbing wasn't there yet). When all
    // three NBC fields are empty, we ACCEPT the conf based on
    // out-of-band trust (SDK only writes confs returned from real
    // Nabla TCP sessions; SDK never synthesizes). When ANY NBC field
    // is present, we require the bundle to verify — strict.
    //
    // **Mainnet flip:** the empty-fields branch will become a hard
    // reject. Tracked in `AXIOM_REPORT_KnownIssues.md` KI#8.
    let nbc_present = !conf.nbc_issuer_pk.is_empty()
        || !conf.nbc_signature.is_empty()
        || !conf.nbc_commitment.is_empty();
    if nbc_present {
        match crate::validation::verify_nbc_for_nabla_confirmation(conf) {
            Ok(true) => { /* anchored — proceed */ }
            Ok(false) | Err(_) => {
                #[cfg(feature = "std")]
                { extern crate std; std::eprintln!("[verify_fact_link DIAG] FAIL: NBC bundle verify failed"); }
                return Err(ValidationError::FactInvalidSignature);
            }
        }
    }

    Ok(())
}

/// Verify a single FACT link's integrity.
///
/// Standard entry point — verifies ALL checks including witness Dilithium
/// signatures. After KI#13 the production chain-verify path goes through
/// `verify_fact_link_internal` directly with `skip_witness_sigs=false`;
/// this wrapper survives for test call sites.
#[allow(dead_code)]
fn verify_fact_link(link: &FactLink) -> Result<(), ValidationError> {
    verify_fact_link_internal(link, false)
}

/// Real workhorse. When `skip_witness_sigs` is true, the Dilithium
/// signature verification loop is skipped, but ALL other structural checks
/// (k≥3 witnesses, no duplicate validators, burn_proof structural integrity,
/// VBC genesis anchors, NablaConfirmation Ed25519) still run.
///
/// `skip_witness_sigs = true` is reachable ONLY from
/// `verify_fact_chain_inner_with_burn_skip` when the link's `tx_id` matches
/// the burn-target. See the KI#13 RELAX comment block above
/// `verify_fact_chain_burn_retire` for the load-bearing safety argument and
/// the explicit "do not generalize" guidance.
fn verify_fact_link_internal(link: &FactLink, skip_witness_sigs: bool) -> Result<(), ValidationError> {
    // Must have k=3 witnesses minimum
    if link.witnesses.len() < MIN_FACT_WITNESSES {
        return Err(ValidationError::FactInsufficientWitnesses);
    }

    // Verify each witness Dilithium (ML-DSA-65) signature
    // FACT uses Dilithium (not SPHINCS+) because FACT is operational:
    // signed every transaction, needs speed (~1ms vs ~100ms for SPHINCS+).
    // Still quantum-resistant. VBC keeps SPHINCS+ (signed once at birth).
    // Signs: BLAKE3("AXIOM_FACT_v2" || tx_id || previous_state_id || new_state_id || amount || sender_anchor_or_zeros)
    let commitment = compute_fact_commitment(
        &link.tx_id,
        &link.previous_state_id,
        &link.new_state_id,
        link.amount,
        link.sender_anchor.as_ref(),
        link.is_dev_class,
        &link.inherited_scar_txids,
    );

    // YPX-001 §1.5.1a — inherited-scar RESOLUTIONS are post-round
    // attachments (like nabla_confirmation), verified HARD here: each must
    // target a txid in this link's inherited set, carry a valid Nabla
    // Ed25519 signature over the attestation payload, and anchor to a
    // NABLA_ROOT_AUTHORITY via NBC. A forged attachment rejects the chain
    // — an attacker cannot wash inherited taint with a fake attestation.
    // (Status string is NOT gated: ANY validly-attested status proves the
    // origin txid entered Nabla's record — re-register heals; "BURNED"
    // proves the origin destroyed the tainted amount.)
    for res in &link.inherited_scar_resolutions {
        if !link.inherited_scar_txids.iter().any(|t| crate::crypto::ct_eq(t, &res.txid)) {
            return Err(ValidationError::FactInvalidSignature);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AXIOM_TXID_ATTEST");
        hasher.update(&res.txid);
        hasher.update(res.status.as_bytes());
        hasher.update(&res.nabla_tick.to_le_bytes());
        let expected = hasher.finalize();
        if crate::crypto::verify_ed25519(
            &res.nabla_node_pk, expected.as_bytes(), &res.nabla_signature,
        ).is_err() {
            return Err(ValidationError::FactInvalidSignature);
        }
        // NBC trust anchor — MANDATORY, same posture as the CL5 redeem
        // attestation check (Phase 5e hotfix precedent: empty/invalid ⇒
        // reject; a self-signed attestation must never clear taint).
        if res.nbc_issuer_pk.is_empty()
            || !crate::validation::verify_nbc_for_txid_attestation(res).unwrap_or(false)
        {
            return Err(ValidationError::FactInvalidSignature);
        }
    }

    if skip_witness_sigs {
        // KI#13 RELAX — the entire Dilithium-verify loop is skipped for the
        // single scarred link being retired by a burn TX. See comment block
        // above `verify_fact_chain_burn_retire`. The commitment computation
        // above is still performed (cheap; useful for any future diagnostic),
        // and every check below this `if` (no duplicates, burn_proof
        // structural, VBC anchors, NablaConfirmation) still runs.
    } else {
    for (idx, witness) in link.witnesses.iter().enumerate() {
        if crate::crypto::verify_dilithium(
            &witness.validator_pk,
            &commitment,
            &witness.signature,
        ).is_err() {
            // DIAG: redeem (link with sender_anchor) is rejecting
            // Dilithium signatures. Print everything compute_fact_commitment
            // hashes plus the witness pk/sig lengths so we can see
            // whether the SDK assembled the link with different bytes
            // than what Core CL5 signed (commitment differs) or whether
            // the wire round-trip mangled signature/pk bytes (commitment
            // matches but verify fails on bad bytes).
            #[cfg(feature = "std")]
            {
                extern crate std;
                let hex8 = |b: &[u8]| -> std::string::String {
                    let n = b.len().min(8);
                    let mut s = std::string::String::new();
                    for byte in &b[..n] {
                        s.push_str(&std::format!("{:02x}", byte));
                    }
                    s
                };
                let anchor_hex = link.sender_anchor.as_ref()
                    .map(|a| hex8(a))
                    .unwrap_or_else(|| std::string::String::from("NONE"));
                std::eprintln!(
                    "[verify_fact_link FAIL] witness[{}]: tx_id={} prev={} new={} amount={} \
                     anchor={} commitment={} pk_len={} pk[..8]={} sig_len={} sig[..8]={}",
                    idx,
                    hex8(&link.tx_id),
                    hex8(&link.previous_state_id),
                    hex8(&link.new_state_id),
                    link.amount,
                    anchor_hex,
                    hex8(&commitment),
                    witness.validator_pk.len(),
                    hex8(&witness.validator_pk),
                    witness.signature.len(),
                    hex8(&witness.signature),
                );
            }
            return Err(ValidationError::FactInvalidSignature);
        }
    }
    } // end of `else { ... }` — KI#13 RELAX skip block

    // Verify no duplicate validators
    for i in 0..link.witnesses.len() {
        for j in (i + 1)..link.witnesses.len() {
            if ct_eq(&link.witnesses[i].validator_id, &link.witnesses[j].validator_id) {
                return Err(ValidationError::FactDuplicateWitness);
            }
        }
    }

    // Verify BurnProof structural integrity (YPX-001 §1.5.4).
    //
    // Closes the empty-validator_sigs forge: pre-2026-05-07 verify_fact_link
    // didn't look at burn_proof at all, so an attacker could mint
    //   BurnProof { burn_tx_id: any, validator_sigs: vec![] }
    // attach it to a scarred link, and `link.is_resolved()` returned true.
    // Counterparties accepting the chain in a redeem would treat the scar
    // as healed for free.
    //
    // Cryptographic verification of the validator_sigs against
    // compute_burn_commitment is deferred — that requires plumbing
    // wallet_pk into BurnProof (or adopting LinkKind so verify_fact_chain
    // can locate the burn TX link cleanly). Tracked in
    // docs/AXIOM_DESIGN_HEAL_SCAR_SPLIT.md §3.2 / §3.3.
    if let Some(ref burn_proof) = link.burn_proof {
        if burn_proof.validator_sigs.len() < MIN_FACT_WITNESSES {
            return Err(ValidationError::BurnProofInsufficientWitnesses);
        }
        for i in 0..burn_proof.validator_sigs.len() {
            for j in (i + 1)..burn_proof.validator_sigs.len() {
                if ct_eq(
                    &burn_proof.validator_sigs[i].validator_id,
                    &burn_proof.validator_sigs[j].validator_id,
                ) {
                    return Err(ValidationError::BurnProofDuplicateValidator);
                }
            }
        }
    }

    // L5: Verify VBC genesis anchor — each witness's chain must trace to ROOT_AUTHORITY_PKS
    for (idx, witness) in link.witnesses.iter().enumerate() {
        if let Some(ref anchor_chain) = witness.vbc_genesis_anchor {
            if anchor_chain.is_empty() {
                #[cfg(feature = "std")]
                { extern crate std; std::eprintln!("[verify_fact_link DIAG] FAIL: VBC anchor empty (witness idx={})", idx); }
                return Err(ValidationError::FactInvalidSignature);
            }
            // The root of the anchor chain must be a root authority key
            let root_pk = &anchor_chain[anchor_chain.len() - 1];
            if !crate::genesis::is_root_authority(root_pk) {
                #[cfg(feature = "std")]
                { extern crate std; std::eprintln!("[verify_fact_link DIAG] FAIL: VBC anchor root_pk not authority (witness idx={} root_pk_len={})", idx, root_pk.len()); }
                return Err(ValidationError::FactInvalidSignature);
            }
        }
        // Production: VBC genesis anchor is required. Without it, the witness
        // bypasses ROOT_AUTHORITY trust chain verification.
        #[cfg(not(feature = "dev-mode"))]
        if witness.vbc_genesis_anchor.is_none() {
            #[cfg(feature = "std")]
            { extern crate std; std::eprintln!("[verify_fact_link DIAG] FAIL: VBC anchor None (witness idx={}) — non-dev-mode build", idx); }
            return Err(ValidationError::FactInvalidSignature);
        }
    }

    // Verify NablaConfirmation signature if present.
    // A scarred link (no confirmation) is valid but unresolved.
    // A confirmed link MUST have a valid Ed25519 signature from the Nabla node.
    // Forged-stub + V2 Ed25519 + NBC trust-anchor are all in the single
    // canonical authority `verify_nabla_confirmation` (CLAUDE.md §12) so the
    // SDK ingest gate and this stored-link re-verify can never drift.
    if let Some(ref conf) = link.nabla_confirmation {
        verify_nabla_confirmation(
            &link.previous_state_id,
            &link.new_state_id,
            conf,
        )?;
    }

    Ok(())
}

/// Verify a FACT checkpoint's integrity.
///
/// SEC-07: requires k=3 (`MIN_FACT_WITNESSES`) DISTINCT validator signatures
/// over the checkpoint commitment. Compression *discards* the compressed links,
/// so post-compression the `root_hash` / `genesis_state_id` / `final_state_id` /
/// `total_amount` provenance is vouched for ONLY by these checkpoint sigs — the
/// discarded links' own k=3 witness sigs are gone. At the old `>= 1` threshold a
/// single malicious validator could forge a checkpoint (fabricate provenance —
/// claim non-genesis money traces to genesis) and downstream validators, unable
/// to re-derive the discarded links, would accept it on the strength of one sig.
///
/// The 3 distinct sigs are produced atomically in the compression round: every
/// witness in that round signs the *deterministic* checkpoint commitment with
/// its own Dilithium key (see `merge_checkpoint_endorsements` + the per-witness
/// CL3 path), and the finalizer merges them. Nabla is mandatory — a network
/// partition produces scars (by design), not reduced cryptographic protection.
/// See `docs/security_review_20260612/SEC-07_RESOLUTION.md`.
fn verify_checkpoint(checkpoint: &FactCheckpoint) -> Result<(), ValidationError> {
    // FINALIZED gate (SEC-07): the covered links are GONE, so the summary is the
    // sole provenance. Require CHECKPOINT_SIG_THRESHOLD distinct validator sigs.
    // (Provisional checkpoints, whose real links are still present, verify through
    // the links and call verify_checkpoint_sigs directly with no count gate.)
    if checkpoint.validator_sigs.len() < CHECKPOINT_SIG_THRESHOLD {
        return Err(ValidationError::FactInsufficientWitnesses);
    }
    verify_checkpoint_sigs(checkpoint)
}

/// Verify a checkpoint's signatures are distinct and valid over its commitment —
/// WITHOUT the threshold count. Used for provisional checkpoints (still
/// accumulating) and as the back half of the finalized gate.
fn verify_checkpoint_sigs(checkpoint: &FactCheckpoint) -> Result<(), ValidationError> {
    // Distinctness (SEC-07 gap #2): "k of N" is forgeable by one validator
    // signing N times without this. Mirror the BurnProof pairwise check.
    for i in 0..checkpoint.validator_sigs.len() {
        for j in (i + 1)..checkpoint.validator_sigs.len() {
            if ct_eq(
                &checkpoint.validator_sigs[i].validator_id,
                &checkpoint.validator_sigs[j].validator_id,
            ) {
                return Err(ValidationError::FactDuplicateWitness);
            }
        }
    }

    // Verify each Dilithium (ML-DSA-65) signature over the checkpoint commitment.
    let commitment = compute_checkpoint_commitment(checkpoint);
    for sig in &checkpoint.validator_sigs {
        if crate::crypto::verify_dilithium(
            &sig.validator_pk,
            &commitment,
            &sig.signature,
        ).is_err() {
            return Err(ValidationError::FactInvalidSignature);
        }
    }

    Ok(())
}

/// Compute FACT link commitment for signing.
/// BLAKE3("AXIOM_FACT_v2" || tx_id || previous_state_id || new_state_id ||
///        amount_le || sender_anchor_or_zeros)
///
/// `sender_anchor` is `Some(sender_chain_tip)` for REDEEM links and `None`
/// for SEND / HEAL / BURN links. None encodes as 32 zero bytes (constant-size
/// commitment, no parser branch).
///
/// Domain tag bumped from "AXIOM_FACT" to "AXIOM_FACT_v2" so legacy
/// signatures cannot accidentally verify under the new scheme — A2 cutover
/// is a hard wire-format break.
///
/// Runs deterministically inside AVM. Lambda calls Core for this — NEVER computes directly.
pub fn compute_fact_commitment(
    tx_id: &[u8; 32],
    previous_state_id: &[u8; 32],
    new_state_id: &[u8; 32],
    amount: u64,
    sender_anchor: Option<&[u8; 32]>,
    is_dev_class: bool,
    inherited_scar_txids: &[[u8; 32]],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_FACT_v2");
    hasher.update(tx_id);
    hasher.update(previous_state_id);
    hasher.update(new_state_id);
    hasher.update(&amount.to_le_bytes());
    let anchor_bytes = sender_anchor.copied().unwrap_or([0u8; 32]);
    hasher.update(&anchor_bytes);
    // `is_dev_class` — FACT chain class lock
    // (`AXIOM_DESIGN_FactChainClassLock.md`). Bound into the
    // commitment so a tampered flag invalidates every witness's
    // Dilithium fact_signature. No domain bump per CLAUDE.md §13.
    hasher.update(&[is_dev_class as u8]);
    // YPX-001 §1.5.1a scar inheritance (2026-07-12): the inherited taint
    // set is signed by every witness — a receiver cannot strip it without
    // invalidating all k Dilithium fact_signatures. Count is bound too so
    // an empty set is distinguishable and list length can't be gamed.
    // Formula change ⇒ CoreID rotation + pre-mainnet chain wipe (§13);
    // no domain bump, same as the is_dev_class addition.
    hasher.update(&(inherited_scar_txids.len() as u32).to_le_bytes());
    for t in inherited_scar_txids {
        hasher.update(t);
    }
    *hasher.finalize().as_bytes()
}

/// YPX-001 §1.5.1a — derive the inherited-scar set for a CROSS-WALLET
/// redeem link from the verified sender chain. THE single builder (every
/// signer + verifier calls this; CLAUDE.md §12 one-builder rule):
///
///   { link.tx_id            for unresolved sender links }
/// ∪ { inherited txid        for sender links' own unresolved inherited sets }
///   − { cheque_txid }        (the tx being redeemed — resolved by THIS
///                             redeem's own txid attestation at CL5)
///   − { ark links }          (required_k == 0 — disclosed-by-design, YPX-010)
///
/// Sorted ascending (BTreeSet order) ⇒ deterministic across all k signers.
/// Self-redeems (sender == receiver wallet) inherit nothing — the scar
/// already lives on the same chain; nothing crosses a wallet boundary.
pub fn compute_inherited_scar_txids(
    sender_chain: &FactChain,
    cheque_txid: &[u8; 32],
    is_self_redeem: bool,
) -> alloc::vec::Vec<[u8; 32]> {
    if is_self_redeem {
        return alloc::vec::Vec::new();
    }
    let mut set: alloc::collections::BTreeSet<[u8; 32]> = alloc::collections::BTreeSet::new();
    for link in &sender_chain.links {
        if link.required_k == 0 {
            continue; // Ark provenance — priced by Confidence Index, not consent
        }
        let own_resolved = link.nabla_confirmation.is_some()
            || link.burn_proof.is_some()
            || link.recall_proof.is_some();
        if !own_resolved && !crate::crypto::ct_eq(&link.tx_id, cheque_txid) {
            set.insert(link.tx_id);
        }
        // Transitive taint: the sender's own unresolved inherited txids
        // propagate — taint survives any number of hops until the ORIGIN
        // txid resolves.
        for t in &link.inherited_scar_txids {
            if !link.inherited_scar_resolutions.iter().any(|r| &r.txid == t) {
                set.insert(*t);
            }
        }
    }
    set.into_iter().collect()
}

/// FACT chain Core uses during CL5 redeem (verify chain + FACT Dilithium anchor).
///
/// Ordering is normative — must stay in lockstep with `modes::execute_cl5` Step 4b:
/// 1. `ChequeBundle.fact_chain`
/// 2. First cheque's `sender_fact_chain`
/// 3. `PublicInputs.sender_fact_chain` (Lambda-resolved fallback)
///
/// Lambda, SDK mirrors, and host-side commitment recomputation MUST match this ordering.
pub fn redeem_fact_chain_ref<'a>(
    cheque_bundle: &'a ChequeBundle,
    inputs_sender_fact_chain: &'a Option<FactChain>,
) -> Option<&'a FactChain> {
    cheque_bundle
        .fact_chain
        .as_ref()
        .or_else(|| {
            cheque_bundle
                .cheques
                .first()
                .and_then(|c| c.sender_fact_chain.as_ref())
        })
        .or(inputs_sender_fact_chain.as_ref())
}

/// `sender_anchor` bytes for redeem FACT commitments (chain tip or checkpoint final id).
pub fn redeem_fact_sender_anchor(
    cheque_bundle: &ChequeBundle,
    inputs_sender_fact_chain: &Option<FactChain>,
) -> Option<[u8; 32]> {
    redeem_fact_chain_ref(cheque_bundle, inputs_sender_fact_chain).and_then(|fc| {
        fc.links
            .last()
            .map(|l| l.new_state_id)
            .or_else(|| fc.checkpoint.as_ref().map(|cp| cp.final_state_id))
    })
}

/// Sign a FACT commitment with Dilithium (ML-DSA-65).
///
/// Computes `compute_fact_commitment(tx_id, prev_sid, new_sid, amount, sender_anchor, false, &[])`
/// and signs it. Used by Lambda to sign FACT natively on host (not inside
/// RISC-V guest where getrandom panics).
pub fn sign_fact_commitment(
    dilithium_sk: &[u8],
    tx_id: &[u8; 32],
    previous_state_id: &[u8; 32],
    new_state_id: &[u8; 32],
    amount: u64,
    sender_anchor: Option<&[u8; 32]>,
    is_dev_class: bool,
    inherited_scar_txids: &[[u8; 32]],
) -> Result<Vec<u8>, crate::types::ValidationError> {
    let commitment = compute_fact_commitment(
        tx_id, previous_state_id, new_state_id, amount, sender_anchor, is_dev_class,
        inherited_scar_txids,
    );
    crate::crypto::sign_dilithium(dilithium_sk, &commitment)
        .map_err(|_| crate::types::ValidationError::FactInvalidSignature)
}

/// YPX-016: Verify a cached witness fact_signature.
///
/// Used by the witness response cache to confirm Core previously endorsed
/// a specific state transition. Computes the FACT commitment from the TX
/// details and verifies the Dilithium signature against it.
///
/// Returns Ok(()) if the signature is valid (Core previously signed this),
/// Err if invalid (tampered or forged).
pub fn verify_cached_fact_signature(
    dilithium_pk: &[u8],
    tx_id: &[u8; 32],
    consumed_state_id: &[u8; 32],  // previous_state_id in FACT terms
    produced_state_id: &[u8; 32],  // new_state_id in FACT terms
    amount: u64,
    sender_anchor: Option<&[u8; 32]>,
    is_dev_class: bool,
    inherited_scar_txids: &[[u8; 32]],
    fact_signature: &[u8],
) -> Result<(), crate::types::ValidationError> {
    let commitment = compute_fact_commitment(
        tx_id, consumed_state_id, produced_state_id, amount, sender_anchor, is_dev_class,
        inherited_scar_txids,
    );
    crate::crypto::verify_dilithium(dilithium_pk, &commitment, fact_signature)
        .map_err(|_| crate::types::ValidationError::FactInvalidSignature)
}

/// Build a verified FactLink from k witness signatures.
///
/// Core verifies each Dilithium signature against the FACT commitment,
/// deduplicates by validator_id, extracts VBC genesis anchors.
/// Returns the assembled FactLink. This is Core's sole authority —
/// Lambda MUST NOT build FactLinks directly.
///
/// # Arguments
/// * `txid` — transaction ID (BLAKE3)
/// * `previous_state_id` — sender's state before this TX
/// * `new_state_id` — sender's state after this TX (produced_state_id)
/// * `amount` — transfer amount
/// * `required_k` — how many witnesses are required for full commit
/// * `witness_sigs` — collected WitnessSigs with fact_signature + VBC bundle
/// * `receiver_contact` — for scar healing propagation
/// * `burn_target_tx_id` — if burn TX, annotate target link with BurnProof
/// * `sender_anchor` — Some(sender_chain_tip) for redeem links, None otherwise.
///   Bound into the FACT commitment.
/// * `existing_chain` — existing FACT chain to append to
#[allow(clippy::too_many_arguments)]
pub fn build_fact_link(
    txid: &[u8; 32],
    previous_state_id: &[u8; 32],
    new_state_id: &[u8; 32],
    amount: u64,
    required_k: u8,
    witness_sigs: &[crate::types::WitnessSig],
    receiver_contact: Option<crate::types::ReceiverContact>,
    burn_target_tx_id: Option<[u8; 32]>,
    sender_anchor: Option<[u8; 32]>,
    is_dev_class: bool,
    // YPX-001 §1.5.1a: inherited taint for a CROSS-WALLET redeem link —
    // produced ONLY by `compute_inherited_scar_txids` (one builder).
    // Empty for send / heal / burn / self-redeem links.
    inherited_scar_txids: alloc::vec::Vec<[u8; 32]>,
    existing_chain: Option<&crate::types::FactChain>,
    // YPX-022 RECALL: when this is the recall self-send, `recall_target_tx_id` is the
    // failed send's txid and `recall_proof` is its Nabla-signed RecallAttestation. Core
    // attaches the proof to that failed link in the output chain, resolving its scar
    // (mirrors the burn_target_tx_id annotation below). Both None for non-recall TXs.
    recall_target_tx_id: Option<[u8; 32]>,
    recall_proof: Option<crate::types::RecallAttestation>,
) -> Result<crate::types::FactChain, crate::types::ValidationError> {
    use crate::types::{FactLink, FactWitness, FactChain, BurnProof};

    // Tier 1 silent-corruption closure at the SOURCE (2026-06-08, uj
    // wallet repro at ~/AXIOM_DEV/TTTTTT-normal.zip). Pre-this-change
    // `build_fact_link` stamped `previous_state_id` from the
    // caller-supplied param without checking it equalled the existing
    // chain's tip.new_state_id. A Lambda caller whose client supplied
    // a stale `previous_state_id` (the SDK's wallet.state_id drifted
    // out of sync with chain.tip.new_state_id — see CLAUDE.md §15 +
    // sdk/core/src/wallet.rs::commit_protocol_transition) would have
    // Core compose a structurally-broken chain, k validators would
    // sign it (the per-link commitment is computed from the link's
    // own bytes, which check out), and the broken chain would persist
    // to disk. The next outbound send would fail at
    // verify_fact_chain's read-side continuity check, but by then
    // the wallet is already structurally locked.
    //
    // The read-side check (verify_fact_chain at line ~312) catches
    // a chain a caller HANDS Core. This check catches a chain Core
    // is about to PRODUCE. Same error code (FactChainBreak), same
    // failure mode, complementary placement: Core no longer trusts
    // its caller's `previous_state_id` blindly when an existing chain
    // can witness the truth.
    //
    // Sticky-class invariant lives in the same `if let` block — both
    // are "if there's an existing chain, the new link MUST be
    // consistent with its tip" checks, both reject BEFORE any
    // Dilithium signing.
    if let Some(chain) = existing_chain {
        if let Some(tip) = chain.links.last() {
            if !crate::crypto::ct_eq(previous_state_id, &tip.new_state_id) {
                return Err(crate::types::ValidationError::FactChainBreak);
            }
            if tip.is_dev_class != is_dev_class {
                return Err(crate::types::ValidationError::DomainMismatch);
            }
        }
    }

    let commitment = compute_fact_commitment(
        txid, previous_state_id, new_state_id, amount, sender_anchor.as_ref(), is_dev_class,
        &inherited_scar_txids,
    );

    // Verify each Dilithium fact_signature against the commitment.
    // Only include witnesses with valid signatures for THIS TX.
    let mut fact_witnesses = alloc::vec::Vec::new();
    let mut seen_validators = alloc::collections::BTreeSet::new();

    for sig in witness_sigs {
        if let Some(ref fact_sig) = sig.fact_signature {
            let dilithium_pk = sig.vbc_bundle.as_ref()
                .map(|vbc| vbc.target_vbc.subject_pubkey_dilithium.clone())
                .unwrap_or_default();

            if dilithium_pk.is_empty() {
                continue;
            }

            let is_valid = crate::verify::verify_dilithium(
                &dilithium_pk, &commitment, fact_sig,
            ).is_ok();

            if is_valid && seen_validators.insert(sig.validator_id) {
                let vbc_genesis_anchor = sig.vbc_bundle.as_ref().map(|bundle| {
                    let mut anchor = alloc::vec::Vec::new();
                    for issuer_pk in &bundle.target_vbc.issuer_set {
                        if issuer_pk.len() >= 32 {
                            let mut pk = [0u8; 32];
                            pk.copy_from_slice(&issuer_pk[..32]);
                            anchor.push(pk);
                        }
                    }
                    for supporting in &bundle.supporting_vbcs {
                        for issuer_pk in &supporting.issuer_set {
                            if issuer_pk.len() >= 32 {
                                let mut pk = [0u8; 32];
                                pk.copy_from_slice(&issuer_pk[..32]);
                                anchor.push(pk);
                            }
                        }
                    }
                    anchor
                });
                fact_witnesses.push(FactWitness {
                    validator_id: sig.validator_id,
                    validator_pk: dilithium_pk,
                    signature: fact_sig.clone(),
                    vbc_genesis_anchor,
                });
            }
        }
    }

    if fact_witnesses.len() < 3 {
        return Err(crate::types::ValidationError::FactInsufficientWitnesses);
    }

    let burn_witnesses = if burn_target_tx_id.is_some() {
        Some(fact_witnesses.clone())
    } else {
        None
    };

    let link = FactLink {
        tx_id: *txid,
        previous_state_id: *previous_state_id,
        new_state_id: *new_state_id,
        amount,
        required_k,
        tick: 0,
        witnesses: fact_witnesses,
        nabla_confirmation: None,
        receiver_contact,
        burn_proof: None,
        sender_anchor,
        is_dev_class,
        recall_proof: None,
        inherited_scar_txids,
        inherited_scar_resolutions: alloc::vec::Vec::new(),
    };

    let mut chain = existing_chain.cloned().unwrap_or_else(FactChain::new);
    chain.links.push(link);

    // Annotate burn target if this is a burn TX
    if let Some(burn_target) = burn_target_tx_id {
        let burn_tx_id = *txid;
        if let Some(target_link) = chain.links.iter_mut().find(|l| l.tx_id == burn_target) {
            target_link.burn_proof = Some(BurnProof {
                burn_tx_id,
                validator_sigs: burn_witnesses.unwrap_or_default(),
            });
        }
    }

    // YPX-022 RECALL: attach the recall_proof to the failed link so its scar is RESOLVED
    // (verify_fact_chain_inner treats a link with a valid recall_proof as non-scarred).
    // Same shape as the burn annotation. The attestation is Nabla-signed + txid-bound, so
    // it can only resolve the link whose tx_id it actually recalled.
    if let (Some(recall_target), Some(proof)) = (recall_target_tx_id, recall_proof) {
        if let Some(target_link) = chain.links.iter_mut().find(|l| ct_eq(&l.tx_id, &recall_target)) {
            target_link.recall_proof = Some(proof);
        }
    }

    Ok(chain)
}

/// Compute FACT checkpoint commitment for signing.
/// BLAKE3("AXIOM_FACT_CHECKPOINT" || root_hash || compressed_count || final_state_id || genesis_state_id || genesis_fact_hash)
///
/// genesis_fact_hash (YPX-011) is included so the checkpoint cryptographically
/// binds to the genesis headlines. It propagates through every recompression.
pub fn compute_checkpoint_commitment(checkpoint: &FactCheckpoint) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_FACT_CHECKPOINT");
    hasher.update(&checkpoint.root_hash);
    hasher.update(&checkpoint.compressed_count.to_le_bytes());
    hasher.update(&checkpoint.final_state_id);
    hasher.update(&checkpoint.genesis_state_id);
    // SEC-11: bind total_amount into the commitment so the k-validator
    // Dilithium sigs attest it. Previously absent — verify_checkpoint (which
    // only checks sigs over this commitment) accepted ANY attacker-chosen
    // total_amount on a "signed" struct. Now a tampered total_amount breaks
    // every checkpoint signature.
    hasher.update(&checkpoint.total_amount.to_le_bytes());
    hasher.update(&checkpoint.genesis_fact_hash);
    *hasher.finalize().as_bytes()
}

/// Compute root hash for checkpoint compression.
/// BLAKE3(link_1_commitment || link_2_commitment || ... || link_n_commitment)
///
/// Runs inside AVM (DMAP-attested). The root hash summarizes all compressed FACT links.
pub fn compute_checkpoint_root(links: &[FactLink]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_FACT_ROOT");
    for link in links {
        let link_commitment = compute_fact_commitment(
            &link.tx_id,
            &link.previous_state_id,
            &link.new_state_id,
            link.amount,
            link.sender_anchor.as_ref(),
            link.is_dev_class,
            &link.inherited_scar_txids,
        );
        hasher.update(&link_commitment);
    }
    *hasher.finalize().as_bytes()
}

/// Compute the commitment that validators sign when healing a scar.
/// BLAKE3("AXIOM_SCAR_HEAL" || original_tx_id || nabla_node_id || root_hash)
// SECURITY-SCAR (Scar Heal Verification):
// Healing a scar requires k=3 Dilithium signatures over this commitment.
// The commitment binds the original TX, the Nabla node that confirmed it,
// and the Merkle root proving the registration exists in Nabla's state tree.
// Ref: YPX-001 §1.5.6, CL9 scar heal signing path.
///
/// Per YPX-001 §1.5.6, this is the payload k=3 validators sign to attest
/// that a Nabla confirmation is genuine.
pub fn compute_scar_heal_commitment(
    original_tx_id: &[u8; 32],
    nabla_node_id: &[u8; 32],
    root_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_SCAR_HEAL");
    hasher.update(original_tx_id);
    hasher.update(nabla_node_id);
    hasher.update(root_hash);
    *hasher.finalize().as_bytes()
}

/// Verify a ScarRecoveryProof: k≥3 Dilithium sigs over the heal commitment.
/// Checks: sig count ≥ 3, no duplicate validators, all sigs valid.
pub fn verify_scar_recovery_proof(
    proof: &crate::types::ScarRecoveryProof,
) -> Result<(), ValidationError> {
    // 1. Need k=3 witnesses minimum
    if proof.healing_witnesses.len() < MIN_FACT_WITNESSES {
        return Err(ValidationError::FactInsufficientWitnesses);
    }
    // 2. No duplicate validator IDs
    let mut seen = alloc::collections::BTreeSet::new();
    for w in &proof.healing_witnesses {
        if !seen.insert(w.validator_id) {
            return Err(ValidationError::FactDuplicateWitness);
        }
    }
    // 3. Compute commitment, verify each signature
    let commitment = compute_scar_heal_commitment(
        &proof.original_tx_id,
        &proof.nabla_confirmation.nabla_node_id,
        &proof.nabla_confirmation.root_hash,
    );
    for w in &proof.healing_witnesses {
        if crate::crypto::verify_dilithium(
            &w.validator_pk,
            &commitment,
            &w.signature,
        ).is_err() {
            return Err(ValidationError::FactInvalidSignature);
        }
    }
    Ok(())
}

/// Sign a scar heal commitment with a validator's Dilithium key.
///
/// This is the operational signing path for scar healing (YPX-001 §1.5.6).
/// Validators call this to produce their attestation that a Nabla confirmation
/// is genuine. The resulting signature goes into a ScarRecoveryProof.
pub fn sign_scar_heal_commitment(
    dilithium_sk: &[u8],
    original_tx_id: &[u8; 32],
    nabla_node_id: &[u8; 32],
    root_hash: &[u8; 32],
) -> Result<Vec<u8>, ValidationError> {
    let commitment = compute_scar_heal_commitment(original_tx_id, nabla_node_id, root_hash);
    crate::crypto::sign_dilithium(dilithium_sk, &commitment)
        .map_err(|_| ValidationError::FactInvalidSignature)
}

/// Compress a FACT chain if it exceeds the soft maximum depth.
///
/// Core owns ALL compression logic. Lambda/Gateway MUST NOT compress directly.
/// Compression preserves provenance: older links are hashed into a checkpoint
/// with a Dilithium signature from the compressing validator.
///
/// - Accepts chains up to MAX_FACT_DEPTH (8) links
/// - Compresses when > MAX_FACT_DEPTH, keeping last FACT_KEEP (5) links
/// - Returns the (possibly compressed) chain
///
/// Arguments:
/// - chain: The FACT chain to potentially compress
/// - validators: Slice of (validator_id, dilithium_pk, dilithium_sk) for k=3 checkpoint signing
pub fn compress_fact_chain(
    mut chain: FactChain,
    validators: &[([u8; 32], &[u8], &[u8])],
) -> Result<FactChain, ValidationError> {
    if validators.is_empty() {
        return Err(ValidationError::FactInsufficientWitnesses);
    }
    // Scar-aware compression (YPX-001 §1.5): only compress the longest
    // resolved prefix. Links are resolved if they have nabla_confirmation
    // or burn_proof. Unresolved scarred links and everything after them
    // stay uncompressed to prevent wash-out attacks.
    //
    // v2.11.11: Pre-Nabla all_unresolved fallback REMOVED. Nabla is live
    // since v2.11.10 — resolved_prefix logic handles all cases. The old
    // fallback caused V3 scar timing failures: chains healed between V2
    // and V3 would switch compression strategy mid-transaction, producing
    // checkpoint mismatches that the finalizer rejected.
    let resolved_prefix = chain.links.iter()
        .take_while(|l| l.is_resolved())
        .count();
    let compressible = resolved_prefix;
    if compressible <= FACT_KEEP {
        return Ok(chain); // Not enough compressible links
    }

    let split_at = compressible - FACT_KEEP;
    let to_compress: Vec<FactLink> = chain.links.drain(..split_at).collect();
    
    // Compute root hash over compressed links
    let root_hash = compute_checkpoint_root(&to_compress);
    
    // Preserve genesis state from existing checkpoint or first compressed link.
    // SEC-11: the provenance anchors must never silently default to zero — a
    // zero genesis/final state id on a checkpoint is a broken audit trail, not
    // a valid value. These are unreachable here (the `compressible > FACT_KEEP`
    // guard guarantees to_compress is non-empty), but make the invariant
    // explicit rather than papering it with a zero default.
    let genesis_state_id = if let Some(ref existing_cp) = chain.checkpoint {
        existing_cp.genesis_state_id
    } else {
        to_compress.first()
            .map(|l| l.previous_state_id)
            .ok_or(ValidationError::FactChainEmpty)?
    };
    let final_state_id = to_compress.last()
        .map(|l| l.new_state_id)
        .ok_or(ValidationError::FactChainEmpty)?;
    // SEC-11: checked_add — a bare `+`/`sum` wraps silently in release and
    // panics (DoS) in debug. total_amount is now commitment-bound, so a wrap
    // would also produce a signed-but-wrong audit value.
    let links_sum: u64 = to_compress.iter().try_fold(0u64, |acc, l| {
        acc.checked_add(l.amount).ok_or(ValidationError::FactAmountOverflow)
    })?;
    let total_amount: u64 = links_sum
        .checked_add(chain.checkpoint.as_ref().map(|cp| cp.total_amount).unwrap_or(0))
        .ok_or(ValidationError::FactAmountOverflow)?;
    let compressed_count = (to_compress.len() as u64)
        .checked_add(chain.checkpoint.as_ref().map(|cp| cp.compressed_count).unwrap_or(0))
        .ok_or(ValidationError::FactAmountOverflow)?;
    
    // Propagate genesis_fact_hash from existing checkpoint, or compute fresh (YPX-011)
    let genesis_fact_hash = chain.checkpoint.as_ref()
        .filter(|cp| cp.genesis_fact_hash != [0u8; 32])
        .map(|cp| cp.genesis_fact_hash)
        .unwrap_or_else(|| crate::genesis_integrity::compute_genesis_fact_hash(
            &crate::genesis_integrity::build_genesis_fact(1)
        ));

    // Build checkpoint stub for commitment computation
    let checkpoint_stub = FactCheckpoint {
        root_hash,
        compressed_count,
        final_state_id,
        genesis_state_id,
        total_amount,
        genesis_fact_hash,
        validator_sigs: vec![],
        pending_links: 0, // not in commitment
    };
    let cp_commitment = compute_checkpoint_commitment(&checkpoint_stub);

    // Sign with k=3 Dilithium validators (Core does all crypto)
    let mut validator_sigs = Vec::with_capacity(validators.len());
    for &(vid, pk, sk) in validators {
        let sig = crate::crypto::sign_dilithium(sk, &cp_commitment)?;
        validator_sigs.push(FactWitness {
            validator_id: vid,
            validator_pk: pk.to_vec(),
            signature: sig,
            vbc_genesis_anchor: None,
        });
    }

    chain.checkpoint = Some(FactCheckpoint {
        root_hash,
        compressed_count,
        final_state_id,
        genesis_state_id,
        total_amount,
        genesis_fact_hash,
        validator_sigs,
        // compress_fact_chain DRAINS the links immediately (legacy immediate
        // path), so its checkpoint is already finalized — no retained links.
        pending_links: 0,
    });

    Ok(chain)
}

/// SEC-07: compute the would-be checkpoint STUB (validator_sigs empty) for a
/// chain, WITHOUT mutating it — or None if the resolved prefix is too short to
/// compress. The fields mirror `compress_fact_chain` EXACTLY (same `to_compress`
/// slice, same root_hash / genesis_state_id / final_state_id / total_amount /
/// compressed_count / genesis_fact_hash), so the commitment a witness signs at
/// endorsement time is byte-identical to the checkpoint the finalizer's
/// `compress_fact_chain` ultimately produces.
///
/// Determinism vs. the finalizer: the finalizer compresses
/// `sender_fact_chain + new_unresolved_link`; the witnesses endorse over
/// `sender_fact_chain`. The new link sits at the tail and is unresolved, so it
/// never enters `to_compress` (which is the leading resolved prefix beyond
/// FACT_KEEP) — both sides compress the identical link set. The
/// `test_sec07_pending_stub_matches_compress` drift-guard pins this equality.
pub fn compute_pending_checkpoint_stub(chain: &FactChain) -> Result<Option<FactCheckpoint>, ValidationError> {
    let resolved_prefix = chain.links.iter()
        .take_while(|l| l.is_resolved())
        .count();
    if resolved_prefix <= FACT_KEEP {
        return Ok(None); // Not enough compressible links — no checkpoint this round.
    }
    let split_at = resolved_prefix - FACT_KEEP;
    let to_compress = &chain.links[..split_at];

    let root_hash = compute_checkpoint_root(to_compress);
    let genesis_state_id = if let Some(ref existing_cp) = chain.checkpoint {
        existing_cp.genesis_state_id
    } else {
        to_compress.first()
            .map(|l| l.previous_state_id)
            .ok_or(ValidationError::FactChainEmpty)?
    };
    let final_state_id = to_compress.last()
        .map(|l| l.new_state_id)
        .ok_or(ValidationError::FactChainEmpty)?;
    let links_sum: u64 = to_compress.iter().try_fold(0u64, |acc, l| {
        acc.checked_add(l.amount).ok_or(ValidationError::FactAmountOverflow)
    })?;
    let total_amount: u64 = links_sum
        .checked_add(chain.checkpoint.as_ref().map(|cp| cp.total_amount).unwrap_or(0))
        .ok_or(ValidationError::FactAmountOverflow)?;
    let compressed_count = (to_compress.len() as u64)
        .checked_add(chain.checkpoint.as_ref().map(|cp| cp.compressed_count).unwrap_or(0))
        .ok_or(ValidationError::FactAmountOverflow)?;
    let genesis_fact_hash = chain.checkpoint.as_ref()
        .filter(|cp| cp.genesis_fact_hash != [0u8; 32])
        .map(|cp| cp.genesis_fact_hash)
        .unwrap_or_else(|| crate::genesis_integrity::compute_genesis_fact_hash(
            &crate::genesis_integrity::build_genesis_fact(1)
        ));

    Ok(Some(FactCheckpoint {
        root_hash,
        compressed_count,
        final_state_id,
        genesis_state_id,
        total_amount,
        genesis_fact_hash,
        validator_sigs: alloc::vec::Vec::new(),
        // Stub for commitment computation only; the caller (advance_fact_checkpoint)
        // sets the real pending_links when it adopts this as a provisional checkpoint.
        pending_links: 0,
    }))
}


/// SEC-07 travel-model checkpoint advance. Called by EACH validator that processes
/// a chain, with its own (validator_id, dilithium_pk, dilithium_sk). One of three
/// things happens (or nothing):
///
/// - **PROPOSE** — no open proposal and the chain is `>= FACT_PROPOSE_TRIGGER` deep:
///   build a checkpoint over the resolved prefix beyond `FACT_KEEP`, sign it once,
///   attach it, and **retain** the covered links (`pending_links = M`). A FINALIZED
///   checkpoint already on the chain is propagated into the new proposal (re-open).
/// - **CO-SIGN** — an open proposal exists and this validator hasn't signed it:
///   re-verify the `M` retained links against `root_hash`, then append this
///   validator's distinct signature.
/// - **FINALIZE** — the proposal has reached `CHECKPOINT_SIG_THRESHOLD` distinct
///   signatures: delete the `M` covered links (`pending_links -> 0`). The committed
///   bytes (root_hash, sigs) are unchanged by this.
///
/// Idempotent per validator (dedup by `validator_id`). Never deletes links below the
/// signature threshold, so the real history is always present while a proposal
/// accumulates — the chain stays fully verifiable and nothing wedges. The client
/// wallet's Core must NOT call this (it has no validator identity); only VBC-backed
/// validators advance a checkpoint. See `docs/security_review_20260612/SEC-07_RESOLUTION.md`.
pub fn advance_fact_checkpoint(
    chain: &mut FactChain,
    validator_id: [u8; 32],
    dilithium_pk: &[u8],
    dilithium_sk: &[u8],
    oods_view_healthy: bool,
) -> Result<(), ValidationError> {
    // YPX-021 §8.2 — the wash-out gate. When the wallet's latest receipt
    // carries `oods_flag.healthy == false` (its previous step happened under
    // an eclipsed network view), the chain must NOT finalize clean: no new
    // compression proposal, no co-sign, no finalize-drain. Links stay
    // retained, exactly like the scarred case (§8.1 step 4: "stop
    // compressing — no wash-out"). The caller (the TX finalizer) passes
    // `receipt.oods_flag.map_or(true, |f| f.healthy)` — a flagless receipt
    // (heal / genesis paths, Phase 1) does not gate. This is an OODS-eclipse
    // liveness limit, never a fund rejection (§8: search, don't die).
    if !oods_view_healthy {
        return Ok(());
    }
    let is_provisional = chain.checkpoint.as_ref().map_or(false, |cp| cp.pending_links > 0);
    if is_provisional {
        let cp = chain.checkpoint.as_mut().unwrap();
        let m = cp.pending_links as usize;
        // Defensive: the covered links must still be present and hash to root_hash.
        if m == 0 || m > chain.links.len() {
            return Ok(());
        }
        let covered_root = compute_checkpoint_root(&chain.links[..m]);
        if !ct_eq(&covered_root, &cp.root_hash) {
            return Ok(()); // retained links don't match the proposal — refuse to sign
        }
        // CO-SIGN (dedup by validator_id — a validator never signs the same proposal twice).
        let already = cp.validator_sigs.iter().any(|s| ct_eq(&s.validator_id, &validator_id));
        if !already {
            let commitment = compute_checkpoint_commitment(cp);
            if let Ok(sig) = crate::crypto::sign_dilithium(dilithium_sk, &commitment) {
                cp.validator_sigs.push(FactWitness {
                    validator_id,
                    validator_pk: dilithium_pk.to_vec(),
                    signature: sig,
                    vbc_genesis_anchor: None,
                });
            }
        }
        // FINALIZE once CHECKPOINT_SIG_THRESHOLD distinct validators have
        // re-verified + signed. Only the TX finalizer reaches this drain.
        if cp.validator_sigs.len() >= CHECKPOINT_SIG_THRESHOLD {
            chain.links.drain(..m);
            chain.checkpoint.as_mut().unwrap().pending_links = 0;
        }
        return Ok(());
    }

    // PROPOSE (or re-open over a finalized checkpoint). Trigger on TOTAL depth
    // (consensus-agreed — every link is signed); only the RESOLVED prefix beyond
    // FACT_KEEP is compressible (scar-safe). compute_pending_checkpoint_stub
    // propagates any existing finalized checkpoint's anchors into the new stub.
    if chain.links.len() >= FACT_PROPOSE_TRIGGER {
        let resolved_prefix = chain.links.iter().take_while(|l| l.is_resolved()).count();
        if resolved_prefix > FACT_KEEP {
            if let Some(mut stub) = compute_pending_checkpoint_stub(chain)? {
                let split_at = resolved_prefix - FACT_KEEP;
                let commitment = compute_checkpoint_commitment(&stub);
                let sig = crate::crypto::sign_dilithium(dilithium_sk, &commitment)
                    .map_err(|_| ValidationError::FactInvalidSignature)?;
                stub.validator_sigs.push(FactWitness {
                    validator_id,
                    validator_pk: dilithium_pk.to_vec(),
                    signature: sig,
                    vbc_genesis_anchor: None,
                });
                stub.pending_links = split_at as u64;
                chain.checkpoint = Some(stub);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ChequeBundle;
    use fips204::ml_dsa_65;
    use fips204::traits::SerDes;

    /// Dilithium keypair (pk bytes, sk bytes) for FACT test signing.
    struct DilithiumTestKey {
        pk: Vec<u8>,
        sk: Vec<u8>,
    }

    fn make_test_link(
        tx_id: [u8; 32],
        prev_state: [u8; 32],
        new_state: [u8; 32],
        amount: u64,
        keys: &[DilithiumTestKey],
    ) -> FactLink {
        let commitment =
            compute_fact_commitment(&tx_id, &prev_state, &new_state, amount, None, false, &[]);
        let mut witnesses = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let sig = crate::crypto::sign_dilithium(&key.sk, &commitment)
                .expect("test sign_dilithium");
            let mut vid = [0u8; 32];
            vid[0] = i as u8; // Unique validator_id per witness
            witnesses.push(FactWitness {
                validator_id: vid,
                validator_pk: key.pk.clone(),
                signature: sig,
                vbc_genesis_anchor: None,
            });
        }
        FactLink {
            tx_id,
            previous_state_id: prev_state,
            new_state_id: new_state,
            amount,
            // required_k > witnesses.len() so this is a real scar (partial commit)
            // when nabla_confirmation is None. make_healed_link overrides with confirmation.
            required_k: (keys.len() + 1) as u8,
            tick: 0,
            witnesses,
            nabla_confirmation: None,
            receiver_contact: None,
            burn_proof: None,
            sender_anchor: None,
            is_dev_class: false,
            recall_proof: None,
            inherited_scar_txids: Vec::new(),
            inherited_scar_resolutions: Vec::new(),
        }
    }

    // SEC-07: 5 keys so make_validators() yields a checkpoint with
    // CHECKPOINT_SIG_THRESHOLD (5) distinct sigs — a finalized checkpoint that
    // passes verify_checkpoint. Link witnesses use the same keys (>= MIN_FACT_WITNESSES).
    fn test_keys() -> Vec<DilithiumTestKey> {
        (0..5).map(|_| {
            let (pk_obj, sk_obj) = ml_dsa_65::try_keygen()
                .expect("Dilithium keygen failed");
            DilithiumTestKey {
                pk: pk_obj.into_bytes().to_vec(),
                sk: sk_obj.into_bytes().to_vec(),
            }
        }).collect()
    }
    
    #[test]
    fn test_empty_chain_valid() {
        let chain = FactChain::new();
        let result = verify_fact_chain(&chain);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }
    
    #[test]
    fn test_single_link_chain() {
        let keys = test_keys();
        let link = make_test_link([1u8; 32], [0u8; 32], [2u8; 32], 1000, &keys);
        let chain = FactChain { checkpoint: None, links: vec![link] };
        let result = verify_fact_chain(&chain);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1); // 1 scar (no nabla)
    }
    
    #[test]
    fn test_chain_continuity() {
        let keys = test_keys();
        let link1 = make_test_link([1u8; 32], [0u8; 32], [2u8; 32], 1000, &keys);
        let link2 = make_test_link([3u8; 32], [2u8; 32], [4u8; 32], 500, &keys);
        let chain = FactChain { checkpoint: None, links: vec![link1, link2] };
        let result = verify_fact_chain(&chain);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_chain_break_detected() {
        let keys = test_keys();
        let link1 = make_test_link([1u8; 32], [0u8; 32], [2u8; 32], 1000, &keys);
        let link2 = make_test_link([3u8; 32], [99u8; 32], [4u8; 32], 500, &keys); // BREAK
        let chain = FactChain { checkpoint: None, links: vec![link1, link2] };
        let result = verify_fact_chain(&chain);
        assert!(result.is_err());
    }

    // ── check_fact_chain_continuity (2026-06-08, uj-class closure) ──
    //
    // Structural-only continuity check; no Dilithium witness verify, no
    // depth enforcement. Used by `set_fact_chain` / `commit_protocol_transition`
    // in the SDK so a broken-chain set is REFUSED at storage time instead
    // of silently persisted (Tier 1 fund-loss class — the uj wallet
    // repro at `~/AXIOM_DEV/TTTTTT-normal.zip`).

    /// Local minimal-link helper: build a FactLink with EMPTY witnesses,
    /// since check_fact_chain_continuity intentionally does NOT touch
    /// the Dilithium pass. Faster than `make_test_link` for the
    /// structural-only tests below.
    fn make_link_no_witnesses(
        tx_id: [u8; 32],
        prev_state: [u8; 32],
        new_state: [u8; 32],
        is_dev_class: bool,
    ) -> FactLink {
        FactLink {
            tx_id,
            previous_state_id: prev_state,
            new_state_id: new_state,
            amount: 1000,
            required_k: 3,
            tick: 0,
            witnesses: Vec::new(),
            nabla_confirmation: None,
            receiver_contact: None,
            burn_proof: None,
            sender_anchor: None,
            is_dev_class,
            recall_proof: None,
            inherited_scar_txids: Vec::new(),
            inherited_scar_resolutions: Vec::new(),
        }
    }

    #[test]
    fn check_fact_chain_continuity_empty_chain_ok() {
        let chain = FactChain::new();
        assert!(check_fact_chain_continuity(&chain).is_ok());
    }

    #[test]
    fn check_fact_chain_continuity_single_link_ok() {
        let chain = FactChain {
            checkpoint: None,
            links: vec![make_link_no_witnesses([1u8; 32], [0u8; 32], [9u8; 32], false)],
        };
        assert!(check_fact_chain_continuity(&chain).is_ok());
    }

    #[test]
    fn check_fact_chain_continuity_continuous_chain_ok() {
        let chain = FactChain {
            checkpoint: None,
            links: vec![
                make_link_no_witnesses([1u8; 32], [0u8; 32], [2u8; 32], false),
                make_link_no_witnesses([3u8; 32], [2u8; 32], [4u8; 32], false),
                make_link_no_witnesses([5u8; 32], [4u8; 32], [6u8; 32], false),
            ],
        };
        assert!(check_fact_chain_continuity(&chain).is_ok());
    }

    #[test]
    fn check_fact_chain_continuity_rejects_break() {
        // Exact uj wallet shape: link[0].new = [9; 32]; link[1].previous = [42; 32] (≠).
        let chain = FactChain {
            checkpoint: None,
            links: vec![
                make_link_no_witnesses([1u8; 32], [0u8; 32], [9u8; 32], false),
                make_link_no_witnesses([2u8; 32], [42u8; 32], [10u8; 32], false), // GAP
            ],
        };
        let err = check_fact_chain_continuity(&chain).unwrap_err();
        assert!(matches!(err, ValidationError::FactChainBreak), "got {:?}", err);
    }

    #[test]
    fn check_fact_chain_continuity_rejects_class_lock_violation() {
        // link[0] is public-class, link[1] tries to flip to dev-class on
        // a structurally continuous chain — caught as DomainMismatch.
        let chain = FactChain {
            checkpoint: None,
            links: vec![
                make_link_no_witnesses([1u8; 32], [0u8; 32], [2u8; 32], false),
                make_link_no_witnesses([3u8; 32], [2u8; 32], [4u8; 32], true),
            ],
        };
        let err = check_fact_chain_continuity(&chain).unwrap_err();
        assert!(matches!(err, ValidationError::DomainMismatch), "got {:?}", err);
    }

    #[test]
    fn check_fact_chain_continuity_no_dilithium_required() {
        // Regression: the whole point of the dedicated check is to NOT
        // require Dilithium witnesses. A 2-link continuous chain with
        // ZERO witnesses on either link MUST pass. (verify_fact_chain
        // would reject this with FactInsufficientWitnesses; we
        // explicitly do not.)
        let chain = FactChain {
            checkpoint: None,
            links: vec![
                make_link_no_witnesses([1u8; 32], [0u8; 32], [2u8; 32], false),
                make_link_no_witnesses([3u8; 32], [2u8; 32], [4u8; 32], false),
            ],
        };
        // verify_fact_chain rejects (insufficient witnesses)
        assert!(verify_fact_chain(&chain).is_err());
        // check_fact_chain_continuity accepts (structural-only)
        assert!(check_fact_chain_continuity(&chain).is_ok());
    }
    
    #[test]
    fn test_too_deep_rejected() {
        // SEC-07 travel model: depth is no longer a hard compression deadline.
        // A chain only fails at the generous anti-abuse FACT_HARD_CEILING (32),
        // not at the old MAX_FACT_DEPTH (8) — chains legitimately sit ~11-12 deep
        // while a checkpoint proposal accumulates its 5 signatures.
        let keys = test_keys();
        let make = |n: usize| {
            let mut links = Vec::new();
            for i in 0..n as u8 {
                let prev = [i; 32];
                let next = [i + 1; 32];
                let mut link = make_test_link([100 + i; 32], prev, next, 100, &keys);
                link.nabla_confirmation = Some(sign_nabla_confirmation(&prev, &next));
                links.push(link);
            }
            FactChain { checkpoint: None, links }
        };
        // A chain past the OLD limit (8) but under the ceiling now VERIFIES.
        assert!(verify_fact_chain(&make(MAX_FACT_DEPTH + 1)).is_ok(),
            "depth {} is fine under the travel model", MAX_FACT_DEPTH + 1);
        // Only past FACT_HARD_CEILING is it rejected.
        assert!(matches!(verify_fact_chain(&make(FACT_HARD_CEILING + 1)),
            Err(ValidationError::FactChainTooDeep)),
            "chain past the anti-abuse ceiling must be rejected");
    }
    
    #[test]
    fn test_scarred_chain_unlimited_depth() {
        // Scarred links (no nabla_confirmation) do NOT count toward MAX_FACT_DEPTH.
        // This prevents "wash-out" attacks: can't launder money by transacting
        // until scars fall off the chain.
        let keys = test_keys();
        let mut links = Vec::new();
        for i in 0..10 { // 10 scarred links — should be fine
            let prev = [i as u8; 32];
            let next = [(i + 1) as u8; 32];
            links.push(make_test_link([100 + i as u8; 32], prev, next, 100, &keys));
            // No nabla_confirmation = scarred
        }
        let chain = FactChain { checkpoint: None, links };
        let result = verify_fact_chain(&chain);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 10); // all 10 are scars
    }
    
    #[test]
    fn test_insufficient_witnesses_rejected() {
        let keys = test_keys();
        let mut link = make_test_link([1u8; 32], [0u8; 32], [2u8; 32], 1000, &keys);
        link.witnesses.truncate(2); // Only 2, need 3
        let chain = FactChain { checkpoint: None, links: vec![link] };
        let result = verify_fact_chain(&chain);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_bad_signature_rejected() {
        let keys = test_keys();
        let mut link = make_test_link([1u8; 32], [0u8; 32], [2u8; 32], 1000, &keys);
        link.witnesses[0].signature = vec![0u8; 64]; // corrupted
        let chain = FactChain { checkpoint: None, links: vec![link] };
        let result = verify_fact_chain(&chain);
        assert!(result.is_err());
    }
    
    /// Make a healed link (has nabla_confirmation)
    /// Ed25519 test keypair for Nabla confirmation signatures.
    fn nabla_test_key() -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pk = sk.verifying_key();
        (sk, pk)
    }

    /// Sign a real NablaConfirmation for test links.  V2 payload —
    /// includes committed_at_tick (default 0 for tests; production
    /// signs the writer's TARDIS tick at commit time).
    fn sign_nabla_confirmation(prev_state: &[u8; 32], new_state: &[u8; 32]) -> crate::types::NablaConfirmation {
        use ed25519_dalek::Signer;
        let (sk, pk) = nabla_test_key();
        let committed_at_tick: u64 = 0;
        let tx_hash = {
            let mut h = blake3::Hasher::new();
            h.update(b"AXIOM_TXHASH");
            h.update(prev_state);
            h.update(new_state);
            *h.finalize().as_bytes()
        };
        let mut h = blake3::Hasher::new();
        h.update(b"AXIOM_FACT_CONFIRM_V2");
        h.update(&tx_hash);
        h.update(new_state);
        h.update(&committed_at_tick.to_le_bytes());
        let payload = h.finalize();
        let sig = sk.sign(payload.as_bytes());
        crate::types::NablaConfirmation {
            nabla_node_id: pk.to_bytes(),
            nabla_signature: sig.to_bytes().to_vec(),
            root_hash: [0u8; 32],
            synced_to_tick: 0,
            committed_at_tick,
            ..Default::default()
        }
    }

    fn make_healed_link(
        tx_id: [u8; 32],
        prev_state: [u8; 32],
        new_state: [u8; 32],
        amount: u64,
        keys: &[DilithiumTestKey],
    ) -> FactLink {
        let mut link = make_test_link(tx_id, prev_state, new_state, amount, keys);
        link.nabla_confirmation = Some(sign_nabla_confirmation(&prev_state, &new_state));
        link
    }

    // ── verify_nabla_confirmation — single canonical authority ──────────

    #[test]
    fn verify_nabla_confirmation_accepts_binding_conf() {
        let prev = [0x10u8; 32];
        let new = [0x11u8; 32];
        let conf = sign_nabla_confirmation(&prev, &new);
        assert!(
            verify_nabla_confirmation(&prev, &new, &conf).is_ok(),
            "a conf signed over (prev,new) MUST verify against the same state-ids",
        );
    }

    #[test]
    fn verify_nabla_confirmation_rejects_wrong_state_ids() {
        // Conf is valid for (prev,new) but presented against a DIFFERENT
        // link's state-ids — the exact mis-attach the SDK gate must catch.
        let prev = [0x10u8; 32];
        let new = [0x11u8; 32];
        let conf = sign_nabla_confirmation(&prev, &new);

        let other_prev = [0x20u8; 32];
        let other_new = [0x21u8; 32];
        assert_eq!(
            verify_nabla_confirmation(&other_prev, &other_new, &conf),
            Err(ValidationError::FactInvalidSignature),
            "a conf bound to a different transition MUST be rejected",
        );
        // Also reject when only ONE of the two state-ids differs.
        assert_eq!(
            verify_nabla_confirmation(&prev, &other_new, &conf),
            Err(ValidationError::FactInvalidSignature),
        );
        assert_eq!(
            verify_nabla_confirmation(&other_prev, &new, &conf),
            Err(ValidationError::FactInvalidSignature),
        );
    }

    #[test]
    fn verify_nabla_confirmation_rejects_forged_stub() {
        let prev = [0x10u8; 32];
        let new = [0x11u8; 32];

        // Empty signature = forged stub.
        let mut empty_sig = sign_nabla_confirmation(&prev, &new);
        empty_sig.nabla_signature = Vec::new();
        assert_eq!(
            verify_nabla_confirmation(&prev, &new, &empty_sig),
            Err(ValidationError::FactInvalidSignature),
        );

        // Zero node_id = forged stub.
        let mut zero_id = sign_nabla_confirmation(&prev, &new);
        zero_id.nabla_node_id = [0u8; 32];
        assert_eq!(
            verify_nabla_confirmation(&prev, &new, &zero_id),
            Err(ValidationError::FactInvalidSignature),
        );
    }

    #[test]
    fn verify_fact_link_matches_extracted_fn_on_a_fixture() {
        // Behavior-preservation guard for the Change-1 extraction: a healed
        // link still passes verify_fact_link, and tampering the conf to a
        // wrong transition still fails it with FactInvalidSignature — i.e.
        // verify_fact_link's conf check IS verify_nabla_confirmation.
        let keys = test_keys();
        let good = make_healed_link([1u8; 32], [0x10; 32], [0x11; 32], 100, &keys);
        assert!(verify_fact_link(&good).is_ok());

        let mut tampered = good.clone();
        // Replace the conf with one bound to a different transition.
        tampered.nabla_confirmation = Some(sign_nabla_confirmation(&[0x99; 32], &[0x98; 32]));
        assert_eq!(
            verify_fact_link(&tampered),
            Err(ValidationError::FactInvalidSignature),
        );
    }

    #[test]
    fn nabla_confirmation_round_trips_and_emits_cbor_bytes() {
        // Change-2 guard: after the serde_bytes shims, NablaConfirmation
        // round-trips through ciborium AND emits its byte fields as CBOR
        // byte-strings (major type 2), not Array<Integer> (major type 4).
        let conf = sign_nabla_confirmation(&[0x10; 32], &[0x11; 32]);

        let mut buf = alloc::vec::Vec::new();
        ciborium::into_writer(&conf, &mut buf).expect("encode");
        let back: crate::types::NablaConfirmation =
            ciborium::from_reader(buf.as_slice()).expect("decode");

        assert_eq!(back.nabla_node_id, conf.nabla_node_id);
        assert_eq!(back.nabla_signature, conf.nabla_signature);
        assert_eq!(back.root_hash, conf.root_hash);
        assert_eq!(back.committed_at_tick, conf.committed_at_tick);

        // Walk the CBOR as a generic Value and assert the byte fields are
        // Value::Bytes, not Value::Array.
        let v: ciborium::Value = ciborium::from_reader(buf.as_slice()).expect("value decode");
        let map = v.as_map().expect("map");
        let field = |key: &str| -> &ciborium::Value {
            map.iter()
                .find(|(k, _)| k.as_text() == Some(key))
                .map(|(_, val)| val)
                .unwrap_or_else(|| panic!("missing field {}", key))
        };
        assert!(
            matches!(field("nabla_node_id"), ciborium::Value::Bytes(_)),
            "nabla_node_id MUST encode as CBOR Bytes",
        );
        assert!(
            matches!(field("nabla_signature"), ciborium::Value::Bytes(_)),
            "nabla_signature MUST encode as CBOR Bytes",
        );
        assert!(
            matches!(field("root_hash"), ciborium::Value::Bytes(_)),
            "root_hash MUST encode as CBOR Bytes",
        );
    }

    #[test]
    fn nabla_confirmation_decodes_legacy_array_encoding() {
        // The shims must still decode a conf an OLD binary serialized as
        // Array<Integer> (forgiving deserialize) so stored chains load.
        use ciborium::Value;
        let conf = sign_nabla_confirmation(&[0x10; 32], &[0x11; 32]);
        let int_arr = |b: &[u8]| -> Value {
            Value::Array(b.iter().map(|&x| Value::Integer(x.into())).collect())
        };
        let legacy = Value::Map(alloc::vec![
            (Value::Text("nabla_node_id".into()), int_arr(&conf.nabla_node_id)),
            (Value::Text("nabla_signature".into()), int_arr(&conf.nabla_signature)),
            (Value::Text("root_hash".into()), int_arr(&conf.root_hash)),
            (Value::Text("synced_to_tick".into()), Value::Integer(0.into())),
            (Value::Text("committed_at_tick".into()), Value::Integer(0.into())),
        ]);
        let mut buf = alloc::vec::Vec::new();
        ciborium::into_writer(&legacy, &mut buf).expect("encode legacy");
        let back: crate::types::NablaConfirmation =
            ciborium::from_reader(buf.as_slice()).expect("decode legacy array form");
        assert_eq!(back.nabla_node_id, conf.nabla_node_id);
        assert_eq!(back.nabla_signature, conf.nabla_signature);
        // And it still verifies after the array→struct decode.
        assert!(verify_nabla_confirmation(&[0x10; 32], &[0x11; 32], &back).is_ok());
    }

    /// Build a chain of N links with given healed/scarred pattern.
    /// healed[i] == true means link i is healed (has nabla_confirmation).
    fn make_chain(keys: &[DilithiumTestKey], healed: &[bool]) -> FactChain {
        let mut links = Vec::new();
        for (i, &is_healed) in healed.iter().enumerate() {
            let prev = [i as u8; 32];
            let next = [(i + 1) as u8; 32];
            let tx = [100 + i as u8; 32];
            if is_healed {
                links.push(make_healed_link(tx, prev, next, 100, keys));
            } else {
                links.push(make_test_link(tx, prev, next, 100, keys));
            }
        }
        FactChain { checkpoint: None, links }
    }

    // ── Phase 1: Scar-aware compression tests ─────────────────────

    #[test]
    fn test_compression_stops_at_scar() {
        // [healed×6, SCAR, healed×2] — only healed prefix (6) compresses.
        // 6 > FACT_KEEP, so split_at = 6 - FACT_KEEP links compressed.
        // Scar at index 6 and links after it remain.
        let keys = test_keys();
        let pattern = [true, true, true, true, true, true, false, true, true];
        let chain = make_chain(&keys, &pattern);
        assert_eq!(chain.links.len(), 9);

        let validators: Vec<([u8; 32], &[u8], &[u8])> = keys.iter().enumerate().map(|(i, k)| {
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            (vid, k.pk.as_slice(), k.sk.as_slice())
        }).collect();

        let split_at = 6 - FACT_KEEP; // compressed from the healed prefix
        let result = compress_fact_chain(chain, &validators).unwrap();
        assert_eq!(result.links.len(), 9 - split_at);
        assert!(result.checkpoint.is_some());
        // The scar link (originally index 6, now shifted left by split_at) must survive.
        assert!(result.links[6 - split_at].nabla_confirmation.is_none(), "scar must survive compression");
    }

    #[test]
    fn test_compression_all_scarred_no_compress() {
        // v2.11.11: All-scarred chains are NOT compressed. resolved_prefix = 0,
        // so compressible = 0 (under FACT_KEEP). Scarred links must remain
        // uncompressed to prevent wash-out attacks and V3 timing mismatches.
        let keys = test_keys();
        let pattern = [false; 10];
        let chain = make_chain(&keys, &pattern);

        let validators: Vec<([u8; 32], &[u8], &[u8])> = keys.iter().enumerate().map(|(i, k)| {
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            (vid, k.pk.as_slice(), k.sk.as_slice())
        }).collect();

        let result = compress_fact_chain(chain, &validators).unwrap();
        // No compression: all 10 scarred links remain, no checkpoint
        assert_eq!(result.links.len(), 10);
        assert!(result.checkpoint.is_none());
    }

    #[test]
    fn test_compression_few_scarred_no_compress() {
        // 4 scarred links (under FACT_KEEP threshold). No compression needed.
        let keys = test_keys();
        let pattern = [false; 4];
        let chain = make_chain(&keys, &pattern);

        let validators: Vec<([u8; 32], &[u8], &[u8])> = keys.iter().enumerate().map(|(i, k)| {
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            (vid, k.pk.as_slice(), k.sk.as_slice())
        }).collect();

        let result = compress_fact_chain(chain, &validators).unwrap();
        assert_eq!(result.links.len(), 4);
        assert!(result.checkpoint.is_none());
    }

    #[test]
    fn test_compression_short_unscarred_prefix_no_compress() {
        // [healed×3, SCAR, healed×6]. Prefix = 3 ≤ FACT_KEEP(5), no compression.
        let keys = test_keys();
        let mut pattern = vec![true, true, true, false];
        pattern.extend([true; 6]);
        let chain = make_chain(&keys, &pattern);

        let validators: Vec<([u8; 32], &[u8], &[u8])> = keys.iter().enumerate().map(|(i, k)| {
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            (vid, k.pk.as_slice(), k.sk.as_slice())
        }).collect();

        let result = compress_fact_chain(chain, &validators).unwrap();
        assert_eq!(result.links.len(), 10);
        assert!(result.checkpoint.is_none());
    }

    #[test]
    fn test_compression_all_healed_compresses_normally() {
        // 10 healed links. Unscarred prefix = 10 > FACT_KEEP.
        // split_at = 10 - FACT_KEEP compressed, FACT_KEEP remain.
        let keys = test_keys();
        let pattern = [true; 10];
        let chain = make_chain(&keys, &pattern);

        let validators: Vec<([u8; 32], &[u8], &[u8])> = keys.iter().enumerate().map(|(i, k)| {
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            (vid, k.pk.as_slice(), k.sk.as_slice())
        }).collect();

        let result = compress_fact_chain(chain, &validators).unwrap();
        assert_eq!(result.links.len(), FACT_KEEP);
        assert!(result.checkpoint.is_some());
        let cp = result.checkpoint.unwrap();
        assert_eq!(cp.compressed_count, (10 - FACT_KEEP) as u64);
    }

    #[test]
    fn test_v3_timing_healed_chain_consistent_compression() {
        // v2.11.11 regression test: A chain healed between V2 and V3 must
        // produce the same compression result as if it were always healed.
        // Before the fix, all-scarred chains used a different compression
        // path (all_unresolved fallback), causing checkpoint mismatches
        // when chains healed mid-transaction.
        let keys = test_keys();
        let validators: Vec<([u8; 32], &[u8], &[u8])> = keys.iter().enumerate().map(|(i, k)| {
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            (vid, k.pk.as_slice(), k.sk.as_slice())
        }).collect();

        // Scenario: 8 links, first 6 healed, last 2 scarred.
        // V2 sees all-scarred, V3 sees first 6 healed.
        // Both must produce no compression (resolved_prefix=6 > FACT_KEEP,
        // so compression happens — but consistently).
        let pattern_v2 = [false; 8]; // V2: all scarred
        let chain_v2 = make_chain(&keys, &pattern_v2);
        let result_v2 = compress_fact_chain(chain_v2, &validators).unwrap();
        // V2: all-scarred → no compression (resolved_prefix=0)
        assert_eq!(result_v2.links.len(), 8);
        assert!(result_v2.checkpoint.is_none());

        let pattern_v3 = [true, true, true, true, true, true, false, false]; // V3: 6 healed + 2 scarred
        let chain_v3 = make_chain(&keys, &pattern_v3);
        let result_v3 = compress_fact_chain(chain_v3, &validators).unwrap();
        // V3: resolved_prefix=6, compressible=6 > FACT_KEEP, split_at = 6 - FACT_KEEP
        assert_eq!(result_v3.links.len(), 8 - (6 - FACT_KEEP));
        assert!(result_v3.checkpoint.is_some());

        // Key invariant: V2 produced no checkpoint, V3 produced one.
        // This is CORRECT because V3 has strictly more information (healed links).
        // The old bug was: V2 produced a checkpoint (via all_unresolved fallback)
        // that was INCOMPATIBLE with V3's scar-aware checkpoint.
        // Now both paths are deterministic given their input state.
    }

    // ── Phase 2: Scar heal commitment/verification tests ──────────

    #[test]
    fn test_compute_scar_heal_commitment_deterministic() {
        let tx_id = [1u8; 32];
        let node_id = [2u8; 32];
        let root_hash = [3u8; 32];
        let c1 = compute_scar_heal_commitment(&tx_id, &node_id, &root_hash);
        let c2 = compute_scar_heal_commitment(&tx_id, &node_id, &root_hash);
        assert_eq!(c1, c2);
        // Non-zero — it actually computed something
        assert_ne!(c1, [0u8; 32]);
    }

    #[test]
    fn test_compute_scar_heal_commitment_different_inputs() {
        let c1 = compute_scar_heal_commitment(&[1u8; 32], &[2u8; 32], &[3u8; 32]);
        let c2 = compute_scar_heal_commitment(&[99u8; 32], &[2u8; 32], &[3u8; 32]);
        assert_ne!(c1, c2, "different tx_id must produce different commitment");
    }

    #[test]
    fn test_verify_valid_scar_recovery_proof() {
        let keys = test_keys();
        let tx_id = [1u8; 32];
        let nabla_conf = sign_nabla_confirmation(&[0u8; 32], &[1u8; 32]);
        let commitment = compute_scar_heal_commitment(&tx_id, &nabla_conf.nabla_node_id, &nabla_conf.root_hash);

        let mut witnesses = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let sig = crate::crypto::sign_dilithium(&key.sk, &commitment)
                .expect("test sign_dilithium");
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            witnesses.push(FactWitness {
                validator_id: vid,
                validator_pk: key.pk.clone(),
                signature: sig,
                vbc_genesis_anchor: None,
            });
        }

        let proof = crate::types::ScarRecoveryProof {
            original_tx_id: tx_id,
            nabla_confirmation: nabla_conf,
            healing_witnesses: witnesses,
            receiver_wallet_id: "test".to_string(),
            fact_link_index: None,
        };

        assert!(verify_scar_recovery_proof(&proof).is_ok());
    }

    #[test]
    fn test_verify_proof_bad_signature() {
        let keys = test_keys();
        let tx_id = [1u8; 32];
        let nabla_conf = sign_nabla_confirmation(&[0u8; 32], &[1u8; 32]);
        let commitment = compute_scar_heal_commitment(&tx_id, &nabla_conf.nabla_node_id, &nabla_conf.root_hash);

        let mut witnesses = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let sig = crate::crypto::sign_dilithium(&key.sk, &commitment)
                .expect("test sign_dilithium");
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            witnesses.push(FactWitness {
                validator_id: vid,
                validator_pk: key.pk.clone(),
                signature: sig,
                vbc_genesis_anchor: None,
            });
        }
        // Corrupt first signature
        witnesses[0].signature = vec![0u8; 64];

        let proof = crate::types::ScarRecoveryProof {
            original_tx_id: tx_id,
            nabla_confirmation: nabla_conf,
            healing_witnesses: witnesses,
            receiver_wallet_id: "test".to_string(),
            fact_link_index: None,
        };

        assert!(verify_scar_recovery_proof(&proof).is_err());
    }

    #[test]
    fn test_verify_proof_insufficient_witnesses() {
        let keys = test_keys();
        let tx_id = [1u8; 32];
        let nabla_conf = sign_nabla_confirmation(&[0u8; 32], &[1u8; 32]);
        let commitment = compute_scar_heal_commitment(&tx_id, &nabla_conf.nabla_node_id, &nabla_conf.root_hash);

        // Only 2 witnesses (need 3)
        let mut witnesses = Vec::new();
        for (i, key) in keys.iter().take(2).enumerate() {
            let sig = crate::crypto::sign_dilithium(&key.sk, &commitment)
                .expect("test sign_dilithium");
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            witnesses.push(FactWitness {
                validator_id: vid,
                validator_pk: key.pk.clone(),
                signature: sig,
                vbc_genesis_anchor: None,
            });
        }

        let proof = crate::types::ScarRecoveryProof {
            original_tx_id: tx_id,
            nabla_confirmation: nabla_conf,
            healing_witnesses: witnesses,
            receiver_wallet_id: "test".to_string(),
            fact_link_index: None,
        };

        let err = verify_scar_recovery_proof(&proof).unwrap_err();
        assert!(matches!(err, ValidationError::FactInsufficientWitnesses));
    }

    #[test]
    fn test_verify_proof_duplicate_witness() {
        let keys = test_keys();
        let tx_id = [1u8; 32];
        let nabla_conf = sign_nabla_confirmation(&[0u8; 32], &[1u8; 32]);
        let commitment = compute_scar_heal_commitment(&tx_id, &nabla_conf.nabla_node_id, &nabla_conf.root_hash);

        let mut witnesses = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let sig = crate::crypto::sign_dilithium(&key.sk, &commitment)
                .expect("test sign_dilithium");
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            witnesses.push(FactWitness {
                validator_id: vid,
                validator_pk: key.pk.clone(),
                signature: sig,
                vbc_genesis_anchor: None,
            });
        }
        // Duplicate: set witness[2] validator_id to same as witness[0]
        witnesses[2].validator_id = witnesses[0].validator_id;

        let proof = crate::types::ScarRecoveryProof {
            original_tx_id: tx_id,
            nabla_confirmation: nabla_conf,
            healing_witnesses: witnesses,
            receiver_wallet_id: "test".to_string(),
            fact_link_index: None,
        };

        let err = verify_scar_recovery_proof(&proof).unwrap_err();
        assert!(matches!(err, ValidationError::FactDuplicateWitness));
    }

    #[test]
    fn test_scar_count() {
        let keys = test_keys();
        let mut link1 = make_test_link([1u8; 32], [0u8; 32], [2u8; 32], 1000, &keys);
        link1.nabla_confirmation = Some(sign_nabla_confirmation(&[0u8; 32], &[2u8; 32])); // healed
        let link2 = make_test_link([3u8; 32], [2u8; 32], [4u8; 32], 500, &keys); // scarred
        let chain = FactChain { checkpoint: None, links: vec![link1, link2] };
        let result = verify_fact_chain(&chain);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1); // 1 scar
    }

    // ── Burn proof compression tests (YPX-001 §1.5.4) ──────────

    /// Make a burned link (has burn_proof, no nabla_confirmation).
    /// `burn_tx_id` defaults to the link's own tx_id — the chain-scoped
    /// reference check (verify_fact_chain_inner) requires burn_tx_id to
    /// match a link in the chain, and the link itself satisfies that for
    /// these structural tests. Production burn TXs are siblings of the
    /// scarred link they target; tests that exercise that shape construct
    /// the burn link explicitly and pass its tx_id here.
    fn make_burned_link(
        tx_id: [u8; 32],
        prev_state: [u8; 32],
        new_state: [u8; 32],
        amount: u64,
        keys: &[DilithiumTestKey],
    ) -> FactLink {
        let mut link = make_test_link(tx_id, prev_state, new_state, amount, keys);
        link.burn_proof = Some(crate::types::BurnProof {
            burn_tx_id: tx_id,
            validator_sigs: link.witnesses.clone(),
        });
        link
    }

    // ── YPX-001 §1.5.1a scar inheritance (CORE RULE, 2026-07-12) ────────
    // Pins: derivation (unresolved − cheque-own − ark, transitive, sorted,
    // self-redeem empty), commitment binding (strip ⇒ sig fail), and the
    // compression defence in depth (inherited-unresolved never resolves).

    #[test]
    fn inherited_set_derivation_rules() {
        let keys = test_keys();
        let mut chain = FactChain::new();
        // L1: unresolved, connected-mode → inherits
        chain.links.push(make_test_link([1u8; 32], [0u8; 32], [1u8; 32], 5, &keys));
        // L2: resolved (conf) → not inherited
        let mut l2 = make_test_link([2u8; 32], [1u8; 32], [2u8; 32], 5, &keys);
        l2.nabla_confirmation = Some(sign_nabla_confirmation(&[1u8; 32], &[2u8; 32]));
        // …but L2 itself CARRIES an unresolved inherited txid → transitive
        l2.inherited_scar_txids = vec![[0xEE; 32]];
        chain.links.push(l2);
        // L3: unresolved ARK provenance (required_k = 0) → excluded
        let mut l3 = make_test_link([3u8; 32], [2u8; 32], [3u8; 32], 5, &keys);
        l3.required_k = 0;
        chain.links.push(l3);
        // L4: unresolved, and it IS the cheque being redeemed → excluded
        chain.links.push(make_test_link([4u8; 32], [3u8; 32], [4u8; 32], 5, &keys));

        let set = compute_inherited_scar_txids(&chain, &[4u8; 32], false);
        assert_eq!(set, vec![[1u8; 32], [0xEE; 32]].into_iter().collect::<alloc::collections::BTreeSet<_>>().into_iter().collect::<Vec<_>>(),
            "expected L1 + L2's transitive txid, sorted; got {:?}", set.len());
        assert!(set.contains(&[1u8; 32]) && set.contains(&[0xEE; 32]) && set.len() == 2);

        // Self-redeem inherits nothing.
        assert!(compute_inherited_scar_txids(&chain, &[4u8; 32], true).is_empty());

        // Resolved transitive entry drops out.
        let mut chain2 = chain.clone();
        chain2.links[1].inherited_scar_resolutions = vec![
            crate::types::NablaTxidAttestation { txid: [0xEE; 32], ..Default::default() }
        ];
        let set2 = compute_inherited_scar_txids(&chain2, &[4u8; 32], false);
        assert!(set2.contains(&[1u8; 32]) && !set2.contains(&[0xEE; 32]));
    }

    #[test]
    fn inherited_set_is_commitment_bound() {
        // Same link data, different inherited sets ⇒ different commitments —
        // stripping the taint invalidates every witness Dilithium signature.
        let a = compute_fact_commitment(&[1u8;32], &[2u8;32], &[3u8;32], 9, None, false, &[]);
        let b = compute_fact_commitment(&[1u8;32], &[2u8;32], &[3u8;32], 9, None, false, &[[7u8;32]]);
        let c = compute_fact_commitment(&[1u8;32], &[2u8;32], &[3u8;32], 9, None, false, &[[7u8;32],[8u8;32]]);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn inherited_unresolved_blocks_resolution_and_compression() {
        let keys = test_keys();
        let mut link = make_test_link([1u8; 32], [0u8; 32], [1u8; 32], 5, &keys);
        link.nabla_confirmation = Some(sign_nabla_confirmation(&[0u8; 32], &[1u8; 32]));
        assert!(link.is_resolved(), "own-confirmed link with no inherited taint resolves");

        link.inherited_scar_txids = vec![[9u8; 32]];
        assert!(!link.is_resolved(),
            "unresolved inherited taint MUST keep the link scarred — the \
             compression prefix (take_while is_resolved) can never cover it");
        assert_eq!(link.inherited_unresolved(), 1);

        link.inherited_scar_resolutions = vec![
            crate::types::NablaTxidAttestation { txid: [9u8; 32], ..Default::default() }
        ];
        assert_eq!(link.inherited_unresolved(), 0);
        assert!(link.is_resolved(), "resolution entry clears the inherited scar");
    }

    #[test]
    fn forged_inherited_resolution_rejects_chain() {
        use ed25519_dalek::Signer;
        // A garbage attestation attached as a "resolution" must HARD-reject —
        // an attacker cannot wash inherited taint with a fake attestation.
        let keys = test_keys();

        // Build the link WITH the inherited set bound into the commitment
        // (make_test_link signs the plain commitment, so build manually).
        let inherited = alloc::vec![[9u8; 32]];
        let commitment = compute_fact_commitment(
            &[1u8;32], &[0u8;32], &[1u8;32], 5, None, false, &inherited);
        let mut witnesses = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let sig = crate::crypto::sign_dilithium(&key.sk, &commitment).unwrap();
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            witnesses.push(crate::types::FactWitness {
                validator_id: vid,
                validator_pk: key.pk.clone(),
                signature: sig,
                vbc_genesis_anchor: None,
            });
        }
        let mut link = make_test_link([1u8; 32], [0u8; 32], [1u8; 32], 5, &keys);
        link.witnesses = witnesses;
        link.inherited_scar_txids = inherited;

        // Bare link (unresolved inherited, no resolutions): verify passes —
        // taint present is a VALID state, just scarred.
        assert!(verify_fact_link(&link).is_ok(),
            "commitment-bound inherited set must verify");

        // Attach a forged resolution: self-signed attestation, no NBC.
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x66; 32]);
        let mut h = blake3::Hasher::new();
        h.update(b"AXIOM_TXID_ATTEST");
        h.update(&[9u8; 32]);
        h.update(b"REDEEMED");
        h.update(&7u64.to_le_bytes());
        let payload = h.finalize();
        link.inherited_scar_resolutions = vec![crate::types::NablaTxidAttestation {
            txid: [9u8; 32],
            status: "REDEEMED".into(),
            nabla_node_pk: sk.verifying_key().to_bytes(),
            nabla_signature: sk.sign(payload.as_bytes()).to_bytes().to_vec(),
            nabla_tick: 7,
            ..Default::default()
        }];
        assert!(verify_fact_link(&link).is_err(),
            "self-signed resolution without NBC anchor MUST reject the chain");

        // Resolution for a txid NOT in the inherited set: reject.
        link.inherited_scar_resolutions = vec![crate::types::NablaTxidAttestation {
            txid: [0xAA; 32],
            ..Default::default()
        }];
        assert!(verify_fact_link(&link).is_err(),
            "resolution targeting a foreign txid MUST reject");
    }

    #[test]
    fn test_burn_proof_makes_link_compressible() {
        // A burned link (burn_proof.is_some()) should be treated as resolved
        // and count toward the compressible prefix, same as healed links.
        let keys = test_keys();
        // 7 burned links + 3 scarred = total 10.
        // Compressible prefix = 7 (burned). 7 > FACT_KEEP → compress.
        let mut links = Vec::new();
        for i in 0..7u8 {
            links.push(make_burned_link([100 + i; 32], [i; 32], [i + 1; 32], 100, &keys));
        }
        for i in 7..10u8 {
            links.push(make_test_link([100 + i; 32], [i; 32], [i + 1; 32], 100, &keys));
        }
        let chain = FactChain { checkpoint: None, links };

        let validators: Vec<([u8; 32], &[u8], &[u8])> = keys.iter().enumerate().map(|(i, k)| {
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            (vid, k.pk.as_slice(), k.sk.as_slice())
        }).collect();

        let split_at = 7 - FACT_KEEP; // 7 compressible burned links
        let result = compress_fact_chain(chain, &validators).unwrap();
        assert_eq!(result.links.len(), 10 - split_at);
        assert!(result.checkpoint.is_some());
        assert_eq!(result.checkpoint.unwrap().compressed_count, split_at as u64);
    }

    #[test]
    fn test_burn_proof_compression_mixed() {
        // Mix of healed and burned links in the prefix, then a scar.
        // [healed, burned, healed, burned, healed, burned, SCAR, healed]
        // Compressible prefix = 6 (all resolved). 6 > FACT_KEEP → compress.
        let keys = test_keys();
        let mut links = Vec::new();
        for i in 0..8u8 {
            let prev = [i; 32];
            let next = [i + 1; 32];
            let tx = [100 + i; 32];
            if i == 6 {
                // SCAR at index 6
                links.push(make_test_link(tx, prev, next, 100, &keys));
            } else if i % 2 == 0 {
                // Even = healed
                links.push(make_healed_link(tx, prev, next, 100, &keys));
            } else {
                // Odd = burned
                links.push(make_burned_link(tx, prev, next, 100, &keys));
            }
        }
        let chain = FactChain { checkpoint: None, links };

        let validators: Vec<([u8; 32], &[u8], &[u8])> = keys.iter().enumerate().map(|(i, k)| {
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            (vid, k.pk.as_slice(), k.sk.as_slice())
        }).collect();

        let split_at = 6 - FACT_KEEP; // 6 resolved links in the prefix (indices 0-5)
        let result = compress_fact_chain(chain, &validators).unwrap();
        assert_eq!(result.links.len(), 8 - split_at);
        assert!(result.checkpoint.is_some());
        assert_eq!(result.checkpoint.unwrap().compressed_count, split_at as u64);
    }

    #[test]
    fn test_burn_proof_not_counted_as_scar() {
        // A burned link should NOT count as a scar
        let keys = test_keys();
        let mut link1 = make_test_link([1u8; 32], [0u8; 32], [2u8; 32], 1000, &keys);
        link1.burn_proof = Some(crate::types::BurnProof {
            burn_tx_id: link1.tx_id, // self-reference satisfies chain-scoped check
            validator_sigs: link1.witnesses.clone(),
        });
        let link2 = make_test_link([3u8; 32], [2u8; 32], [4u8; 32], 500, &keys); // scarred

        let chain = FactChain { checkpoint: None, links: vec![link1, link2] };
        let result = verify_fact_chain(&chain);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1); // Only link2 is a scar, link1 is burned (resolved)
    }

    // ── BurnProof structural verification (Phase 1.2a) ──────────────
    //
    // These three tests prove that a chain that arrives with a forged
    // BurnProof on a scarred link is rejected by verify_fact_chain.
    // Pre-2026-05-07 verify_fact_link didn't look at burn_proof at all
    // and these forges all silently passed.

    #[test]
    fn test_burn_proof_empty_validator_sigs_rejected() {
        // Empty validator_sigs — the headline forge. is_resolved() returned
        // true for free, letting an attacker present a "burned" scar to a
        // counterparty in a redeem.
        let keys = test_keys();
        let mut link1 = make_test_link([1u8; 32], [0u8; 32], [2u8; 32], 1000, &keys);
        link1.burn_proof = Some(crate::types::BurnProof {
            burn_tx_id: link1.tx_id,
            validator_sigs: vec![],
        });
        let chain = FactChain { checkpoint: None, links: vec![link1] };
        let err = verify_fact_chain(&chain).unwrap_err();
        assert!(matches!(err, ValidationError::BurnProofInsufficientWitnesses));
    }

    #[test]
    fn test_burn_proof_duplicate_validator_rejected() {
        // Two of the three sigs share validator_id. One real validator
        // can't unilaterally "burn" by replaying their own sig.
        let keys = test_keys();
        let mut link1 = make_test_link([1u8; 32], [0u8; 32], [2u8; 32], 1000, &keys);
        let mut sigs = link1.witnesses.clone();
        sigs[1].validator_id = sigs[0].validator_id; // collide
        link1.burn_proof = Some(crate::types::BurnProof {
            burn_tx_id: link1.tx_id,
            validator_sigs: sigs,
        });
        let chain = FactChain { checkpoint: None, links: vec![link1] };
        let err = verify_fact_chain(&chain).unwrap_err();
        assert!(matches!(err, ValidationError::BurnProofDuplicateValidator));
    }

    #[test]
    fn test_burn_proof_burn_tx_id_must_be_in_chain() {
        // burn_tx_id pointing at a tx_id absent from the chain — attacker
        // claims a burn TX exists somewhere off-chain. Chain-scoped
        // reference check rejects.
        let keys = test_keys();
        let mut link1 = make_test_link([1u8; 32], [0u8; 32], [2u8; 32], 1000, &keys);
        link1.burn_proof = Some(crate::types::BurnProof {
            burn_tx_id: [0xDEu8; 32], // not in chain
            validator_sigs: link1.witnesses.clone(),
        });
        let chain = FactChain { checkpoint: None, links: vec![link1] };
        let err = verify_fact_chain(&chain).unwrap_err();
        assert!(matches!(err, ValidationError::BurnTxIdNotInChain));
    }

    #[test]
    fn test_burn_commitment_deterministic() {
        let c1 = crate::crypto::compute_burn_commitment(&[1u8; 32], &[2u8; 32], 1000);
        let c2 = crate::crypto::compute_burn_commitment(&[1u8; 32], &[2u8; 32], 1000);
        assert_eq!(c1, c2);
        assert_ne!(c1, [0u8; 32]); // non-trivial
    }

    #[test]
    fn test_burn_commitment_different_inputs() {
        let c1 = crate::crypto::compute_burn_commitment(&[1u8; 32], &[2u8; 32], 1000);
        let c2 = crate::crypto::compute_burn_commitment(&[99u8; 32], &[2u8; 32], 1000);
        let c3 = crate::crypto::compute_burn_commitment(&[1u8; 32], &[2u8; 32], 9999);
        assert_ne!(c1, c2, "different tx_id must produce different commitment");
        assert_ne!(c1, c3, "different amount must produce different commitment");
    }

    /// SEC-07 travel model: a 9-resolved-link chain is now WITHIN limits
    /// (verify accepts it — depth 9 < FACT_HARD_CEILING 32), and
    /// verify_and_compress still compresses the excess on demand.
    #[test]
    fn test_over_depth_verify_ok_and_compress_succeeds() {
        let keys = test_keys();
        let pattern = [true; 9];
        let chain = make_chain(&keys, &pattern);

        // Standalone verify now ACCEPTS (depth is not a hard deadline anymore).
        assert!(verify_fact_chain(&chain).is_ok(),
            "depth-9 chain verifies under the travel model");

        // verify_and_compress still compresses the excess (legacy immediate path).
        let validators: Vec<([u8; 32], &[u8], &[u8])> = keys.iter().enumerate().map(|(i, k)| {
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            (vid, k.pk.as_slice(), k.sk.as_slice())
        }).collect();

        let (compressed, scar_count) = verify_and_compress_fact_chain(chain, &validators).unwrap();
        assert_eq!(scar_count, 0, "All links are resolved — zero scars");
        assert!(compressed.links.len() <= MAX_FACT_DEPTH,
            "After compression, links must be within MAX_FACT_DEPTH");
        assert!(compressed.checkpoint.is_some(), "Compression must produce a checkpoint");
    }

    // ── Adversarial FACT chain compression tests ─────────────────

    /// Helper: build validator tuples from test keys for compress_fact_chain.
    fn make_validators(keys: &[DilithiumTestKey]) -> Vec<([u8; 32], &[u8], &[u8])> {
        keys.iter().enumerate().map(|(i, k)| {
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            (vid, k.pk.as_slice(), k.sk.as_slice())
        }).collect()
    }

    #[test]
    fn test_compression_never_drops_scarred_link() {
        // Chain: [healed×8, SCAR, healed×2] = 11 links.
        // resolved_prefix = 8 (stops at index 8 which is the scar).
        // 8 > FACT_KEEP → split_at = 8 - FACT_KEEP compressed.
        // The SCAR at original index 8 must survive in the output.
        let keys = test_keys();
        let mut pattern = vec![true; 8];
        pattern.push(false); // SCAR at index 8
        pattern.push(true);
        pattern.push(true);
        assert_eq!(pattern.len(), 11);

        let chain = make_chain(&keys, &pattern);
        let scar_count_before = chain.links.iter()
            .filter(|l| !l.is_resolved()).count();
        assert_eq!(scar_count_before, 1);

        let split_at = 8 - FACT_KEEP;
        let validators = make_validators(&keys);
        let result = compress_fact_chain(chain, &validators).unwrap();

        assert_eq!(result.links.len(), 11 - split_at);
        assert!(result.checkpoint.is_some());

        // Verify the SCAR link is still present
        let scar_count_after = result.links.iter()
            .filter(|l| !l.is_resolved()).count();
        assert_eq!(scar_count_after, 1, "scar must survive compression");

        // The scar should be at original index 8 minus split_at compressed
        assert!(!result.links[8 - split_at].is_resolved(), "scar link must be at expected position");
    }

    #[test]
    fn test_compression_preserves_scar_identity() {
        // Build chain with a known scar tx_id. Compress multiple times.
        // The same tx_id must remain after each compression.
        let keys = test_keys();
        let validators = make_validators(&keys);

        // Chain: [healed×10, SCAR, healed×4] = 15 links.
        // Scar tx_id is at index 10: [100+10; 32] = [110; 32]
        let mut pattern = vec![true; 10];
        pattern.push(false); // SCAR at index 10
        pattern.extend(vec![true; 4]);

        let chain = make_chain(&keys, &pattern);
        let scar_tx_id = chain.links[10].tx_id;
        assert_eq!(scar_tx_id, [110u8; 32]);

        // First compression: resolved_prefix=10, split_at=10-5=5
        let result1 = compress_fact_chain(chain, &validators).unwrap();
        let scar_ids_1: Vec<[u8; 32]> = result1.links.iter()
            .filter(|l| !l.is_resolved())
            .map(|l| l.tx_id)
            .collect();
        assert_eq!(scar_ids_1, vec![[110u8; 32]], "scar tx_id must survive first compression");

        // Second compression: remaining = 10 links, resolved_prefix = 5 (healed before scar)
        // 5 <= FACT_KEEP → no further compression. Chain stays the same.
        let result2 = compress_fact_chain(result1, &validators).unwrap();
        let scar_ids_2: Vec<[u8; 32]> = result2.links.iter()
            .filter(|l| !l.is_resolved())
            .map(|l| l.tx_id)
            .collect();
        assert_eq!(scar_ids_2, vec![[110u8; 32]], "scar tx_id must survive second compression");
    }

    #[test]
    fn test_compressed_then_verified_preserves_scars() {
        // Build chain, compress, then run verify_fact_chain on result.
        // Scar count from verify must match the original scar count.
        let keys = test_keys();
        let validators = make_validators(&keys);

        // [healed×4, SCAR, SCAR, healed×1] = 7 links, 2 scars.
        // After compression: checkpoint + 5 remaining links (within MAX_FACT_DEPTH=5).
        let mut pattern = vec![true; 4];
        pattern.push(false);
        pattern.push(false);
        pattern.push(true);

        let chain = make_chain(&keys, &pattern);
        let scar_count_before = chain.scar_count();
        assert_eq!(scar_count_before, 2);

        // Compress: resolved_prefix=4, split_at=4-FACT_KEEP
        let compressed = compress_fact_chain(chain, &validators).unwrap();
        let scar_count_compressed = compressed.scar_count();
        assert_eq!(scar_count_compressed, 2, "compression must not change scar count");

        // Verify the compressed chain
        let verify_scar_count = verify_fact_chain(&compressed).unwrap();
        assert_eq!(verify_scar_count, 2, "verify_fact_chain scar count must match");
    }

    #[test]
    fn test_interleaved_scars_block_compression() {
        // [healed, SCAR, healed×6, SCAR, healed×3] = 12 links.
        // resolved_prefix = 1 (stops at index 1, the first scar).
        // 1 <= FACT_KEEP(5) → no compression at all.
        let keys = test_keys();
        let validators = make_validators(&keys);

        let mut pattern = vec![true];       // index 0: healed
        pattern.push(false);                // index 1: SCAR
        pattern.extend(vec![true; 6]);      // index 2-7: healed
        pattern.push(false);                // index 8: SCAR
        pattern.extend(vec![true; 3]);      // index 9-11: healed
        assert_eq!(pattern.len(), 12);

        let chain = make_chain(&keys, &pattern);

        // Verify resolved_prefix = 1
        let resolved_prefix = chain.links.iter()
            .take_while(|l| l.is_resolved())
            .count();
        assert_eq!(resolved_prefix, 1, "resolved prefix stops at first scar");

        let result = compress_fact_chain(chain, &validators).unwrap();
        // No compression: 1 <= FACT_KEEP(5)
        assert_eq!(result.links.len(), 12, "no links should be compressed");
        assert!(result.checkpoint.is_none(), "no checkpoint when nothing compresses");
    }

    #[test]
    fn test_healed_scar_becomes_compressible() {
        // Build chain with scar at index 3, verify prefix stops there.
        // Then "heal" it by adding nabla_confirmation. Verify prefix increases.
        let keys = test_keys();
        let validators = make_validators(&keys);

        // [healed×3, SCAR, healed×6] = 10 links. resolved_prefix = 3.
        let mut pattern = vec![true; 3];
        pattern.push(false); // SCAR at index 3
        pattern.extend(vec![true; 6]);
        let mut chain = make_chain(&keys, &pattern);

        let prefix_before = chain.links.iter()
            .take_while(|l| l.is_resolved()).count();
        assert_eq!(prefix_before, 3, "prefix stops at scar");

        // Heal the scar by adding nabla_confirmation
        chain.links[3].nabla_confirmation = Some(sign_nabla_confirmation(&[3u8; 32], &[4u8; 32]));

        let prefix_after = chain.links.iter()
            .take_while(|l| l.is_resolved()).count();
        assert_eq!(prefix_after, 10, "after healing, entire chain is resolved");

        // Now compression should proceed: 10 > FACT_KEEP, split_at = 10 - FACT_KEEP
        let result = compress_fact_chain(chain, &validators).unwrap();
        assert_eq!(result.links.len(), FACT_KEEP);
        assert!(result.checkpoint.is_some());
        assert_eq!(result.checkpoint.unwrap().compressed_count, (10 - FACT_KEEP) as u64);
    }

    #[test]
    fn test_checkpoint_genesis_fact_hash_survives_recompression() {
        // Build a long chain (20+ healed links). Compress twice.
        // genesis_fact_hash in the final checkpoint must match the first compression's.
        let keys = test_keys();
        let validators = make_validators(&keys);

        // 22 healed links
        let pattern = vec![true; 22];
        let chain = make_chain(&keys, &pattern);

        // First compression: resolved_prefix=22, split_at=22-5=17 compressed, 5 remain.
        let result1 = compress_fact_chain(chain, &validators).unwrap();
        assert!(result1.checkpoint.is_some());
        let genesis_hash_1 = result1.checkpoint.as_ref().unwrap().genesis_fact_hash;
        assert_ne!(genesis_hash_1, [0u8; 32], "genesis_fact_hash must be non-zero");

        // Now add more healed links to exceed FACT_KEEP again for a second compression.
        let mut chain2 = result1;
        // Extend from where the chain left off (last link's new_state_id)
        let base = chain2.links.last().unwrap().new_state_id;
        for i in 0..8u8 {
            let prev = if i == 0 { base } else {
                let mut s = [0u8; 32];
                s[0] = 200 + i - 1;
                s
            };
            let mut next = [0u8; 32];
            next[0] = 200 + i;
            let mut tx = [0u8; 32];
            tx[0] = 200 + i;
            tx[1] = 0xFF;
            chain2.links.push(make_healed_link(tx, prev, next, 100, &keys));
        }

        // Second compression
        let result2 = compress_fact_chain(chain2, &validators).unwrap();
        assert!(result2.checkpoint.is_some());
        let genesis_hash_2 = result2.checkpoint.as_ref().unwrap().genesis_fact_hash;

        assert_eq!(genesis_hash_1, genesis_hash_2,
            "genesis_fact_hash must propagate through recompression unchanged");
    }

    #[test]
    fn test_chain_continuity_break_after_compression() {
        // Compress a valid chain, then tamper with checkpoint's final_state_id.
        // verify_fact_chain must reject.
        let keys = test_keys();
        let validators = make_validators(&keys);

        let pattern = vec![true; 10];
        let chain = make_chain(&keys, &pattern);

        let mut compressed = compress_fact_chain(chain, &validators).unwrap();
        // Sanity: the compressed chain should pass verification
        assert!(verify_fact_chain(&compressed).is_ok());

        // Tamper with checkpoint's final_state_id
        compressed.checkpoint.as_mut().unwrap().final_state_id = [0xFFu8; 32];

        // Two possible failure modes:
        // 1. Checkpoint signature verification fails (commitment changed)
        // 2. Chain continuity fails (first link's previous_state_id != tampered final_state_id)
        // Either way, verify must reject.
        let result = verify_fact_chain(&compressed);
        assert!(result.is_err(), "tampered checkpoint final_state_id must be rejected");
    }

    #[test]
    fn test_max_unresolved_scars_enforced() {
        // Build chain with 21 unresolved scars.
        // The MAX_UNRESOLVED_SCARS (20) check lives in validation.rs, not fact.rs.
        // fact.rs's verify_fact_chain correctly counts and returns the scar count.
        let keys = test_keys();

        let pattern = vec![false; 21];
        let chain = make_chain(&keys, &pattern);

        let scar_count = verify_fact_chain(&chain).unwrap();
        assert_eq!(scar_count, 21, "fact.rs must accurately count all 21 scars");
        assert_eq!(chain.scar_count(), 21);

        assert!(scar_count > crate::validation::MAX_UNRESOLVED_SCARS,
            "21 scars must exceed MAX_UNRESOLVED_SCARS(20) — validation.rs would reject");
    }

    #[test]
    fn test_total_links_cap_rejects() {
        // Chains exceeding MAX_TOTAL_LINKS (64) are rejected — DoS prevention.
        let keys = test_keys();
        let pattern = vec![false; 65];
        let chain = make_chain(&keys, &pattern);

        let result = verify_fact_chain(&chain);
        assert!(result.is_err(), "65 total links must be rejected (MAX_TOTAL_LINKS=64)");
    }

    #[test]
    fn test_burned_link_compresses_like_healed() {
        // Chain: [burned×6, healed×2] = 8 links.
        // All 8 are resolved. resolved_prefix = 8.
        // 8 > FACT_KEEP → split_at = 8 - FACT_KEEP compressed.
        let keys = test_keys();
        let validators = make_validators(&keys);

        let mut links = Vec::new();
        for i in 0..6u8 {
            links.push(make_burned_link([100 + i; 32], [i; 32], [i + 1; 32], 100, &keys));
        }
        for i in 6..8u8 {
            links.push(make_healed_link([100 + i; 32], [i; 32], [i + 1; 32], 100, &keys));
        }
        let chain = FactChain { checkpoint: None, links };

        // Verify all links are resolved
        assert!(chain.links.iter().all(|l| l.is_resolved()));
        assert_eq!(chain.scar_count(), 0);

        let result = compress_fact_chain(chain, &validators).unwrap();
        assert_eq!(result.links.len(), FACT_KEEP, "should keep FACT_KEEP links");
        assert!(result.checkpoint.is_some());
        assert_eq!(result.checkpoint.as_ref().unwrap().compressed_count, (8 - FACT_KEEP) as u64);

        // Verify the compressed chain passes verification
        let scar_count = verify_fact_chain(&result).unwrap();
        assert_eq!(scar_count, 0, "no scars — all links are resolved");
    }

    #[test]
    fn test_forge_checkpoint_root_hash_detected() {
        // Compress a valid chain, then modify the checkpoint's root_hash.
        // Re-verify must detect the tampering (signature over commitment includes root_hash).
        let keys = test_keys();
        let validators = make_validators(&keys);

        let pattern = vec![true; 10];
        let chain = make_chain(&keys, &pattern);

        let mut compressed = compress_fact_chain(chain, &validators).unwrap();
        // Sanity: passes verification
        assert!(verify_fact_chain(&compressed).is_ok());

        // Forge the root_hash
        let original_root = compressed.checkpoint.as_ref().unwrap().root_hash;
        compressed.checkpoint.as_mut().unwrap().root_hash = [0xDEu8; 32];
        assert_ne!(compressed.checkpoint.as_ref().unwrap().root_hash, original_root);

        // Verification must fail: the Dilithium signatures were computed over a
        // commitment that includes the original root_hash, so forging it breaks
        // the signature check.
        let result = verify_fact_chain(&compressed);
        assert!(result.is_err(), "forged checkpoint root_hash must be rejected");
        assert!(matches!(result.unwrap_err(), ValidationError::FactInvalidSignature),
            "must fail with FactInvalidSignature due to commitment mismatch");
    }

    #[test]
    fn test_forge_checkpoint_total_amount_detected() {
        // SEC-11: total_amount is now bound into compute_checkpoint_commitment,
        // so tampering with it breaks the k-validator Dilithium signatures.
        // Before the fix, total_amount was absent from the commitment and any
        // attacker-chosen value was accepted on a "signed" struct.
        let keys = test_keys();
        let validators = make_validators(&keys);

        let pattern = vec![true; 10];
        let chain = make_chain(&keys, &pattern);

        let mut compressed = compress_fact_chain(chain, &validators).unwrap();
        assert!(verify_fact_chain(&compressed).is_ok());

        let original = compressed.checkpoint.as_ref().unwrap().total_amount;
        compressed.checkpoint.as_mut().unwrap().total_amount = original.wrapping_add(1_000_000);

        let result = verify_fact_chain(&compressed);
        assert!(result.is_err(), "forged checkpoint total_amount must be rejected");
        assert!(matches!(result.unwrap_err(), ValidationError::FactInvalidSignature),
            "must fail with FactInvalidSignature due to commitment mismatch");
    }

    // ── SEC-07 travel-model checkpoint (AXIOM Origin 2026-06-12) ──
    // docs/security_review_20260612/SEC-07_RESOLUTION.md
    //
    // A checkpoint is a PROPOSAL that travels with the chain and accumulates
    // distinct validator co-signatures across rounds; covered links are RETAINED
    // (provisional) until CHECKPOINT_SIG_THRESHOLD distinct sigs, then deleted
    // (finalized). Each test FAILS without the corresponding piece of the design.

    /// (validator_id, pk, sk) for the i-th test validator.
    fn validator_i(keys: &[DilithiumTestKey], i: usize) -> ([u8; 32], &[u8], &[u8]) {
        let mut vid = [0u8; 32];
        vid[0] = i as u8;
        (vid, keys[i].pk.as_slice(), keys[i].sk.as_slice())
    }

    #[test]
    fn ypx021_unhealthy_oods_view_blocks_checkpoint_advance() {
        // YPX-021 §8.2 wash-out gate: a wallet whose latest receipt was
        // stamped under an eclipsed view (`healthy = false`) must not make
        // ANY compression progress — no proposal, no co-sign, no finalize.
        // FAILS without the `oods_view_healthy` gate in advance_fact_checkpoint.
        let keys = test_keys();
        let mut chain = make_chain(&keys, &vec![true; 10]); // 10 resolved links
        let (vid, pk, sk) = validator_i(&keys, 0);

        // Unhealthy view → nothing happens.
        advance_fact_checkpoint(&mut chain, vid, pk, sk, false).unwrap();
        assert!(chain.checkpoint.is_none(), "unhealthy view must not PROPOSE");
        assert_eq!(chain.links.len(), 10, "no links may be touched");

        // Same chain, healthy view → proposes normally (control).
        advance_fact_checkpoint(&mut chain, vid, pk, sk, true).unwrap();
        assert!(chain.checkpoint.is_some(), "healthy view proposes");

        // A provisional proposal must also not advance under an unhealthy view.
        let (vid2, pk2, sk2) = validator_i(&keys, 1);
        let sigs_before = chain.checkpoint.as_ref().unwrap().validator_sigs.len();
        advance_fact_checkpoint(&mut chain, vid2, pk2, sk2, false).unwrap();
        assert_eq!(
            chain.checkpoint.as_ref().unwrap().validator_sigs.len(),
            sigs_before,
            "unhealthy view must not CO-SIGN"
        );
    }

    #[test]
    fn test_sec07_advance_propose_retains_links_one_sig() {
        // First validator to see a depth>=7 chain PROPOSES: writes the checkpoint,
        // signs once, and KEEPS the covered links (provisional). Verify passes
        // because the real links are still present.
        let keys = test_keys();
        let mut chain = make_chain(&keys, &vec![true; 10]); // 10 resolved links
        let (vid, pk, sk) = validator_i(&keys, 0);
        advance_fact_checkpoint(&mut chain, vid, pk, sk, true).unwrap();

        let cp = chain.checkpoint.as_ref().expect("proposal created");
        assert!(cp.pending_links > 0, "provisional: links retained");
        assert_eq!(cp.validator_sigs.len(), 1, "proposer signs once");
        // covered links still physically present (10 links, none deleted yet)
        assert_eq!(chain.links.len(), 10);
        // and the chain still verifies (through the real links, no k=5 gate yet)
        assert!(verify_fact_chain(&chain).is_ok(), "provisional chain must verify");
    }

    #[test]
    fn test_sec07_advance_accumulates_then_finalizes_at_threshold() {
        // CHECKPOINT_SIG_THRESHOLD DISTINCT validators advance the proposal in turn;
        // the threshold-th finalizes (deletes the covered links). Below threshold it
        // stays provisional with the covered links intact.
        let keys = test_keys();
        let mut chain = make_chain(&keys, &vec![true; 10]);
        for i in 0..(CHECKPOINT_SIG_THRESHOLD - 1) {
            let (vid, pk, sk) = validator_i(&keys, i);
            advance_fact_checkpoint(&mut chain, vid, pk, sk, true).unwrap();
            let cp = chain.checkpoint.as_ref().unwrap();
            assert_eq!(cp.validator_sigs.len(), i + 1);
            assert!(cp.pending_links > 0, "still provisional below threshold");
            assert_eq!(chain.links.len(), 10, "no links deleted below threshold");
            assert!(verify_fact_chain(&chain).is_ok());
        }
        // threshold-th distinct validator → finalize.
        let (vid, pk, sk) = validator_i(&keys, CHECKPOINT_SIG_THRESHOLD - 1);
        advance_fact_checkpoint(&mut chain, vid, pk, sk, true).unwrap();
        let cp = chain.checkpoint.as_ref().unwrap();
        assert_eq!(cp.validator_sigs.len(), CHECKPOINT_SIG_THRESHOLD);
        assert_eq!(cp.pending_links, 0, "finalized: links deleted");
        assert_eq!(chain.links.len(), FACT_KEEP, "kept FACT_KEEP tail, dropped covered");
        assert!(verify_fact_chain(&chain).is_ok(), "finalized threshold-sig checkpoint verifies");
    }

    #[test]
    fn test_sec07_advance_dedup_same_validator() {
        // The same validator advancing twice must NOT add a second signature.
        let keys = test_keys();
        let mut chain = make_chain(&keys, &vec![true; 10]);
        let (vid, pk, sk) = validator_i(&keys, 0);
        advance_fact_checkpoint(&mut chain, vid, pk, sk, true).unwrap();
        advance_fact_checkpoint(&mut chain, vid, pk, sk, true).unwrap();
        assert_eq!(chain.checkpoint.as_ref().unwrap().validator_sigs.len(), 1,
            "same validator can't sign the same proposal twice");
    }

    #[test]
    fn test_sec07_finalized_below_threshold_rejected() {
        // A FINALIZED checkpoint (links deleted) with < CHECKPOINT_SIG_THRESHOLD sigs
        // is the SEC-07 forge — too few validators could claim false provenance.
        // Must be rejected. Use threshold-1 distinct sigs.
        let keys = test_keys();
        let chain = make_chain(&keys, &vec![true; 10]);
        // compress_fact_chain DRAINS immediately → finalized checkpoint.
        let under = CHECKPOINT_SIG_THRESHOLD - 1;
        let validators: Vec<([u8;32],&[u8],&[u8])> = (0..under).map(|i| validator_i(&keys, i)).collect();
        let compressed = compress_fact_chain(chain, &validators).unwrap();
        assert_eq!(compressed.checkpoint.as_ref().unwrap().pending_links, 0);
        assert_eq!(compressed.checkpoint.as_ref().unwrap().validator_sigs.len(), under);
        assert!(matches!(verify_fact_chain(&compressed),
            Err(ValidationError::FactInsufficientWitnesses)),
            "finalized checkpoint below CHECKPOINT_SIG_THRESHOLD sigs must be rejected");
    }

    #[test]
    fn test_sec07_finalized_5_sigs_accepted() {
        // Finalized with 5 distinct sigs verifies.
        let keys = test_keys();
        let chain = make_chain(&keys, &vec![true; 10]);
        let validators: Vec<([u8;32],&[u8],&[u8])> = (0..5).map(|i| validator_i(&keys, i)).collect();
        let compressed = compress_fact_chain(chain, &validators).unwrap();
        assert_eq!(compressed.checkpoint.as_ref().unwrap().validator_sigs.len(), 5);
        assert!(verify_fact_chain(&compressed).is_ok());
    }

    #[test]
    fn test_sec07_finalized_duplicate_validator_rejected() {
        // 5 valid sigs that share a validator_id → forgeable by one validator.
        let keys = test_keys();
        let chain = make_chain(&keys, &vec![true; 10]);
        let validators: Vec<([u8;32],&[u8],&[u8])> = (0..5).map(|i| validator_i(&keys, i)).collect();
        let mut compressed = compress_fact_chain(chain, &validators).unwrap();
        let sig0 = compressed.checkpoint.as_ref().unwrap().validator_sigs[0].clone();
        compressed.checkpoint.as_mut().unwrap().validator_sigs = vec![sig0.clone(); 5];
        assert!(matches!(verify_fact_chain(&compressed),
            Err(ValidationError::FactDuplicateWitness)),
            "finalized checkpoint with duplicate validator_id must be rejected");
    }

    #[test]
    fn test_sec07_forged_pending_links_rejected() {
        // A provisional checkpoint whose retained links don't hash to root_hash
        // (forged pending_links or tampered covered links) must be rejected.
        let keys = test_keys();
        let mut chain = make_chain(&keys, &vec![true; 10]);
        let (vid, pk, sk) = validator_i(&keys, 0);
        advance_fact_checkpoint(&mut chain, vid, pk, sk, true).unwrap();
        assert!(verify_fact_chain(&chain).is_ok());
        // Tamper: claim the checkpoint covers a different number of leading links.
        let real = chain.checkpoint.as_ref().unwrap().pending_links;
        chain.checkpoint.as_mut().unwrap().pending_links = real + 1;
        assert!(verify_fact_chain(&chain).is_err(),
            "mismatched pending_links vs root_hash must be rejected");
    }

    #[test]
    fn test_sec07_provisional_verifies_with_few_sigs() {
        // Explicitly: a provisional checkpoint with only 2 sigs still verifies,
        // because the covered links are present and self-verify. No deadlock.
        let keys = test_keys();
        let mut chain = make_chain(&keys, &vec![true; 10]);
        advance_fact_checkpoint(&mut chain, validator_i(&keys,0).0, validator_i(&keys,0).1, validator_i(&keys,0).2, true).unwrap();
        advance_fact_checkpoint(&mut chain, validator_i(&keys,1).0, validator_i(&keys,1).1, validator_i(&keys,1).2, true).unwrap();
        let cp = chain.checkpoint.as_ref().unwrap();
        assert_eq!(cp.validator_sigs.len(), 2);
        assert!(cp.pending_links > 0);
        assert!(verify_fact_chain(&chain).is_ok(),
            "2-sig provisional checkpoint verifies (links present) — no deadlock");
    }

    #[test]
    fn test_sec07_pending_stub_matches_compress() {
        // Drift guard: the stub advance signs must hash to the same commitment as
        // the checkpoint compress_fact_chain builds.
        let keys = test_keys();
        let chain = make_chain(&keys, &vec![true; 10]);
        let stub = compute_pending_checkpoint_stub(&chain).unwrap().unwrap();
        let stub_commitment = compute_checkpoint_commitment(&stub);
        let validators: Vec<([u8;32],&[u8],&[u8])> = (0..5).map(|i| validator_i(&keys, i)).collect();
        let compressed = compress_fact_chain(chain, &validators).unwrap();
        let real = compute_checkpoint_commitment(compressed.checkpoint.as_ref().unwrap());
        assert_eq!(stub_commitment, real,
            "advance's signed commitment must equal compress_fact_chain's checkpoint");
    }

    fn redeem_stub_cheque(sender_fact_chain: Option<FactChain>) -> crate::types::ValidatorCheque {
        crate::types::ValidatorCheque {
            recall_target_tx_id: None,
            txid: [0u8; 32],
            validator_id: [1u8; 32],
            validator_pk: vec![0u8; 32],
            signature: vec![],
            execution_proof: vec![1u8],
            vbc_bundle: None,
            carrier_type: String::new(),
            carrier_address: String::new(),
            sender_wallet_id: String::new(),
            receiver_wallet_id: String::new(),
            amount: 0,
            rate_bps: 10,
            reference: String::new(),
            epoch: 0,
            created_at: 0,
            state_hash: [0u8; 32],
            produced_state_id: [0u8; 32],
            sender_fact_chain,
            zkp_nonce: None,
            proof_type: 1,
            dmap_input_hash: [0u8; 32],
            dmap_output_hash: [0u8; 32],
            oracle_claim: None,
            nabla_hint: None,
            sender_wallet_pk: None,
        }
    }

    #[test]
    fn redeem_fact_chain_ref_follows_core_cl5_priority() {
        let keys = test_keys();
        let on_cheque = FactChain {
            checkpoint: None,
            links: vec![make_test_link([9u8; 32], [0u8; 32], [0xEEu8; 32], 1, &keys)],
        };
        let from_lambda_fallback = FactChain {
            checkpoint: None,
            links: vec![make_test_link([8u8; 32], [0u8; 32], [0xDDu8; 32], 1, &keys)],
        };

        let bundle = ChequeBundle {
            cheques: vec![redeem_stub_cheque(Some(on_cheque.clone()))],
            fact_chain: None,
        };

        assert_eq!(
            redeem_fact_sender_anchor(&bundle, &Some(from_lambda_fallback.clone())),
            Some([0xEEu8; 32]),
            "tier 2 — cheque.sender_fact_chain must win over Lambda fallback",
        );

        let bundle_outer = ChequeBundle {
            cheques: vec![redeem_stub_cheque(None)],
            fact_chain: Some(from_lambda_fallback.clone()),
        };

        assert_eq!(
            redeem_fact_sender_anchor(&bundle_outer, &Some(on_cheque)),
            Some([0xDDu8; 32]),
            "tier 1 — bundle.fact_chain must win over inputs fallback",
        );
    }

    /// Round-trip a FactChain through ciborium without mutation.
    ///
    /// Lambda emits chain bytes via ciborium::into_writer. The SDK reads them
    /// via ciborium::from_reader. If serialization is byte-deterministic, a
    /// pure encode→decode→encode produces bytes identical to the first encode,
    /// and verify_fact_link still passes on the decoded chain.
    ///
    /// If THIS fails, the bug is in struct-level (de)serialization — there is
    /// no mutation involved.
    #[test]
    fn test_factchain_pure_roundtrip_preserves_bytes_and_verify() {
        let keys = test_keys();
        let link = make_test_link([7u8; 32], [0u8; 32], [42u8; 32], 1000, &keys);
        let chain = FactChain { checkpoint: None, links: vec![link.clone()] };

        let mut bytes_a = Vec::new();
        ciborium::into_writer(&chain, &mut bytes_a).expect("encode A");

        let chain_decoded: FactChain = ciborium::from_reader(&bytes_a[..]).expect("decode");

        let mut bytes_b = Vec::new();
        ciborium::into_writer(&chain_decoded, &mut bytes_b).expect("encode B");

        assert_eq!(
            bytes_a, bytes_b,
            "pure round-trip MUST be byte-deterministic; differs at len(a)={} len(b)={}",
            bytes_a.len(), bytes_b.len()
        );

        verify_fact_link(&chain_decoded.links[0])
            .expect("decoded link must still verify");
    }

    /// Round-trip a FactChain through ciborium::Value (the SDK's
    /// update_fact_chain_confirmation path) using a REAL Ed25519-signed
    /// NablaConfirmation. Mirrors what the SDK does in production after a
    /// /register response from a Nabla node.
    ///
    /// The SDK reads chain bytes as Value::Map, replaces the
    /// `nabla_confirmation` value in-place on the last link, then re-emits.
    /// nabla_confirmation is NOT in compute_fact_commitment, so the
    /// recomputed Dilithium commitment is unchanged. The Nabla
    /// confirmation's Ed25519 signature is over a different payload
    /// (AXIOM_FACT_CONFIRM domain), built from prev/new state. If
    /// verify_fact_link fails after this round-trip, ciborium Value→typed
    /// deserialization is mangling either the link's commitment-input bytes,
    /// the witness signature/pk bytes, or the conf's nabla_signature/node_id
    /// bytes (e.g., Value::Bytes vs serde-default Vec<u8>=Array<Integer>).
    #[test]
    fn test_factchain_value_roundtrip_with_real_nabla_mutation_preserves_verify() {
        use ciborium::Value;
        use ed25519_dalek::{SigningKey, Signer};

        let keys = test_keys();
        let link = make_test_link([7u8; 32], [0u8; 32], [42u8; 32], 1000, &keys);
        let chain = FactChain { checkpoint: None, links: vec![link.clone()] };

        // Build a REAL Ed25519 keypair for the Nabla node
        let nabla_sk = SigningKey::from_bytes(&[7u8; 32]);
        let nabla_pk_bytes: [u8; 32] = nabla_sk.verifying_key().to_bytes();

        // Compute the Ed25519 payload exactly as verify_fact_link does
        // (V2 — includes committed_at_tick; test uses 0).
        let committed_at_tick: u64 = 0;
        let tx_hash = {
            let mut h = blake3::Hasher::new();
            h.update(b"AXIOM_TXHASH");
            h.update(&link.previous_state_id);
            h.update(&link.new_state_id);
            *h.finalize().as_bytes()
        };
        let payload = {
            let mut h = blake3::Hasher::new();
            h.update(b"AXIOM_FACT_CONFIRM_V2");
            h.update(&tx_hash);
            h.update(&link.new_state_id);
            h.update(&committed_at_tick.to_le_bytes());
            *h.finalize().as_bytes()
        };
        let nabla_sig_bytes: [u8; 64] = nabla_sk.sign(&payload).to_bytes();

        // Encode chain → CBOR bytes (Lambda side)
        let mut chain_bytes = Vec::new();
        ciborium::into_writer(&chain, &mut chain_bytes).expect("encode chain");

        // Decode as Value (SDK side)
        let mut value: Value = ciborium::from_reader(&chain_bytes[..]).expect("decode value");

        // Construct a NablaConfirmation Value EXACTLY the way the SDK does
        // it in update_fact_chain_confirmation (sdk/client/src/nabla.rs:678-683):
        // bytes fields wrapped in Value::Bytes (CBOR major type 2).
        let conf = Value::Map(vec![
            (Value::Text("nabla_node_id".into()), Value::Bytes(nabla_pk_bytes.to_vec())),
            (Value::Text("nabla_signature".into()), Value::Bytes(nabla_sig_bytes.to_vec())),
            (Value::Text("root_hash".into()), Value::Bytes(vec![0u8; 32])),
            (Value::Text("synced_to_tick".into()), Value::Integer(0.into())),
            (Value::Text("committed_at_tick".into()), Value::Integer(committed_at_tick.into())),
        ]);

        // Walk into chain.links[last].nabla_confirmation and replace null
        // (mirrors update_fact_chain_confirmation in sdk/client/src/nabla.rs)
        if let Value::Map(ref mut pairs) = value {
            for (k, v) in pairs.iter_mut() {
                if k.as_text() == Some("links") {
                    if let Value::Array(ref mut links) = v {
                        if let Some(last) = links.last_mut() {
                            if let Value::Map(ref mut link_pairs) = last {
                                let mut replaced = false;
                                for (lk, lv) in link_pairs.iter_mut() {
                                    if lk.as_text() == Some("nabla_confirmation") {
                                        *lv = conf.clone();
                                        replaced = true;
                                        break;
                                    }
                                }
                                if !replaced {
                                    link_pairs.push((
                                        Value::Text("nabla_confirmation".into()),
                                        conf.clone(),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        // Re-encode the mutated Value back to CBOR
        let mut mutated_bytes = Vec::new();
        ciborium::into_writer(&value, &mut mutated_bytes).expect("re-encode mutated");

        // Decode back into a typed FactChain (Lambda side after SDK mutation)
        let chain_after: FactChain = ciborium::from_reader(&mutated_bytes[..])
            .expect("decode mutated bytes back to FactChain");

        let link_after = &chain_after.links[0];

        // Fields in compute_fact_commitment must be untouched
        assert_eq!(link_after.tx_id, link.tx_id, "tx_id mutated");
        assert_eq!(link_after.previous_state_id, link.previous_state_id, "prev_state_id mutated");
        assert_eq!(link_after.new_state_id, link.new_state_id, "new_state_id mutated");
        assert_eq!(link_after.amount, link.amount, "amount mutated");
        assert_eq!(link_after.sender_anchor, link.sender_anchor, "sender_anchor mutated");

        // Witnesses must be untouched
        assert_eq!(link_after.witnesses.len(), link.witnesses.len(), "witness count");
        for (i, (a, b)) in link_after.witnesses.iter().zip(link.witnesses.iter()).enumerate() {
            assert_eq!(a.validator_id, b.validator_id, "witness[{}] validator_id", i);
            assert_eq!(a.validator_pk, b.validator_pk, "witness[{}] validator_pk", i);
            assert_eq!(a.signature, b.signature, "witness[{}] signature", i);
        }

        // The mutation succeeded — confirmation is now Some
        assert!(link_after.nabla_confirmation.is_some(),
                "nabla_confirmation should be Some after mutation");

        // The conf bytes must round-trip exactly so Ed25519 verify passes.
        let conf_after = link_after.nabla_confirmation.as_ref().unwrap();
        assert_eq!(conf_after.nabla_node_id, nabla_pk_bytes,
                   "nabla_node_id round-trip mismatch (Bytes→[u8;32] mangled?)");
        assert_eq!(conf_after.nabla_signature.as_slice(), &nabla_sig_bytes[..],
                   "nabla_signature round-trip mismatch (Bytes→Vec<u8> mangled?)");

        // verify_fact_link MUST still pass — this is the core invariant
        verify_fact_link(link_after).expect(
            "verify_fact_link must pass after Value-roundtrip with nabla_confirmation mutation; \
             if this fails, ciborium Value→typed round-trip mangles a byte field"
        );
    }

    /// Multi-link chain mutation: only the last link gets a fresh
    /// nabla_confirmation. Earlier links must remain byte-exact (their
    /// witness Dilithium sigs must still verify). Mirrors what happens in
    /// the SDK: each /register acks one link at a time, and the chain may
    /// already have N-1 links from prior TXs.
    #[test]
    fn test_factchain_value_roundtrip_multilink_only_last_mutated() {
        use ciborium::Value;
        use ed25519_dalek::{SigningKey, Signer};

        let keys = test_keys();
        let link1 = make_test_link([1u8; 32], [0u8; 32], [2u8; 32], 1000, &keys);
        let link2 = make_test_link([3u8; 32], [2u8; 32], [4u8; 32], 500, &keys);
        let link3 = make_test_link([5u8; 32], [4u8; 32], [6u8; 32], 250, &keys);
        let chain = FactChain {
            checkpoint: None,
            links: vec![link1.clone(), link2.clone(), link3.clone()],
        };

        let nabla_sk = SigningKey::from_bytes(&[7u8; 32]);
        let nabla_pk_bytes: [u8; 32] = nabla_sk.verifying_key().to_bytes();
        let committed_at_tick: u64 = 0;
        let payload = {
            let tx_hash = {
                let mut h = blake3::Hasher::new();
                h.update(b"AXIOM_TXHASH");
                h.update(&link3.previous_state_id);
                h.update(&link3.new_state_id);
                *h.finalize().as_bytes()
            };
            let mut h = blake3::Hasher::new();
            h.update(b"AXIOM_FACT_CONFIRM_V2");
            h.update(&tx_hash);
            h.update(&link3.new_state_id);
            h.update(&committed_at_tick.to_le_bytes());
            *h.finalize().as_bytes()
        };
        let nabla_sig_bytes: [u8; 64] = nabla_sk.sign(&payload).to_bytes();

        let mut chain_bytes = Vec::new();
        ciborium::into_writer(&chain, &mut chain_bytes).expect("encode chain");
        let mut value: Value = ciborium::from_reader(&chain_bytes[..]).expect("decode value");

        let conf = Value::Map(vec![
            (Value::Text("nabla_node_id".into()), Value::Bytes(nabla_pk_bytes.to_vec())),
            (Value::Text("nabla_signature".into()), Value::Bytes(nabla_sig_bytes.to_vec())),
            (Value::Text("root_hash".into()), Value::Bytes(vec![0u8; 32])),
            (Value::Text("synced_to_tick".into()), Value::Integer(0.into())),
            (Value::Text("committed_at_tick".into()), Value::Integer(committed_at_tick.into())),
        ]);

        if let Value::Map(ref mut pairs) = value {
            for (k, v) in pairs.iter_mut() {
                if k.as_text() == Some("links") {
                    if let Value::Array(ref mut links) = v {
                        if let Some(last) = links.last_mut() {
                            if let Value::Map(ref mut link_pairs) = last {
                                let mut replaced = false;
                                for (lk, lv) in link_pairs.iter_mut() {
                                    if lk.as_text() == Some("nabla_confirmation") {
                                        *lv = conf.clone();
                                        replaced = true;
                                        break;
                                    }
                                }
                                if !replaced {
                                    link_pairs.push((
                                        Value::Text("nabla_confirmation".into()),
                                        conf.clone(),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut mutated_bytes = Vec::new();
        ciborium::into_writer(&value, &mut mutated_bytes).expect("re-encode mutated");
        let chain_after: FactChain = ciborium::from_reader(&mutated_bytes[..])
            .expect("decode mutated bytes");

        assert_eq!(chain_after.links.len(), 3);
        // Earlier links must still verify (signatures unchanged)
        verify_fact_link(&chain_after.links[0]).expect("link[0] verify");
        verify_fact_link(&chain_after.links[1]).expect("link[1] verify");
        // Last link must verify with confirmation now attached
        verify_fact_link(&chain_after.links[2]).expect("link[2] verify");
        assert!(chain_after.links[0].nabla_confirmation.is_none(), "link[0] still scarred");
        assert!(chain_after.links[1].nabla_confirmation.is_none(), "link[1] still scarred");
        assert!(chain_after.links[2].nabla_confirmation.is_some(), "link[2] healed");
    }

    /// Redeem-link round-trip: link with `sender_anchor: Some([u8;32])`
    /// (which IS in the FACT commitment hash). Tests that Option<[u8;32]>
    /// round-trips correctly through Value::Bytes / Value::Array and
    /// witness sigs still verify.
    #[test]
    fn test_factchain_value_roundtrip_redeem_link_with_sender_anchor() {
        use ciborium::Value;

        let keys = test_keys();
        let tx_id: [u8; 32] = [11u8; 32];
        let prev: [u8; 32] = [22u8; 32];
        let new: [u8; 32] = [33u8; 32];
        let amount = 7000u64;
        let anchor: [u8; 32] = [99u8; 32];

        // Sign WITH sender_anchor as part of the commitment
        let commitment = compute_fact_commitment(&tx_id, &prev, &new, amount, Some(&anchor), false, &[]);
        let mut witnesses = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let sig = crate::crypto::sign_dilithium(&key.sk, &commitment).expect("sign");
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            witnesses.push(FactWitness {
                validator_id: vid,
                validator_pk: key.pk.clone(),
                signature: sig,
                vbc_genesis_anchor: None,
            });
        }
        let link = FactLink {
            tx_id,
            previous_state_id: prev,
            new_state_id: new,
            amount,
            required_k: 4,
            tick: 0,
            witnesses,
            nabla_confirmation: None,
            receiver_contact: None,
            burn_proof: None,
            sender_anchor: Some(anchor),
            is_dev_class: false,
            recall_proof: None,
            inherited_scar_txids: Vec::new(),
            inherited_scar_resolutions: Vec::new(),
        };
        verify_fact_link(&link).expect("pre-roundtrip redeem link must verify");

        let chain = FactChain { checkpoint: None, links: vec![link.clone()] };
        let mut chain_bytes = Vec::new();
        ciborium::into_writer(&chain, &mut chain_bytes).expect("encode");

        // Pure round-trip without mutation
        let chain_decoded: FactChain = ciborium::from_reader(&chain_bytes[..]).expect("decode");
        assert_eq!(chain_decoded.links[0].sender_anchor, Some(anchor),
                   "sender_anchor must round-trip exactly");
        verify_fact_link(&chain_decoded.links[0])
            .expect("redeem link with sender_anchor must verify after pure round-trip");

        // Round-trip via Value
        let value: Value = ciborium::from_reader(&chain_bytes[..]).expect("decode value");
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf).expect("re-encode value");
        let chain_after: FactChain = ciborium::from_reader(&buf[..]).expect("decode after value");
        assert_eq!(chain_after.links[0].sender_anchor, Some(anchor),
                   "sender_anchor must survive Value round-trip");
        verify_fact_link(&chain_after.links[0])
            .expect("redeem link with sender_anchor must verify after Value round-trip");
    }

    /// FACT chain class lock — sticky invariant
    /// (`AXIOM_DESIGN_FactChainClassLock.md`).
    ///
    /// `verify_fact_chain` must reject a chain whose links cross a
    /// class boundary. Catches the case where a chain was constructed
    /// by concatenating links from two different-class wallets, or
    /// where an attacker flipped `is_dev_class` on a single link.
    #[test]
    fn fact_chain_class_break_rejected() {
        let keys = test_keys();

        // Build link 0 (genesis-equivalent) with is_dev_class=true.
        let tx0: [u8; 32] = [0xA0; 32];
        let prev0: [u8; 32] = [0x00; 32];
        let new0: [u8; 32] = [0xA1; 32];
        let amount = 1000u64;
        let commit0 = compute_fact_commitment(&tx0, &prev0, &new0, amount, None, true, &[]);
        let mut wits0 = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let sig = crate::crypto::sign_dilithium(&key.sk, &commit0).expect("sign 0");
            let mut vid = [0u8; 32]; vid[0] = i as u8;
            wits0.push(FactWitness {
                validator_id: vid,
                validator_pk: key.pk.clone(),
                signature: sig,
                vbc_genesis_anchor: None,
            });
        }
        let link0 = FactLink {
            tx_id: tx0,
            previous_state_id: prev0,
            new_state_id: new0,
            amount, required_k: 3, tick: 0,
            witnesses: wits0,
            nabla_confirmation: None,
            receiver_contact: None, burn_proof: None,
            sender_anchor: None,
            is_dev_class: true,
            recall_proof: None,
            inherited_scar_txids: Vec::new(),
            inherited_scar_resolutions: Vec::new(),
        };

        // Build link 1 chained from link 0's tip but with is_dev_class=FALSE
        // (the attack — a class boundary crossed mid-chain).
        let tx1: [u8; 32] = [0xB0; 32];
        let new1: [u8; 32] = [0xB1; 32];
        let commit1 = compute_fact_commitment(&tx1, &new0, &new1, amount, None, false, &[]);
        let mut wits1 = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let sig = crate::crypto::sign_dilithium(&key.sk, &commit1).expect("sign 1");
            let mut vid = [0u8; 32]; vid[0] = (i + 4) as u8;
            wits1.push(FactWitness {
                validator_id: vid,
                validator_pk: key.pk.clone(),
                signature: sig,
                vbc_genesis_anchor: None,
            });
        }
        let link1 = FactLink {
            tx_id: tx1,
            previous_state_id: new0,
            new_state_id: new1,
            amount, required_k: 3, tick: 0,
            witnesses: wits1,
            nabla_confirmation: None,
            receiver_contact: None, burn_proof: None,
            sender_anchor: None,
            is_dev_class: false,
            recall_proof: None,
            inherited_scar_txids: Vec::new(),
            inherited_scar_resolutions: Vec::new(),
        };

        let chain = FactChain { checkpoint: None, links: vec![link0, link1] };
        let result = verify_fact_chain(&chain);
        assert!(
            matches!(result, Err(crate::types::ValidationError::DomainMismatch)),
            "chain whose links cross class boundary MUST reject — got {:?}",
            result,
        );
    }

    /// `build_fact_link` rejects an attempt to append a link with
    /// `is_dev_class` differing from the existing chain's tip. The
    /// rejection happens BEFORE any Dilithium signing — same
    /// `DomainMismatch` error code as `verify_fact_chain` so callers
    /// don't have to distinguish the two paths.
    #[test]
    fn fact_chain_build_rejects_class_mismatch_with_existing() {
        let keys = test_keys();

        // Existing chain has is_dev_class=true at its tip.
        let tx_tip: [u8; 32] = [0xCC; 32];
        let new_tip: [u8; 32] = [0xCD; 32];
        let amount = 500u64;
        let commit = compute_fact_commitment(&tx_tip, &[0u8; 32], &new_tip, amount, None, true, &[]);
        let mut wits = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let sig = crate::crypto::sign_dilithium(&key.sk, &commit).expect("sign tip");
            let mut vid = [0u8; 32]; vid[0] = i as u8;
            wits.push(FactWitness {
                validator_id: vid,
                validator_pk: key.pk.clone(),
                signature: sig,
                vbc_genesis_anchor: None,
            });
        }
        let tip_link = FactLink {
            tx_id: tx_tip,
            previous_state_id: [0u8; 32],
            new_state_id: new_tip,
            amount, required_k: 3, tick: 0,
            witnesses: wits,
            nabla_confirmation: None,
            receiver_contact: None, burn_proof: None,
            sender_anchor: None,
            is_dev_class: true,
            recall_proof: None,
            inherited_scar_txids: Vec::new(),
            inherited_scar_resolutions: Vec::new(),
        };
        let existing = FactChain { checkpoint: None, links: vec![tip_link] };

        // Try to append a link with is_dev_class=false. Build the
        // witness sigs for the NEW link's commitment (so verify_dilithium
        // succeeds and we hit the sticky-class check, not the sig check).
        let tx_new: [u8; 32] = [0xDD; 32];
        let new_new: [u8; 32] = [0xDE; 32];
        let new_commit = compute_fact_commitment(&tx_new, &new_tip, &new_new, amount, None, false, &[]);
        let witness_sigs: Vec<crate::types::WitnessSig> = keys.iter().enumerate().map(|(i, key)| {
            let mut vid = [0u8; 32]; vid[0] = (i + 8) as u8;
            crate::types::WitnessSig {
                validator_id: vid,
                validator_pk: key.pk.clone(),
                signature: vec![0u8; 64],
                execution_proof: vec![],
                proof_type: 0,
                availability_attestation: None,
                carrier_type: "test".to_string(),
                carrier_address: "t".to_string(),
                vbc_bundle: Some(crate::types::VBCProofBundle {
                    target_vbc: crate::types::VBC {
                        network_size_baseline: 0,
                        baseline_tick: 0,
                        version: 9,
                        validator_id: vid,
                        subject_pubkey_dilithium: key.pk.clone(),
                        subject_pubkey_ed25519: vec![0u8; 32],
                        subject_pubkey_sphincs: vec![0u8; 32],
                        pgp_fingerprint: vec![],
                        node_name: "t".into(),
                        proof_cap: "dmap".into(),
                        issued_at: 0, expires_at: u64::MAX,
                        chain_depth: 0,
                        issuer_set: vec![],
                        signatures: vec![],
                        max_tx: 50000,
                        founding_vbc_hash: [0u8; 32],
                    },
                    supporting_vbcs: vec![],
                }),
                fact_signature: Some(crate::crypto::sign_dilithium(&key.sk, &new_commit).expect("dilithium sign")),
                checkpoint_sig: None,
                receipt_signature: None,
                receipt_commitment_sig: None,
                validator_hints: vec![],
                rate_bps: 0,
                slot_amount: 0,
            }
        }).collect();

        let result = build_fact_link(
            &tx_new, &new_tip, &new_new, amount, 3,
            &witness_sigs, None, None, None,
            /* is_dev_class = */ false,  // ← the mismatch
            Vec::new(),
            Some(&existing),
            None, None,
        );

        assert!(
            matches!(result, Err(crate::types::ValidationError::DomainMismatch)),
            "appending a class-mismatched link to existing chain MUST \
             reject with DomainMismatch — got {:?}",
            result,
        );
    }

    /// uj-class repro (2026-06-08): `build_fact_link` MUST reject when
    /// the caller-supplied `previous_state_id` doesn't match the
    /// existing chain's tip `new_state_id`. The bug this test pins:
    /// pre-2026-06-08 Core stamped the caller's `previous_state_id`
    /// without ever cross-checking the existing chain, so a Lambda
    /// caller fed a stale value (the SDK's wallet.state_id drifted
    /// from chain.tip.new_state_id) would have Core compose a
    /// structurally-broken chain; k validators would happily sign
    /// it (the per-link commitment is over the link's own bytes,
    /// which validate); the chain would persist; the next outbound
    /// send would fail at verify_fact_chain's read-side check; the
    /// wallet would be locked. uj wallet snapshot is at
    /// `~/AXIOM_DEV/TTTTTT-normal.zip`.
    ///
    /// Reject must fire BEFORE any Dilithium signing — the witness
    /// sigs in this fixture are over the NEW link's commitment (so
    /// signature verification would succeed if reached). If the
    /// reject ever moves *after* sig verification, this test still
    /// passes structurally but the build path wastes ~30ms per
    /// validator on doomed Dilithium work.
    #[test]
    fn fact_chain_build_rejects_continuity_break_with_existing() {
        let keys = test_keys();

        // Existing chain: a single link whose new_state_id = REAL_TIP.
        let tx_tip: [u8; 32] = [0xAA; 32];
        let real_tip: [u8; 32] = [0xAB; 32];
        let amount = 500u64;
        let commit = compute_fact_commitment(&tx_tip, &[0u8; 32], &real_tip, amount, None, false, &[]);
        let mut wits = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let sig = crate::crypto::sign_dilithium(&key.sk, &commit).expect("sign tip");
            let mut vid = [0u8; 32]; vid[0] = i as u8;
            wits.push(FactWitness {
                validator_id: vid,
                validator_pk: key.pk.clone(),
                signature: sig,
                vbc_genesis_anchor: None,
            });
        }
        let tip_link = FactLink {
            tx_id: tx_tip,
            previous_state_id: [0u8; 32],
            new_state_id: real_tip,
            amount, required_k: 3, tick: 0,
            witnesses: wits,
            nabla_confirmation: None,
            receiver_contact: None, burn_proof: None,
            sender_anchor: None,
            is_dev_class: false,
            recall_proof: None,
            inherited_scar_txids: Vec::new(),
            inherited_scar_resolutions: Vec::new(),
        };
        let existing = FactChain { checkpoint: None, links: vec![tip_link] };

        // Build a new link with a STALE previous_state_id — the
        // exact shape of the uj corruption (the SDK's wallet.state_id
        // drifted from chain.tip.new_state_id and shipped the stale
        // value as previous_state_id).
        let tx_new: [u8; 32] = [0xCC; 32];
        let stale_prev: [u8; 32] = [0xDE; 32];   // ← NOT real_tip
        let new_new: [u8; 32] = [0xCD; 32];
        let new_commit = compute_fact_commitment(&tx_new, &stale_prev, &new_new, amount, None, false, &[]);
        let witness_sigs: Vec<crate::types::WitnessSig> = keys.iter().enumerate().map(|(i, key)| {
            let mut vid = [0u8; 32]; vid[0] = (i + 8) as u8;
            crate::types::WitnessSig {
                validator_id: vid,
                validator_pk: key.pk.clone(),
                signature: vec![0u8; 64],
                execution_proof: vec![],
                proof_type: 0,
                availability_attestation: None,
                carrier_type: "test".to_string(),
                carrier_address: "t".to_string(),
                vbc_bundle: Some(crate::types::VBCProofBundle {
                    target_vbc: crate::types::VBC {
                        network_size_baseline: 0,
                        baseline_tick: 0,
                        version: 9,
                        validator_id: vid,
                        subject_pubkey_dilithium: key.pk.clone(),
                        subject_pubkey_ed25519: vec![0u8; 32],
                        subject_pubkey_sphincs: vec![0u8; 32],
                        pgp_fingerprint: vec![],
                        node_name: "t".into(),
                        proof_cap: "dmap".into(),
                        issued_at: 0, expires_at: u64::MAX,
                        chain_depth: 0,
                        issuer_set: vec![],
                        signatures: vec![],
                        max_tx: 50000,
                        founding_vbc_hash: [0u8; 32],
                    },
                    supporting_vbcs: vec![],
                }),
                fact_signature: Some(crate::crypto::sign_dilithium(&key.sk, &new_commit).expect("dilithium sign")),
                checkpoint_sig: None,
                receipt_signature: None,
                receipt_commitment_sig: None,
                validator_hints: vec![],
                rate_bps: 0,
                slot_amount: 0,
            }
        }).collect();

        let result = build_fact_link(
            &tx_new, &stale_prev, &new_new, amount, 3,
            &witness_sigs, None, None, None,
            /* is_dev_class = */ false,
            Vec::new(),
            Some(&existing),
            None, None,
        );

        assert!(
            matches!(result, Err(crate::types::ValidationError::FactChainBreak)),
            "appending a link whose previous_state_id ≠ existing chain's tip.new_state_id \
             MUST reject with FactChainBreak BEFORE any signing — got {:?}",
            result,
        );
    }

    /// Empty existing chain + caller's `previous_state_id` is the
    /// genesis anchor — must succeed (no tip to check against).
    /// Regression check: the new continuity gate must not regress
    /// the legitimate "no chain yet" path that every first send /
    /// fund_genesis exercises.
    #[test]
    fn fact_chain_build_allows_first_link_no_existing_chain() {
        let keys = test_keys();
        let tx_new: [u8; 32] = [0xCC; 32];
        let prev: [u8; 32] = [0x00; 32];
        let new: [u8; 32] = [0xCD; 32];
        let amount = 500u64;
        let new_commit = compute_fact_commitment(&tx_new, &prev, &new, amount, None, false, &[]);
        let witness_sigs: Vec<crate::types::WitnessSig> = keys.iter().enumerate().map(|(i, key)| {
            let mut vid = [0u8; 32]; vid[0] = (i + 8) as u8;
            crate::types::WitnessSig {
                validator_id: vid,
                validator_pk: key.pk.clone(),
                signature: vec![0u8; 64],
                execution_proof: vec![],
                proof_type: 0,
                availability_attestation: None,
                carrier_type: "test".to_string(),
                carrier_address: "t".to_string(),
                vbc_bundle: Some(crate::types::VBCProofBundle {
                    target_vbc: crate::types::VBC {
                        network_size_baseline: 0,
                        baseline_tick: 0,
                        version: 9,
                        validator_id: vid,
                        subject_pubkey_dilithium: key.pk.clone(),
                        subject_pubkey_ed25519: vec![0u8; 32],
                        subject_pubkey_sphincs: vec![0u8; 32],
                        pgp_fingerprint: vec![],
                        node_name: "t".into(),
                        proof_cap: "dmap".into(),
                        issued_at: 0, expires_at: u64::MAX,
                        chain_depth: 0,
                        issuer_set: vec![],
                        signatures: vec![],
                        max_tx: 50000,
                        founding_vbc_hash: [0u8; 32],
                    },
                    supporting_vbcs: vec![],
                }),
                fact_signature: Some(crate::crypto::sign_dilithium(&key.sk, &new_commit).expect("dilithium sign")),
                checkpoint_sig: None,
                receipt_signature: None,
                receipt_commitment_sig: None,
                validator_hints: vec![],
                rate_bps: 0,
                slot_amount: 0,
            }
        }).collect();

        let result = build_fact_link(
            &tx_new, &prev, &new, amount, 3,
            &witness_sigs, None, None, None,
            false,
            Vec::new(),
            None, // ← no existing chain
            None, None,
        );
        assert!(result.is_ok(), "first link with no existing chain must succeed: {:?}", result);
    }

    // ─────────────────────────────────────────────────────────────────────
    // KI#13 RELAX tests — narrow burn-verify exception.
    //
    // These tests pin the contract of `verify_fact_chain_burn_retire` /
    // `verify_fact_chain_inner_with_burn_skip`: the Dilithium witness-sig
    // verify is skipped ONLY on the link whose tx_id matches the supplied
    // burn-target, and ALL other structural checks survive at full strength.
    //
    // See the KI#13 RELAX comment block above `verify_fact_chain_burn_retire`
    // in this file, plus docs/AXIOM_REPORT_KnownIssues.md #13 and CLAUDE.md
    // "Exceptional non-verify carve-out (KI#13)". If you find yourself
    // tempted to extend this pattern to any other verify gate — STOP and
    // talk to AXIOM Origin first.
    // ─────────────────────────────────────────────────────────────────────

    /// Corrupting the witness sig on the burn-target link MUST still pass
    /// when verified via verify_fact_chain_burn_retire — the whole point of
    /// the relax is that post-ELF-rebuild scars can still be burned.
    #[test]
    fn ki13_burn_retire_skips_sig_on_target_link() {
        let keys = test_keys();
        let mut target_link =
            make_test_link([0xAAu8; 32], [0u8; 32], [2u8; 32], 1000, &keys);
        // Corrupt every witness's signature — simulates the post-ELF-rebuild
        // condition where the link was signed under different consensus rules.
        for w in target_link.witnesses.iter_mut() {
            w.signature.iter_mut().for_each(|b| *b = b.wrapping_add(1));
        }
        let chain = FactChain { checkpoint: None, links: vec![target_link] };

        // Standard verify_fact_chain MUST reject.
        let std_result = verify_fact_chain(&chain);
        assert!(
            matches!(std_result, Err(ValidationError::FactInvalidSignature)),
            "standard verify_fact_chain MUST reject corrupt scar sig — got {:?}",
            std_result,
        );

        // burn_retire variant pointing at the same tx_id MUST accept.
        let burn_target = [0xAAu8; 32];
        let relax_result = verify_fact_chain_burn_retire(&chain, &burn_target);
        assert!(
            relax_result.is_ok(),
            "verify_fact_chain_burn_retire MUST accept the corrupt scar when \
             burn_target_tx_id matches — got {:?}",
            relax_result,
        );
    }

    /// The relax is NARROW — corrupting a NON-target link's sig must still
    /// be rejected even by the burn-retire variant. The skip is bound to
    /// exactly one tx_id, not "any link in this chain."
    #[test]
    fn ki13_burn_retire_does_not_skip_sig_on_other_links() {
        let keys = test_keys();
        // link1 is the burn target (will be corrupted at sig). link2 is
        // honest in our test world, but we corrupt IT to prove the relax
        // doesn't transfer.
        let target_link =
            make_test_link([0xAAu8; 32], [0u8; 32], [2u8; 32], 1000, &keys);
        let mut other_link =
            make_test_link([0xBBu8; 32], [2u8; 32], [4u8; 32], 500, &keys);
        for w in other_link.witnesses.iter_mut() {
            w.signature.iter_mut().for_each(|b| *b = b.wrapping_add(1));
        }
        let chain = FactChain { checkpoint: None, links: vec![target_link, other_link] };

        let burn_target = [0xAAu8; 32];
        let result = verify_fact_chain_burn_retire(&chain, &burn_target);
        assert!(
            matches!(result, Err(ValidationError::FactInvalidSignature)),
            "verify_fact_chain_burn_retire MUST still reject when a NON-target \
             link has a corrupt sig — got {:?}",
            result,
        );
    }

    /// The relax does NOT bypass structural checks on the burn-target link.
    /// A link with fewer than MIN_FACT_WITNESSES (k=3) witnesses must still
    /// be rejected even when sig-verify is skipped on it.
    #[test]
    fn ki13_burn_retire_still_enforces_min_witnesses_on_target() {
        let keys = test_keys();
        let mut target_link =
            make_test_link([0xAAu8; 32], [0u8; 32], [2u8; 32], 1000, &keys);
        // Drop two witnesses → only 1 left (< MIN_FACT_WITNESSES = 3).
        target_link.witnesses.truncate(1);
        let chain = FactChain { checkpoint: None, links: vec![target_link] };

        let burn_target = [0xAAu8; 32];
        let result = verify_fact_chain_burn_retire(&chain, &burn_target);
        assert!(
            matches!(result, Err(ValidationError::FactInsufficientWitnesses)),
            "verify_fact_chain_burn_retire MUST still enforce k=3 witness \
             minimum on the burn-target link — got {:?}",
            result,
        );
    }

    /// The relax does NOT bypass chain continuity. A chain whose burn-target
    /// link breaks the previous_state_id chain must still be rejected.
    #[test]
    fn ki13_burn_retire_still_enforces_chain_continuity() {
        let keys = test_keys();
        let link0 =
            make_test_link([0xAAu8; 32], [0u8; 32], [2u8; 32], 1000, &keys);
        // link1's previous_state_id deliberately does NOT match link0.new_state_id.
        let link1 =
            make_test_link([0xBBu8; 32], [99u8; 32], [4u8; 32], 500, &keys);
        let chain = FactChain { checkpoint: None, links: vec![link0, link1] };

        // Burn-target is link1 (the broken-continuity link).
        let burn_target = [0xBBu8; 32];
        let result = verify_fact_chain_burn_retire(&chain, &burn_target);
        assert!(
            matches!(result, Err(ValidationError::FactChainBreak)),
            "verify_fact_chain_burn_retire MUST still enforce chain continuity \
             even when sig-verify is skipped — got {:?}",
            result,
        );
    }

    /// When `burn_target_tx_id` doesn't match any link in the chain, the
    /// relax has no effect — every link is sig-verified as if standard
    /// verify were called. This guards against a "burn with a made-up
    /// target tx_id" pattern silently dropping verification on the chain.
    #[test]
    fn ki13_burn_retire_no_effect_when_target_not_in_chain() {
        let keys = test_keys();
        let mut link =
            make_test_link([0xAAu8; 32], [0u8; 32], [2u8; 32], 1000, &keys);
        // Corrupt sig on the (only) link.
        for w in link.witnesses.iter_mut() {
            w.signature.iter_mut().for_each(|b| *b = b.wrapping_add(1));
        }
        let chain = FactChain { checkpoint: None, links: vec![link] };

        // Burn-target tx_id that does NOT match any link.
        let unrelated_target = [0xFFu8; 32];
        let result = verify_fact_chain_burn_retire(&chain, &unrelated_target);
        assert!(
            matches!(result, Err(ValidationError::FactInvalidSignature)),
            "verify_fact_chain_burn_retire MUST reject when burn_target_tx_id \
             matches no link (relax does not transfer) — got {:?}",
            result,
        );
    }
}
