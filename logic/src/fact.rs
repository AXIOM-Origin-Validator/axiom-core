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
//!   - ZKP path (premium): RISC Zero STARK proof (future — the zkVM guest
//!     carries FactCargo's txid only; it computes no FACT commitment, R35)
//!
//! Lambda NEVER builds FACT proofs — it only signs commitments computed by Core.
//! FACT is a Core-layer construct; Lambda is merely a witness that signs.

// CONSENSUS_CRITICAL

use alloc::vec;
use alloc::vec::Vec;
use crate::types::{ChequeBundle, FactChain, FactCheckpoint, FactLink, FactWitness, NablaConfirmation};
use crate::errors::ValidationError;
use crate::crypto::ct_eq;

/// Live tail retained after a checkpoint FINALIZES.
/// Value: `protocol_core.toml :: fact_keep` (editing it rotates the CoreID).
pub const FACT_KEEP: usize = crate::validation::protocol_gen::FACT_KEEP as usize;

/// Basis for the SDK's burn-per-call cap (`MAX_BURNS_PER_HEAL_CALL = this + 1`).
/// ⚠ NOT a depth gate — nothing on the validation path rejects against it. The
/// depth bounds are `FACT_HARD_CEILING` (protocol) and the operator's
/// `max_fact_links` (Core validation Step 0b'). Believing this gated depth cost
/// a full misdiagnosis on 2026-08-18.
/// Value: `protocol_core.toml :: max_fact_depth`.
pub const MAX_FACT_DEPTH: usize = crate::validation::protocol_gen::MAX_FACT_DEPTH as usize;

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
pub const FACT_PROPOSE_TRIGGER: usize = crate::validation::protocol_gen::FACT_PROPOSE_TRIGGER as usize;

/// Distinct validator co-signatures a checkpoint PROPOSAL must accumulate before it
/// FINALIZES (covered links deleted). Global, = MIN_FACT_WITNESSES (k=3). Only the TX
/// finalizer compresses, and only once the proposal carries this many distinct sigs;
/// sigs accumulate across rounds via S-ABR overlap (~1 new sig/tx). Kept global (not
/// per-k) deliberately: a verifier can't cross-check a per-k threshold after the
/// covered links are deleted, so per-k would let colluding validators forge it
/// downward. See advance_fact_checkpoint + verify_checkpoint.
pub const CHECKPOINT_SIG_THRESHOLD: usize = crate::validation::protocol_gen::CHECKPOINT_SIG_THRESHOLD as usize;

/// Anti-abuse ceiling ONLY — never the compression trigger. With S-ABR overlap the
/// proposal gains ~1 sig per TX, so a chain peaks around depth 11-12 before
/// finalizing; this generous bound just caps a pathological non-converging chain.
pub const FACT_HARD_CEILING: usize = crate::validation::protocol_gen::FACT_HARD_CEILING as usize;

/// Minimum witnesses per FACT link (same as k=3 requirement)
pub const MIN_FACT_WITNESSES: usize = 3;

/// YP §26.17.6.5 (2026-09-11, KI#145) — what a verifier is handed BESIDES the
/// chain: the certificate bundles its witnesses resolve to (B2) and, where the
/// verifier knows whose chain it is, the opening state Core derives for that
/// wallet (B1). Both come in through `PublicInputs`; Core never fetches.
#[derive(Clone, Copy)]
pub struct FactTrust<'a> {
    /// B2 — `PublicInputs.fact_certificates`: verified ONCE per execution,
    /// deduplicated by `vbc::vbc_reference_hash`. A witness whose reference
    /// names none of them is `FactWitnessUncertified`; a presented bundle that
    /// fails verification is `FactCertificateInvalid` for the whole execution.
    pub certificates: &'a [crate::types::VBCProofBundle],
    /// B1 — `genesis::opening_state_id_for(pk, k, proof_type)` of the wallet
    /// the chain belongs to: the chain MUST start there (`FactOriginInvalid`).
    /// `None` where the verifier does not hold that key — CL5, where the money
    /// sender's key is not in the cheque: every link of that chain was created
    /// by an execution that DID hold it (CL2/CL3 on the sender's own validators),
    /// and B2 proves those witnesses are certified validators running this Core.
    pub expected_origin: Option<[u8; 32]>,
}

impl<'a> FactTrust<'a> {
    pub fn new(certificates: &'a [crate::types::VBCProofBundle], expected_origin: Option<[u8; 32]>) -> Self {
        FactTrust { certificates, expected_origin }
    }
}

/// YP §26.17.6.5 B4 — the certificate REFERENCES a chain's verification needs:
/// the live-tail witnesses, the checkpoint cosigners and the burn-proof
/// signers (a witness that exists only in compressed history needs none —
/// the cosigners vouched for it). Pure. The SDK and Lambda use it to decide
/// which bundles to PRESENT; Core never calls it to fetch anything.
pub fn certificate_references(chain: &FactChain) -> alloc::collections::BTreeSet<[u8; 32]> {
    let mut refs = alloc::collections::BTreeSet::new();
    let mut note = |w: &FactWitness| {
        if w.vbc_hash != [0u8; 32] {
            refs.insert(w.vbc_hash);
        }
    };
    if let Some(cp) = chain.checkpoint.as_ref() {
        for s in &cp.validator_sigs { note(s); }
    }
    for link in &chain.links {
        for w in &link.witnesses { note(w); }
        if let Some(bp) = link.burn_proof.as_ref() {
            for s in &bp.validator_sigs { note(s); }
        }
    }
    refs
}

/// The certificates Core verified for THIS execution, keyed by reference:
/// `vbc_hash → (validator_id = BLAKE3(sphincs_pk), dilithium_pk)`.
struct CertifiedSet {
    entries: alloc::collections::BTreeMap<[u8; 32], ([u8; 32], Vec<u8>)>,
}

/// B2, step one — verify every presented certificate bundle once (three root
/// signatures for a genesis certificate, or three issuers whose own
/// certificates verify to the roots — `verify_vbc_bundle_historical`, the
/// same walk every receipt- and cheque-borne certificate takes). No clock:
/// a FACT link's `tick` is not inside the witnessed commitment, so expiry
/// cannot be judged from it, and a validator renewing its certificate while
/// a link it witnessed awaits confirmation must not turn that link invalid.
/// A PROVISIONAL certificate (§5.2.2a: a candidate, free to obtain from three
/// issuers) never certifies a witness — otherwise k=3 forged witnesses would
/// cost three candidacies.
fn certify_presented(certificates: &[crate::types::VBCProofBundle]) -> Result<CertifiedSet, ValidationError> {
    let mut entries = alloc::collections::BTreeMap::new();
    for bundle in certificates {
        let vbc = &bundle.target_vbc;
        let reference = crate::vbc::vbc_reference_hash(vbc);
        if entries.contains_key(&reference) {
            continue; // the same signed certificate presented twice — verified once
        }
        if crate::vbc::verify_vbc_bundle_historical(bundle, 0).is_err() {
            #[cfg(feature = "std")]
            { extern crate std; std::eprintln!("[verify_fact_chain DIAG] presented certificate does not verify to the roots (validator_id[..4]={:02x?})", &vbc.validator_id[..4]); }
            return Err(ValidationError::FactCertificateInvalid);
        }
        if crate::validation::vbc_is_provisional(vbc.issued_at, vbc.expires_at) {
            continue; // verifies, but certifies nothing: a candidate cannot witness
        }
        entries.insert(
            reference,
            (crate::crypto::compute_validator_id(&vbc.subject_pubkey_sphincs), vbc.subject_pubkey_dilithium.clone()),
        );
    }
    Ok(CertifiedSet { entries })
}

impl CertifiedSet {
    /// B2, step two — bind ONE witness: its reference names a verified,
    /// non-provisional certificate whose SPHINCS+ key hashes to
    /// `validator_id` and whose Dilithium key IS `validator_pk`. Every key the
    /// witness signed with is therefore a key three roots (or three certified
    /// issuers) vouched for — not a key the witness brought along.
    fn bind(&self, witness: &FactWitness) -> Result<(), ValidationError> {
        let (validator_id, dilithium_pk) = match self.entries.get(&witness.vbc_hash) {
            Some(e) => e,
            None => {
                #[cfg(feature = "std")]
                { extern crate std; std::eprintln!("[verify_fact_chain DIAG] witness validator_id[..4]={:02x?} references no presented certificate", &witness.validator_id[..4]); }
                return Err(ValidationError::FactWitnessUncertified);
            }
        };
        if !ct_eq(validator_id, &witness.validator_id)
            || dilithium_pk.len() != witness.validator_pk.len()
            || !ct_eq(dilithium_pk, &witness.validator_pk)
        {
            #[cfg(feature = "std")]
            { extern crate std; std::eprintln!("[verify_fact_chain DIAG] witness validator_id[..4]={:02x?} does not match its certificate's keys", &witness.validator_id[..4]); }
            return Err(ValidationError::FactWitnessUncertified);
        }
        Ok(())
    }
}

/// Verify a complete FACT chain.
/// Returns Ok(scar_count) on success, Err on integrity failure.
///
/// This runs in CL2 during redeem: receiver's validators verify the sender's
/// money provenance before accepting the cheque.
/// Rejects chains that exceed MAX_FACT_DEPTH resolved links (must compress first).
///
/// YP §26.17.6.5: `trust` carries the certificates the witnesses resolve to
/// and (where known) the wallet's derived opening state — see `FactTrust`.
///
/// Runs inside AVM (DMAP-attested). ZKP premium path: future RISC Zero guest integration.
pub fn verify_fact_chain(chain: &FactChain, trust: &FactTrust) -> Result<usize, ValidationError> {
    verify_fact_chain_inner(chain, true, trust)
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
                vbc_hash: c.vbc_hash,
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
    // YP §26.17.6.5 B2 — this validator's own certificate reference
    // (`vbc::vbc_reference_hash(&own_bundle.target_vbc)`).
    vbc_hash: [u8; 32],
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
        vbc_hash,
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
    trust: &FactTrust,
) -> Result<usize, ValidationError> {
    verify_fact_chain_inner_with_burn_skip(chain, true, Some(burn_target_tx_id), trust)
}


/// Internal verification logic shared by verify and verify_and_compress.
///
/// `enforce_depth`: when true, reject chains with more than MAX_FACT_DEPTH resolved links.
/// verify_fact_chain sets true (standalone verify — client must compress first).
/// verify_and_compress sets false (will compress after verification succeeds).
pub(crate) fn verify_fact_chain_inner(chain: &FactChain, enforce_depth: bool, trust: &FactTrust) -> Result<usize, ValidationError> {
    verify_fact_chain_inner_with_burn_skip(chain, enforce_depth, None, trust)
}

/// Real workhorse. When `burn_skip` is `Some(target_tx_id)`, the Dilithium
/// witness-sig verification on the matching link is skipped. All other
/// structural checks on that link still run, and ALL checks on every other
/// link run at full strength. See KI#13 RELAX comment block above
/// `verify_fact_chain_burn_retire`.
pub(crate) fn verify_fact_chain_inner_with_burn_skip(chain: &FactChain, enforce_depth: bool, burn_skip: Option<&[u8; 32]>, trust: &FactTrust) -> Result<usize, ValidationError> {
    // Empty chain is valid only for genesis wallets (no history yet)
    if chain.links.is_empty() && chain.checkpoint.is_none() {
        return Ok(0);
    }

    // YP §26.17.6.5 B2 — the certificates this execution was handed, verified
    // ONCE here; every witness below (links, cosigners, burn proofs) must
    // resolve into this set. Absence is refusal, never a lookup.
    let certified = certify_presented(trust.certificates)?;

    // YP §26.17.6.5 B1 — the chain starts where Core says this wallet started:
    // `origin == opening_state_id_for(pk, k, proof_type)`. An invented origin (a
    // first state with a balance nobody derived) is not a chain. Enforced
    // wherever the verifier holds the wallet key (see `FactTrust`).
    if let Some(expected) = trust.expected_origin {
        let origin = match chain.checkpoint.as_ref() {
            Some(cp) => cp.genesis_state_id,
            None => chain.links[0].previous_state_id, // non-empty: the early return above
        };
        if !ct_eq(&origin, &expected) {
            #[cfg(feature = "std")]
            { extern crate std; std::eprintln!("[verify_fact_chain DIAG] origin {:02x?} is not the wallet's derived opening state {:02x?}", &origin[..4], &expected[..4]); }
            return Err(ValidationError::FactOriginInvalid);
        }
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
    // BURN IS EXEMPT — a wallet at the ceiling must never be dead (decided
    // 2026-08-18). Before this, the operator gate (`max_fact_links`, validation
    // Step 0b') exempted `is_heal_self_send` while THIS ceiling exempted nothing,
    // so recovery could walk a chain from the operator gate up to the ceiling and
    // then find every operation refused — send, heal AND burn. Permanent strand,
    // the shape YP §8443 warns about.
    //
    // Only BURN is let through, not heal: burn is the one operation that makes a
    // chain SHORTER. It stamps `burn_proof` on a scarred link, which resolves it
    // unconditionally (`FactLink::is_resolved`), extending the resolved prefix so
    // the checkpoint can cover those links and DELETE them on finalize —
    // "Self-scar the stuck TX, burn it, FACT compression cleans up" (YP §8432).
    // Heal only APPENDS a link, so exempting heal here would let a pathological
    // chain grow without bound and defeat the very load bound this ceiling is
    // (a link is ~80KB; the ceiling caps worst-case CBOR verified per TX).
    //
    // `burn_skip` is `Some(target_tx_id)` exactly when the caller is validating a
    // burn TX retiring that link (threaded from `burn_target_for_relax` in
    // validation.rs). Reusing that existing signal deliberately: KI#58 is the
    // record of what happens when a SECOND burn predicate is invented and drifts
    // out of step with the burn shape the SDK actually builds.
    let is_burn_retiring = burn_skip.is_some();
    if enforce_depth && !is_burn_retiring {
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
            verify_checkpoint_sigs(checkpoint, &certified)?;
            // No final_state_id anchor check here: while provisional, final_state_id
            // sits MID-chain at links[m-1], and continuity is verified over all links.
        } else {
            // FINALIZED: covered links deleted; the summary is the sole provenance.
            // Enforce the k=5 distinct-sig gate + the anchor to the live tail.
            verify_checkpoint(checkpoint, &certified)?;
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
        // KI#183: a self-send writes two links under one txid, and the relax must
        // cover ONLY the scarred one being retired — skipping the witness verify on
        // its already-resolved sibling would weaken a link nobody is burning.
        let skip_witness_sigs = burn_skip
            .map_or(false, |target| unresolved_target_index(&chain.links, target) == Some(i));
        if let Err(e) = verify_fact_link_internal(link, skip_witness_sigs, &certified) {
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

        // BurnProof.burn_tx_id must reference an actual burn link in this
        // chain that was witnessed to burn THIS scar for THIS amount
        // (YPX-001 §1.5.4). Three bindings, together forgery-proof:
        //   (1) the named burn link exists in this chain (else the burn_tx_id
        //       points at a forged value or another wallet's chain);
        //   (2) that burn link's `burn_target_tx_id` names THIS scar — bound
        //       into its `compute_fact_commitment`, so the k=3 witnesses
        //       attested which scar it destroyed and it cannot be re-pointed;
        //   (3) the burn link destroyed THIS scar's exact amount.
        //
        // (2)+(3) close the COPY forge (2026-07-17): `BurnProof.validator_sigs`
        // is only a clone of the burn link's own witnesses (`build_fact_link`)
        // and binds nothing about the target on its own, so before this a proof
        // lifted off a genuinely-burned 1-atom link and pasted onto a
        // 1000-atom scar passed (1) and read `is_resolved() == true`. Now the
        // paste fails (2) — the burn link's witnessed target is the 1-atom scar,
        // not the 1000 — and independently fails (3). Proven by
        // `tests::burn_proof_copied_from_another_link_rejected`.
        if let Some(ref burn_proof) = link.burn_proof {
            let burn_link = chain.links.iter()
                .find(|l| ct_eq(&l.tx_id, &burn_proof.burn_tx_id));
            match burn_link {
                None => return Err(ValidationError::BurnTxIdNotInChain),
                Some(bl) => {
                    let targets_this = bl.burn_target_tx_id.as_ref()
                        .is_some_and(|t| ct_eq(t, &link.tx_id));
                    if !targets_this {
                        return Err(ValidationError::BurnTargetMismatch);
                    }
                    if bl.amount != link.amount {
                        return Err(ValidationError::BurnAmountMismatch);
                    }
                    // YP §26.17.6.5 B2′ — the proof's signatures ARE the burn
                    // link's witnesses (`build_fact_link` clones them), so each
                    // must be one of that link's witnesses byte-for-byte: those
                    // are Dilithium-verified over the burn commitment and
                    // certificate-bound above. Closes HEAL_SCAR_SPLIT §3.2's
                    // deferral ("counted, not verified") without a second
                    // commitment to keep in step.
                    for proof_sig in &burn_proof.validator_sigs {
                        let vouched = bl.witnesses.iter().any(|w| {
                            ct_eq(&w.validator_id, &proof_sig.validator_id)
                                && ct_eq(&w.vbc_hash, &proof_sig.vbc_hash)
                                && w.validator_pk.len() == proof_sig.validator_pk.len()
                                && ct_eq(&w.validator_pk, &proof_sig.validator_pk)
                                && w.signature.len() == proof_sig.signature.len()
                                && ct_eq(&w.signature, &proof_sig.signature)
                        });
                        if !vouched {
                            return Err(ValidationError::FactBurnSigInvalid);
                        }
                    }
                }
            }
        }

        // YPX-022 RECALL: a scarred link is ALSO resolved if it carries a valid
        // recall_proof — a Nabla-signed RecallAttestation whose txid == this link's
        // tx_id, proving the sub-quorum send here was reclaimed (no value moved). This
        // replaces the earlier Lambda-side scar-passcode exemption for is_recall with a
        // real, verified resolution: the scar is cleared, not skipped. Forgery-proof —
        // the attestation is Nabla Ed25519 + NBC-root anchored (verify_recall_attestation),
        // so an attacker can't wash out a genuine scar by attaching a fake proof.
        // ONE rule, two entry points kept in lockstep (drift-guarded by
        // `tests::is_resolved_matches_link_is_resolved`): `link_is_resolved` (HERE,
        // WITH the Nabla Ed25519 + NBC-root signature verification — the verify-time
        // form) and the structural `FactLink::is_resolved` (compression / scar-cap /
        // Ark CI — the post-verify form, safe because THIS function runs first and
        // rejects a forged recall/burn proof). Both treat recall + inherited taint
        // identically; they can only differ on an UNVERIFIED chain, which never
        // reaches a post-verify consumer. See KI#62 for the drift that made
        // hand-duplicating the rule expensive.
        let resolved = link_is_resolved(link);
        // ⚠ MISREADING GUARD (2026-08-04) — `scar_count` is DERIVED, it is not
        // the record. The record is per-link, right here: `nabla_confirmation`,
        // `burn_proof`, `recall_proof`, `inherited_scar_txids` /
        // `inherited_scar_resolutions`. A count tells you HOW MANY links are
        // unresolved — never WHICH, and never WHY.
        //
        // Reading `scars=1` off a log line and inferring a cause is how a whole
        // session went wrong: the same "1" is produced by an own unregistered
        // link (KI#52) and by an inherited scar (YPX-001 §1.5.1a), which have
        // different causes AND different fixes — heal repairs the first and is
        // structurally powerless against the second. To tell them apart you
        // MUST open the chain and look at the fields above.
        if !resolved {
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
///        `payload  = BLAKE3("AXIOM_FACT_CONFIRM" || tx_hash || new_state_id
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
        // §17.10.5.3).  Domain tag bumped to "AXIOM_FACT_CONFIRM";
        // any pre-V2 confirmation that survived the upgrade gets
        // rejected here.  Pre-mainnet, no compat shim per CLAUDE.md §13.
        // Pattern 1 sweep — ONE builder, shared with the Nabla node that
        // SIGNS this payload. Assembling it here independently is what makes a
        // signer/verifier pair drift silently (KI#54).
        let payload_bytes = crate::crypto::fact_confirm_payload(
            previous_state_id, new_state_id, conf.committed_at_tick,
        );
        let payload = blake3::Hash::from(payload_bytes);

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
fn verify_fact_link(link: &FactLink, certified: &CertifiedSet) -> Result<(), ValidationError> {
    verify_fact_link_internal(link, false, certified)
}

/// P3.2 (YPX-010 §11) — verify the RECEIVER-as-witness attestation on a k=0 Ark link.
///
/// Mandatory on EVERY k=0 link, offline or settled: the receiver's own Ed25519 wallet
/// key signs the SAME `compute_fact_commitment` bytes the k=3 Dilithium witnesses would
/// sign online, so the receiver attests exactly the transition (tx_id, states, amount,
/// anchors, taint, burn-target). It is the proof the link was a real ⟠ trade (§12.2)
/// and survives settlement in place. This does NOT verify any appended validator sigs
/// (the caller falls through to the k≥3 path for a settled link); it verifies the
/// receiver witness and enforces S1. The `receiver_pk == trade receiver` binding
/// (exclusivity §11.7) is CL2's job (P3.4) — here we prove the link was witnessed by
/// whatever key it names, and nothing weaker.
fn verify_k0_ark_receiver_witness(link: &FactLink) -> Result<(), ValidationError> {
    // S1 (§11): an OFFLINE k=0 link NEVER carries a Nabla confirmation — offline
    // trades have no Nabla. (A SETTLED k=0 link — witnesses non-empty — legally
    // carries one per §12.2 and takes the settled branch in the caller instead.)
    if link.nabla_confirmation.is_some() {
        return Err(ValidationError::ArkK0NablaConfirmationForbidden);
    }
    if link.receiver_witness.is_none() {
        return Err(ValidationError::ArkReceiverWitnessMissing);
    }
    verify_k0_receiver_witness_sig(link)
}

/// The receiver-witness SIGNATURE check alone (shared by the offline shape,
/// where it is mandatory, and the settled shape, where it is verified only
/// when carried): the named Ed25519 key over this link's fact commitment.
fn verify_k0_receiver_witness_sig(link: &FactLink) -> Result<(), ValidationError> {
    let rw = link
        .receiver_witness
        .as_ref()
        .ok_or(ValidationError::ArkReceiverWitnessMissing)?;

    let commitment = compute_fact_commitment(
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
        return Err(ValidationError::ArkReceiverWitnessInvalid);
    }
    Ok(())
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
fn verify_fact_link_internal(link: &FactLink, skip_witness_sigs: bool, certified: &CertifiedSet) -> Result<(), ValidationError> {
    // P3.2 witness-eligibility branch (YPX-010 §11): a k=0 Ark (`K_ARK`) ⟠→⟠ trade
    // link is witnessed by the receiver's own wallet key (receiver-as-witness), NOT a
    // k≥3 VBC quorum. This is a TIER BRANCH inside the one verifier, not a second
    // verifier: `required_k == K_ARK` selects the receiver-as-witness path.
    //
    //   - OFFLINE (unsettled) link: `witnesses` is empty — the receiver-as-witness
    //     Ed25519 signature is the SOLE proof (floor 1, P3.1). Verify it and stop.
    //   - SETTLED link (YPX-010 §12.2): validators have appended Dilithium
    //     `FactWitness` entries into `witnesses` at settlement, and the
    //     `receiver_witness` survives in place as the proof the settled link was a
    //     real ⟠ trade. Verify the receiver witness AND fall through to full-strength
    //     Dilithium/VBC verification of the appended validators below.
    //
    // The `receiver_pk ↔ trade-receiver` binding (exclusivity §11.7) is enforced at
    // CL2 accept time where the current tx's `receiver_wallet_id` is known (P3.4); here
    // we prove the link was witnessed by the key it names, and reject S1 malformation.
    if link.required_k == crate::wallet_id::K_ARK {
        if link.witnesses.is_empty() {
            // OFFLINE (unsettled) ⟠-trade link: the receiver-as-witness
            // Ed25519 is the SOLE proof (floor 1, §11.3) and S1 bans a
            // confirmation — no honest one can exist offline.
            verify_k0_ark_receiver_witness(link)?;
            return Ok(());
        }
        // SETTLED (§12.2 — P3.8 fix, reviewed and approved 2026-07-19): the link was
        // replayed through the ONLINE path; k validators re-witnessed the
        // SAME transition and Nabla registered it, so the
        // `nabla_confirmation` is LEGAL here — it is the entire point of
        // settlement. S1's ban targets exclusively the OFFLINE shape above.
        // (Pre-fix, `verify_k0_ark_receiver_witness` ran unconditionally and
        // every post-settlement wallet's chain rejected
        // ArkK0NablaConfirmationForbidden on its next tx — soak ark_soak5.)
        // The Step-1 receiver-witness is verified WHEN CARRIED — Lambda's
        // rebuilt settlement link does not yet carry it in place (§11.2.1
        // survival is a tracked follow-up) — and the Dilithium quorum below
        // is the settled link's actual proof, at the full k≥3 floor.
        if link.receiver_witness.is_some() {
            verify_k0_receiver_witness_sig(link)?;
        }
        if link.witnesses.len() < MIN_FACT_WITNESSES {
            return Err(ValidationError::FactInsufficientWitnesses);
        }
        // Fall through to the Dilithium verification below.
    } else if link.witnesses.len() < MIN_FACT_WITNESSES {
        // The EXISTENCE floor of an online link is the absolute 3. A link with
        // fewer witnesses than ITS OWN `required_k` is not refused here — it is
        // a SCAR (`has_scars` / `scar_count`: witnesses < required_k), carried
        // in the chain until lifted or burned (YP §26.17, HEAL_SCAR_SPLIT).
        // KI#150 (2026-09-12) confirmed this split: the tier-floor rule judges
        // ANCHORS (receipts) at their k; links judge their k as scar-or-not.
        return Err(ValidationError::FactInsufficientWitnesses);
    }

    // Verify each witness Dilithium (ML-DSA-65) signature
    // FACT uses Dilithium (not SPHINCS+) because FACT is operational:
    // signed every transaction, needs speed (~1ms vs ~100ms for SPHINCS+).
    // Still quantum-resistant. VBC keeps SPHINCS+ (signed once at birth).
    // Signs: `compute_fact_commitment` over the link's own fields — see its doc
    // for the full preimage (incl. is_dev_class, required_k, inherited set, burn target).
    let commitment = compute_fact_commitment(
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

    // YPX-001 §1.5.1a — inherited-scar RESOLUTIONS are post-round
    // attachments (like nabla_confirmation), verified HARD here: each must
    // target a txid in this link's inherited set, carry a valid Nabla
    // Ed25519 signature over the attestation payload, and anchor to a
    // NABLA_ROOT_AUTHORITY via NBC. A forged attachment rejects the chain
    // — an attacker cannot wash inherited taint with a fake attestation.
    // This is VALIDITY only (the payload binds `origin` and
    // `sender_registered_at_tick`, so neither can be spliced or re-dated).
    // Whether a valid attachment CLEARS the taint is judged separately by
    // `origin_settled_link` (YPX-001 §1.5.1b): only a SETTLED REGISTERED
    // origin clears. ~~"ANY validly-attested status proves the origin txid
    // entered Nabla's record; BURNED proves the origin destroyed the tainted
    // amount"~~ — WRONG, superseded 2026-09-28 (KI#221, ForkSettlement §3.1):
    // consumed ≠ backed, and an upstream burn would launder downstream.
    for res in &link.inherited_scar_resolutions {
        if !link.inherited_scar_txids.iter().any(|t| crate::crypto::ct_eq(t, &res.txid)) {
            return Err(ValidationError::FactInvalidSignature);
        }
        if !txid_attestation_signature_valid(res) {
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
                     anchor={} k={} commitment={} pk_len={} pk[..8]={} sig_len={} sig[..8]={}",
                    idx,
                    hex8(&link.tx_id),
                    hex8(&link.previous_state_id),
                    hex8(&link.new_state_id),
                    link.amount,
                    anchor_hex,
                    link.required_k,
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
        // The burn proof's signatures are the BURN round's witnesses (a
        // self-send at the wallet's own tier), not the scarred link's k —
        // absolute floor 3 (KI#150 review, 2026-09-12).
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

    // YP §26.17.6.5 B2 — every Dilithium witness resolves to a certificate this
    // execution verified to the roots, and signed with THAT certificate's key.
    // Runs on the KI#13 burn-retire link too (its signatures are skipped, its
    // identities are not), and on a settled k=0 link's appended validators.
    for witness in &link.witnesses {
        certified.bind(witness)?;
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
fn verify_checkpoint(checkpoint: &FactCheckpoint, certified: &CertifiedSet) -> Result<(), ValidationError> {
    // FINALIZED gate (SEC-07): the covered links are GONE, so the summary is the
    // sole provenance. Require CHECKPOINT_SIG_THRESHOLD distinct validator sigs.
    // (Provisional checkpoints, whose real links are still present, verify through
    // the links and call verify_checkpoint_sigs directly with no count gate.)
    if checkpoint.validator_sigs.len() < CHECKPOINT_SIG_THRESHOLD {
        return Err(ValidationError::FactInsufficientWitnesses);
    }
    verify_checkpoint_sigs(checkpoint, certified)
}

/// Verify a checkpoint's signatures are distinct and valid over its commitment —
/// WITHOUT the threshold count. Used for provisional checkpoints (still
/// accumulating) and as the back half of the finalized gate.
fn verify_checkpoint_sigs(checkpoint: &FactCheckpoint, certified: &CertifiedSet) -> Result<(), ValidationError> {
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

    // Verify each Dilithium (ML-DSA-65) signature over the checkpoint commitment —
    // YP §26.17.6.5 B3: a cosigner is bound (B2) BEFORE its signature counts.
    // Compression discards the covered links' witnesses; the cosigners are all
    // the provenance that remains, so they must be certified validators.
    let commitment = compute_checkpoint_commitment(checkpoint);
    for sig in &checkpoint.validator_sigs {
        certified.bind(sig)?;
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

/// Is this transaction AUTHORIZED to carry a `burn_target_tx_id`?
///
/// Two shapes may carry one, and they are not interchangeable:
///
///   1. A send to `BURN_ADDRESS` — the §1.5.4 canonical burn.
///   2. A **self-send heal-burn** (`is_heal && sender == receiver`) — the
///      scar-burn pattern (bd29f7a, 2026-05-11). Addressing the wallet
///      itself was what earned the depth-gate exemption, so a wallet
///      past `max_fact_links` could still burn a scar. (⚠ KI#241 F-9.4,
///      2026-10-01: shape 1 is depth-exempt too now, and the SDK burns in
///      shape 1 — the only shape Nabla's provenance exit recognises; shape 2
///      is its depth-refused fallback.) The
///      `burn_target_tx_id` still names the scarred link for
///      `build_fact_link` to annotate with a `BurnProof`.
///
/// **This predicate exists because the rule had THREE implementations that
/// disagreed** (KI#54): `validation.rs` carried the exemption,
/// `execute_cl3_zkp_checkpoint` did not (so ZKP mode rejected every
/// heal-burn DMAP accepted), and the CL3 witness-signing path gated on
/// `BURN_ADDRESS` alone. Any new site asking "may this TX carry a burn
/// target?" MUST call this, never re-derive it.
pub fn burn_target_is_authorized(tx: &crate::types::Transaction) -> bool {
    tx.receiver_wallet_id == crate::types::BURN_ADDRESS
        || (tx.is_heal() && tx.sender_wallet_id == tx.receiver_wallet_id)
}

/// THE single derivation of the burn target bound into a link's FACT
/// commitment.
///
/// Both the k=3 **witnesses** (who sign the commitment) and the
/// **finalizer** (who verifies those signatures against a recomputed
/// commitment) MUST obtain the field from here. When they disagree, every
/// witness signature fails to verify against a commitment nobody signed,
/// `build_fact_link` drops the whole witness set, and the caller sees
/// `FactInsufficientWitnesses` — 3-of-3 signatures present, yet
/// "insufficient witnesses" (KI#54).
///
/// The failure is silent and total: the chain never extends, the wallet
/// cannot burn, and the only remaining escapes (burn, then RECALL) destroy
/// value over what is a builder mismatch — nothing the sender or receiver
/// did. **Never re-derive this field at a call site.**
pub fn fact_burn_target(tx: &crate::types::Transaction) -> Option<&[u8; 32]> {
    if burn_target_is_authorized(tx) {
        tx.burn_target_tx_id.as_ref()
    } else {
        None
    }
}

/// Compute FACT link commitment for signing — THE one builder (Pattern 1).
///
/// ```text
/// BLAKE3("AXIOM_FACT_v2" || tx_id || previous_state_id || new_state_id ||
///        amount_le(8) || sender_anchor_or_zeros(32) || is_dev_class(u8) ||
///        required_k(u8) || inherited_count_le(u32) || inherited_txids… ||
///        burn_target_or_zeros(32))
/// ```
///
/// `sender_anchor` is `Some(sender_chain_tip)` for REDEEM links and `None`
/// for SEND / HEAL / BURN links. None encodes as 32 zero bytes (constant-size
/// commitment, no parser branch). `required_k` is the link's own
/// `FactLink::required_k` (0 = Ark k=0 endpoint, 3/4/5 = tier) — every
/// signer and every verifier passes the SAME value the link declares.
///
/// Domain tag bumped from "AXIOM_FACT" to "AXIOM_FACT_v2" so legacy
/// signatures cannot accidentally verify under the new scheme — A2 cutover
/// is a hard wire-format break. Every later field (is_dev_class, the
/// inherited set, the burn target, required_k) was added WITHOUT a domain
/// bump (CLAUDE.md §13: the version tag is the scar; CoreID rotation +
/// pre-mainnet wipe instead).
///
/// Runs deterministically inside AVM. Lambda calls Core for this — NEVER computes directly.
pub fn compute_fact_commitment(
    tx_id: &[u8; 32],
    previous_state_id: &[u8; 32],
    new_state_id: &[u8; 32],
    amount: u64,
    sender_anchor: Option<&[u8; 32]>,
    is_dev_class: bool,
    required_k: u8,
    inherited_scar_txids: &[[u8; 32]],
    burn_target_tx_id: Option<&[u8; 32]>,
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
    // `required_k` — Fork Settlement R4 (`AXIOM_DESIGN_ForkSettlement.md`
    // §3.3a, 2026-09-28, wave 2b-ii). Until this byte was bound, a link's
    // `required_k` was an UNSIGNED field that three Core decisions read:
    //   * the Ark inheritance filter `required_k == 0` in
    //     `compute_inherited_scar_txids` (a colluding receiver could set the
    //     tip's `required_k` to 0 and inherit NOTHING — the R4 attack);
    //   * the k=0 receiver-witness path selector `link.required_k == K_ARK`
    //     in `verify_fact_link_internal`;
    //   * the quorum threshold in `verify_link_witness_quorum` (a holder could
    //     edit 5 → 3 and the unchanged witness sigs still verified).
    // Bound here, any edit invalidates every witness's Dilithium
    // fact_signature. Formula change ⇒ CoreID rotation + pre-mainnet chain
    // wipe (§13); no domain bump, beside `is_dev_class` exactly as it was.
    hasher.update(&[required_k]);
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
    // YPX-001 §1.5.4 burn-target binding (2026-07-17): on a BURN TX's own link
    // this names the scarred link being destroyed, so the k=3 witnesses attest
    // WHICH scar this burn resolves. Without it a BurnProof — whose
    // `validator_sigs` are merely a clone of this link's own witnesses — could
    // be copied onto any other scar in the chain and washed it for free.
    // A zero sentinel keeps non-burn links byte-identical to a `None` burn,
    // exactly as `sender_anchor` above does. Formula change ⇒ CoreID rotation
    // + pre-mainnet chain wipe (§13); no domain bump.
    hasher.update(&burn_target_tx_id.copied().unwrap_or([0u8; 32]));
    *hasher.finalize().as_bytes()
}

/// YPX-001 §1.5.1a — VALIDITY of a txid attestation — a stored inherited-scar
/// resolution, or the one a redeem carries (NOT whether it clears — that is
/// `origin_settled_link`): the Nabla node's Ed25519 signature
/// over the ONE payload builder `crypto::txid_attest_payload` (Pattern 1, shared
/// with the signing node; binds `origin` + `sender_registered_at_tick`) AND the
/// MANDATORY NBC trust anchor to `NABLA_ROOT_AUTHORITY_PKS` (Phase 5e posture:
/// empty/invalid ⇒ invalid; a self-signed attestation must never clear taint).
/// Called by `verify_fact_link_internal` for every stored resolution, and by the
/// SDK before it splices one or ranks a redeem's candidates (ForkSettlement wave 5 —
/// "never splice an attestation Core would not count"; RULE 1: this was a
/// hand-assembled third copy in `sdk/client/src/nabla.rs` until then).
///
/// ForkSettlement §9p (2026-09-30): ALSO requires the signed `origin_status` to
/// agree with `origin` ([`txid_attestation_origin_consistent`]) — a malformed
/// attestation is invalid exactly like a bad signature (a stored one rejects
/// the chain; the SDK never splices or ranks one).
pub fn txid_attestation_signature_valid(att: &crate::types::NablaTxidAttestation) -> bool {
    let expected = blake3::Hash::from(crate::crypto::txid_attest_payload(
        &att.txid, &att.status, att.nabla_tick,
        att.origin.as_ref(), att.sender_registered_at_tick,
        att.oods_size, att.oods_healthy, att.origin_status));
    txid_attestation_origin_consistent(att)
        && crate::crypto::verify_ed25519(&att.nabla_node_pk, expected.as_bytes(), &att.nabla_signature).is_ok()
        && !att.nbc_issuer_pk.is_empty()
        && crate::validation::verify_nbc_for_txid_attestation(att).unwrap_or(false)
}

/// ForkSettlement §9p (KI#221 residual 1, 2026-09-30) — THE one consistency
/// rule between a txid attestation's signed `origin_status` and its signed
/// `origin`: `Vouched` ⇔ `origin.is_some()`. `Vouched` without an origin, or
/// `Held` / `Unknown` WITH one, is MALFORMED — an honest node never signs it
/// (`NablaNode::origin_vouch`), so Core refuses it like any bad attestation:
/// CL5 Step 3.5 (`TxidAttestationBadStatus`) and every stored resolution
/// (via [`txid_attestation_signature_valid`] → `FactInvalidSignature`). One
/// function, both sites (RULE 1).
pub fn txid_attestation_origin_consistent(att: &crate::types::NablaTxidAttestation) -> bool {
    (att.origin_status == crate::types::OriginVouchStatus::Vouched) == att.origin.is_some()
}

/// YPX-001 §1.5.1b SETTLE READY TIME — the LINK-LEVEL form (ForkSettlement §3.2
/// [R11, R20] / §4 R3, KI#221). THE one Core definition of "when does this
/// attestation's origin SETTLE?": `Some(sender_registered_at_tick + floor)` iff the
/// attestation VOUCHES a registered Send origin that recomputes to
/// `inherited_txid`, else `None`. `origin_settled_link` is exactly
/// `ready_at.is_some_and(|r| att.nabla_tick >= r)`, and the SDK's `ScarSettling`
/// wait (`axiom_sdk_core::inherited_sweep`, wave 5) reads the SAME value — the
/// predicate and the wait cannot drift apart (RULE 1; the KI#62 shape must not
/// recur). Signature/NBC validity is NOT judged here — `verify_fact_link_internal`
/// and CL5 Step 3.5 verify the ONE payload (which binds `origin` and
/// `sender_registered_at_tick`) before any consumer reads this.
///
/// `Some` iff ALL of (fail closed on every missing piece → `None`):
/// * `att.txid == inherited_txid` — the attestation is about THIS txid;
/// * `sender_registered_at_tick != 0` — the node holds the registration
///   uncontested (0 = absent / contested / registrant banned);
/// * `origin_status == Vouched` — the node's signed statement (ForkSettlement
///   §9p): a `Held` or `Unknown` attestation NEVER settles, whatever else it
///   carries (a well-formed one carries no origin anyway —
///   [`txid_attestation_origin_consistent`]; this conjunct keeps the rule
///   true even for a caller that skipped the validity check);
/// * `oods_healthy` — the vouching node's own OODS reading was HEALTHY when
///   it signed (ForkSettlement §9h [R53]; signed, fail-closed);
/// * `origin` is present and `kind == Send` — a REDEEM-kind leg is never an
///   origin [R11];
/// * `origin.preimage.txid(origin.epoch) == inherited_txid` — EXACT binding by
///   recomputation; the registrant's `client_pk`, the consumed state, receiver
///   and amount are all inside that preimage.
///
/// The ready time is `sender_registered_at_tick + settle_floor_secs(is_dev_class)`,
/// floor = `dev_or_real(is_dev_class, SCAR_SETTLE_TICKS_DEV, SCAR_SETTLE_TICKS)` — on the
/// vouching node's OWN clock (`virtual_secs`); it is meaningful only against that
/// same node's `nabla_tick`, never against a client clock or another node.
///
/// The attestation's `status` is NOT an input: `REDEEMED` (consumed ≠ backed)
/// and `BURNED` (an upstream burn would launder every downstream holder) never
/// clear by themselves. ~~KI#180: "`REDEEMED` or `BURNED` resolves"~~ —
/// `txid_attestation_resolves_origin` was REPLACED by this predicate
/// 2026-09-28 (ForkSettlement §3.1 / R27, KI#221).
pub fn origin_settle_ready_at(
    att: &crate::types::NablaTxidAttestation,
    inherited_txid: &[u8; 32],
    is_dev_class: bool,
) -> Option<u64> {
    if !ct_eq(&att.txid, inherited_txid) || att.sender_registered_at_tick == 0 {
        return None;
    }
    // ForkSettlement §9p — only a VOUCHED status can settle (Held / Unknown never).
    if att.origin_status != crate::types::OriginVouchStatus::Vouched {
        return None;
    }
    // ForkSettlement §9h [R53] (Core W7a): a "settled" vouch requires the
    // vouching node's OWN OODS reading to have been HEALTHY at signing time
    // (signed flag, YPX-021 `oods_size·3 ≥ baseline`). An eclipsed or
    // partitioned node sees < 1/3 of its baseline — it may be the node the
    // other fork leg never reached — so its vouch is never Settling/settled.
    // Fail-closed; lives HERE so every consumer (link form, CL5 form, SDK
    // ScarSettling wait) inherits it (RULE 1).
    if !att.oods_healthy {
        return None;
    }
    let origin = att.origin.as_ref()?;
    if origin.kind != crate::types::LegKind::Send {
        return None;
    }
    if !ct_eq(&origin.preimage.txid(origin.epoch), inherited_txid) {
        return None;
    }
    Some(att.sender_registered_at_tick.saturating_add(settle_floor_secs(is_dev_class)))
}

/// THE settle floor in SECONDS for a class — `dev_or_real(is_dev_class,
/// SCAR_SETTLE_TICKS_DEV, SCAR_SETTLE_TICKS).to_secs()` (40 s dev / 200 s
/// real at the current registers). Extracted from `origin_settle_ready_at`
/// (Fork Settlement W7a, spec R52i, 2026-09-28) so the Nabla vouch's
/// `registered_at_secs` arithmetic and the door's R52f `Settling(ready_at)`
/// WAIT read the floor from Core, never from a Nabla constant (RULE 1 — the
/// floor lives in ONE place; spec test T7 mutates exactly that). Both callers
/// compare it against ONE node's own `virtual_secs`; it is a duration, not a
/// clock.
pub fn settle_floor_secs(is_dev_class: bool) -> u64 {
    crate::types::dev_or_real(
        is_dev_class,
        crate::validation::SCAR_SETTLE_TICKS_DEV,
        crate::validation::SCAR_SETTLE_TICKS,
    )
    .to_secs()
}

/// YPX-001 §1.5.1b SETTLED ORIGIN — the LINK-LEVEL form (ForkSettlement §3.2
/// [R11, R20], KI#221). THE one Core predicate for "does this attestation CLEAR
/// inherited origin `inherited_txid`?" — `FactLink::inherited_unresolved{,_txids}`,
/// the transitive loop in `compute_inherited_scar_txids`, and (via
/// `origin_settled_cl5`) the CL5 skip all call it; the SDK calls it too (RULE 1).
/// Clears iff `origin_settle_ready_at` vouches AND the node has HELD the
/// registration for the settle floor on its OWN wall clock:
/// `nabla_tick >= ready_at` (both values are that one node's `virtual_secs`; no
/// inter-node skew). Every conjunct and the floor are documented — and live —
/// on `origin_settle_ready_at`; this fn adds only the tick comparison.
pub fn origin_settled_link(
    att: &crate::types::NablaTxidAttestation,
    inherited_txid: &[u8; 32],
    is_dev_class: bool,
) -> bool {
    origin_settle_ready_at(att, inherited_txid, is_dev_class)
        .is_some_and(|ready_at| att.nabla_tick >= ready_at)
}

/// YPX-001 §1.5.1b SETTLED ORIGIN — the CL5 form (ForkSettlement §3.2 / Q2). The
/// link-level rule with `inherited_txid = cheque.txid`, AND the origin preimage
/// agrees with the cheque in hand and with the verified sender tip:
/// * `preimage.receiver_wallet_id == cheque.receiver_wallet_id` and
///   `preimage.amount == cheque.amount` (cheque-signed fields);
/// * `preimage.consumed_state_id == sender_tip.previous_state_id` [R5] — the
///   registered leg is THIS send (KI#146: the tip of `redeem_fact_chain_ref` IS
///   the send; its `previous_state_id` is in the witness-signed commitment).
///
/// Used at ONE site, `cl5_inherited_scar_txids`: when it holds, the cheque's
/// own origin is NOT inherited — the ordinary receiver never carries a scar.
pub fn origin_settled_cl5(
    att: &crate::types::NablaTxidAttestation,
    cheque: &crate::types::ValidatorCheque,
    sender_tip: &FactLink,
    is_dev_class: bool,
) -> bool {
    if !origin_settled_link(att, &cheque.txid, is_dev_class) {
        return false;
    }
    // origin_settled_link returned true ⇒ origin is Some.
    let p = match att.origin.as_ref() {
        Some(o) => &o.preimage,
        None => return false,
    };
    p.receiver_wallet_id == cheque.receiver_wallet_id
        && p.amount == cheque.amount
        && ct_eq(&p.consumed_state_id, &sender_tip.previous_state_id)
}

/// WHICH link a txid-bound proof resolves. ONE definition for every such
/// proof — no layer above Core chooses, and no second copy exists (RULE 1).
///
/// Normative: **YPX-001 §1.2.1** — a self-send (genesis claim, heal, burn,
/// RECALL, HAL) writes TWO links under ONE txid, its send leg and its
/// self-redeem leg, so a txid alone DOES NOT NAME A LINK. The proof belongs to
/// the first UNRESOLVED match (a resolved link needs no further proof); with no
/// unresolved match the first match is kept so an existing annotation still
/// reads back.
///
/// Callers: the burn annotation and the RECALL annotation in `build_fact_link`,
/// and the KI#13 burn-retire relax in `verify_fact_chain_inner_with_burn_skip`.
///
/// History — this rule has been got wrong once per layer, always by reading
/// "tx_id" as if it identified a link: KI#183 (burn, Core), KI#188 (the SDK's
/// confirmation splice), KI#189 (RECALL, Core — which kept a private
/// first-match `find` for the twelve lines between it and the burn annotation
/// already fixed here). Attach a new proof kind THROUGH THIS FUNCTION.
/// Renamed from `burn_target_index` (KI#189): the rule was never burn-specific,
/// only its name was.
pub fn unresolved_target_index(links: &[FactLink], target: &[u8; 32]) -> Option<usize> {
    links.iter().position(|l| ct_eq(&l.tx_id, target) && !link_is_resolved(l))
        .or_else(|| links.iter().position(|l| ct_eq(&l.tx_id, target)))
}

/// **THE definition of "is this FACT link resolved?" — one builder, Core-owned.**
///
/// Every consumer calls this. Do NOT re-derive the rule anywhere: not in the
/// SDK, not in a harness, not in a test. It was duplicated once (a hand-rolled
/// CBOR walk in `axiom-sdk`'s `heal.rs`) and the copy silently omitted the
/// inherited-taint clause, which made inherited scars invisible to the wallet
/// and left `burn_scars` — the only escape from them — unreachable. KI#62.
///
/// The rule, and why each clause is there:
///
/// * `burn_proof` resolves **unconditionally, inherited taint included** — the
///   tainted value is destroyed, so nothing remains to launder (YPX-001
///   §1.5.1a).
/// * otherwise the link's OWN transition must be resolved — a Nabla
///   confirmation, or a recall / KI#59 out-of-order attestation that is bound
///   to this link AND verifies (forgery-proof: a fake attestation must not
///   wash out a real scar);
/// * AND it must carry no unresolved inherited taint
///   (`FactLink::inherited_unresolved`, which clears an inherited origin ONLY
///   on a SETTLED registration — `origin_settled_link`, §1.5.1b). A
///   confirmed-but-tainted link stays scarred until the ORIGIN settles —
///   consent is not cleansing.
///
/// Normative: YPX-001 §1.5 / §1.5.1a / §1.5.1b.
pub fn link_is_resolved(link: &FactLink) -> bool {
    let recall_resolved = link.recall_proof.as_ref().is_some_and(|att| {
        ct_eq(&att.txid, &link.tx_id)
            && crate::validation::verify_recall_attestation(att).is_ok()
    });
    // KI#59 — out-of-order own-scar clearing. The state binding
    // (att.new_state_id == link.new_state_id) is what makes the attestation match
    // exactly ONE link: a forked pair (B→C, B→C') have different states, so a
    // wallet cannot mark both resolved. Nabla Ed25519 + NBC-root anchored, so a
    // forged proof cannot wash out a genuine scar.
    let ooo_resolved = link.out_of_order_confirmation.as_ref().is_some_and(|att| {
        ct_eq(&att.txid, &link.tx_id)
            && ct_eq(&att.new_state_id, &link.new_state_id)
            && crate::validation::verify_ooo_confirmation(att).is_ok()
    });
    link.burn_proof.is_some()
        || ((link.nabla_confirmation.is_some() || recall_resolved || ooo_resolved)
            && link.inherited_unresolved() == 0)
}

/// Convenience inverse of [`link_is_resolved`]. Same single definition — a scar
/// is exactly a link that is not resolved.
pub fn link_is_scarred(link: &FactLink) -> bool {
    !link_is_resolved(link)
}

/// KI#59 — the self-contained k-witness-quorum check on ONE link: `>= floor-3`
/// witnesses, each carrying a valid Dilithium signature over the recomputed
/// `compute_fact_commitment`. Reuses the SAME commitment builder + verifier the
/// full chain verify uses (RULE 1), so a link accepted here is signed by the same
/// keys Core will check.
///
/// ⚠ SCOPE: this verifies the witness SIGNATURES over the link's own carried
/// `validator_pk`s — it does NOT anchor those keys to VBC roots (that needs a
/// `FactTrust`, and is CORE's job via `verify_fact_chain_inner` when the wallet
/// presents the whole chain). Nabla calls this as griefing-HYGIENE for KI#59 (do
/// not sign an out-of-order confirmation for a garbage/under-witnessed link); the
/// AUTHORITATIVE k-witness + VBC-certification verification stays in Core (RULE 5
/// — a Nabla that skips it can only WITHHOLD a valid attestation or emit a useless
/// one, never forge a scar resolution).
pub fn verify_link_witness_quorum(link: &FactLink) -> bool {
    if link.witnesses.len() < MIN_FACT_WITNESSES {
        return false;
    }
    let commitment = compute_fact_commitment(
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
    link.witnesses.iter().all(|w| {
        crate::crypto::verify_dilithium(&w.validator_pk, &commitment, &w.signature).is_ok()
    })
}

/// YPX-001 §1.5.1a — derive the inherited-scar set for a CROSS-WALLET
/// redeem link from the verified sender chain. THE single builder (every
/// signer + verifier calls this; CLAUDE.md §12 one-builder rule):
///
///   { link.tx_id            for unresolved sender links — INCLUDING the
///                            cheque's own origin link (§1.5.1a, KI#221) }
/// ∪ { inherited txid        for sender links' inherited txids not yet
///                            cleared by `origin_settled_link` }
///   − { cheque_txid }        ONLY when `cheque_origin_settled` — CL5 has
///                            proven the cheque's origin SETTLED
///                            (`origin_settled_cl5`, §1.5.1b, ForkSettlement Q2)
///   − { ark links }          (required_k == 0 — disclosed-by-design, YPX-010)
///
/// A NON-TIP link's OWN transition counts as resolved on a Nabla confirmation,
/// a burn proof, a recall proof, or a KI#59 out-of-order confirmation
/// (consistent with `link_is_resolved`; ForkSettlement §3.1 / Fable review-1
/// #5). The cheque's OWN send link (`tx_id == cheque_txid`) is different
/// (ForkSettlement §9g [R52a], KI#221 H-0): a Nabla confirmation or an
/// out-of-order confirmation on it does NOT resolve it — a confirmation is a
/// k=1, first-seen fact about a head, not a SETTLED origin — so only
/// `cheque_origin_settled` (or a burn / recall proof) keeps it out.
///
/// Sorted ascending (BTreeSet order) ⇒ deterministic across all k signers.
/// Self-redeems (sender == receiver wallet) inherit nothing — the scar
/// already lives on the same chain; nothing crosses a wallet boundary.
/// Live coverage: `tests/ypx001_inherited_scar_gate.py` (its assertion on the
/// cheque's own txid is the OLD rule — flipped by the SDK/gates wave).
pub fn compute_inherited_scar_txids(
    sender_chain: &FactChain,
    cheque_txid: &[u8; 32],
    is_self_redeem: bool,
    cheque_origin_settled: bool,
) -> alloc::vec::Vec<[u8; 32]> {
    if is_self_redeem {
        return alloc::vec::Vec::new();
    }
    let mut set: alloc::collections::BTreeSet<[u8; 32]> = alloc::collections::BTreeSet::new();
    for link in &sender_chain.links {
        if link.required_k == 0 {
            continue; // Ark provenance — priced by Confidence Index, not consent
        }
        let is_cheque_origin = crate::crypto::ct_eq(&link.tx_id, cheque_txid);
        // ⚠ RULE 0 §4 MARKER (2026-09-28, ForkSettlement §9g [R52a], KI#221 H-0).
        // WRONG READING (as built by wave 2b-i, 22106189 → W7a): "a link with a
        // `nabla_confirmation` (or a KI#59 out-of-order confirmation) is
        // own-resolved — INCLUDING the tip, the cheque's own send — so the
        // cheque's origin is not inherited." A confirmation is a k=1,
        // FIRST-SEEN, buyable fact about a head: each leg of a parallel fork
        // (tx_a → P, tx_b → Q) is GENUINELY confirmed by the door that saw it
        // first, and the chain CL5 reads is receiver-assembled, outside the
        // cheque signature (KI#146) — so a colluding receiver splices that
        // confirmation onto its copy of the tip and the origin was never
        // inherited: the settle rule below NEVER RAN and both legs came out
        // clean. "Registered" is not "settled uncontested".
        // CORRECT READING: a confirmed tip is NOT a settled origin. For the
        // link whose `tx_id == cheque_txid` a confirmation / ooo confirmation
        // does not count; the origin is skipped ONLY when CL5 proved it SETTLED
        // (`cheque_origin_settled` ⇐ `origin_settled_cl5`). `burn_proof` /
        // `recall_proof` stay (a burned or recalled send cannot be redeemed at
        // all). NON-tip links keep the own-resolved rule unchanged.
        // Authoritative: AXIOM_DESIGN_ForkSettlement.md §9g [R52a] (spec R52a),
        // YPX-001 §1.5.1a / §1.5.1b, KI#221.
        let confirmation_resolves = !is_cheque_origin
            && (link.nabla_confirmation.is_some()
                // KI#59 out-of-order confirmation resolves the link's own
                // transition in `link_is_resolved`; be consistent here for
                // NON-tip links (ForkSettlement §3.1).
                || link.out_of_order_confirmation.is_some());
        let own_resolved = confirmation_resolves
            || link.burn_proof.is_some()
            || link.recall_proof.is_some();
        // ⚠ RULE 0 §4 MARKER (2026-09-28, KI#221, ForkSettlement §3.1).
        // WRONG READING (as-built 2026-07-12 → 2026-09-27, and the 2026-08-04
        // "misreading guard" that stood here): "the cheque's OWN txid is
        // EXCLUDED — `&& !ct_eq(&link.tx_id, cheque_txid)` — because THIS
        // redeem's txid attestation resolves it." It does not: that attestation
        // proves only NOT_REDEEMED (nobody consumed the cheque yet), never that
        // the SENDER's leg is genuinely registered. The exclusion was the leak —
        // both legs of a parallel fork (tx_a to P, tx_b to Q) came out CLEAN.
        // CORRECT: the cheque's own unresolved origin IS inherited, and is
        // skipped ONLY when CL5 proved it SETTLED (`cheque_origin_settled` ⇐
        // `origin_settled_cl5`: a registered Send leg whose preimage recomputes
        // to the cheque's txid, matches receiver/amount/sender tip, held ≥ the
        // settle floor by the vouching node). Authoritative: YPX-001 §1.5.1a +
        // §1.5.1b, AXIOM_DESIGN_ForkSettlement.md §3.1/§3.2, KI#221.
        let skip_as_settled_cheque_origin = cheque_origin_settled && is_cheque_origin;
        if !own_resolved && !skip_as_settled_cheque_origin {
            set.insert(link.tx_id);
        }
        // Transitive taint: the sender's own inherited txids propagate —
        // taint survives any number of hops until the ORIGIN settles
        // (the SAME link-level predicate `FactLink::inherited_unresolved` uses,
        // under this link's own k-signed class).
        for t in link.inherited_unresolved_txids() {
            set.insert(*t);
        }
    }
    set.into_iter().collect()
}

/// CL5's inherited-scar derivation — the WHOLE decision `modes::execute_cl5`
/// makes at its inherit site, split out so it is drivable by a unit test (RULE 6
/// 3a: no CL5 unit test reaches that site through `execute_core` — the gates
/// before it need validator-signed cheques with VBC lineage).
///
/// * `fact_chain_ref` — `redeem_fact_chain_ref`'s choice (tip IS this send,
///   KI#146). `None` on a cross-wallet redeem FAILS CLOSED
///   (`RedeemSenderAnchorMissing`, the laundering direction — 2026-07-12);
///   `None` on a self-redeem inherits nothing.
/// * `txid_attestation` — CL5's `inputs.txid_attestation`, ALREADY verified at
///   Step 3.5 (signature over the ONE payload + mandatory NBC anchor); not
///   re-verified here. `None` (k=0 offline redeem) ⇒ never settled.
/// * `is_dev_class` — the bundle class CL5 derived and binds into the FACT
///   commitment.
///
/// ForkSettlement Q2: if the cheque's origin is SETTLED (`origin_settled_cl5`
/// against the first cheque and the chain's tip), the cheque's own origin is not
/// inherited; every other unresolved sender link still is.
pub fn cl5_inherited_scar_txids(
    fact_chain_ref: Option<&FactChain>,
    cheque_bundle: &crate::types::ChequeBundle,
    txid_attestation: Option<&crate::types::NablaTxidAttestation>,
    is_self_redeem: bool,
    is_dev_class: bool,
) -> Result<alloc::vec::Vec<[u8; 32]>, ValidationError> {
    let fc = match fact_chain_ref {
        Some(fc) => fc,
        None if is_self_redeem => return Ok(alloc::vec::Vec::new()),
        None => return Err(ValidationError::RedeemSenderAnchorMissing),
    };
    let cheque = match cheque_bundle.cheques.first() {
        Some(c) => c,
        None => return Err(ValidationError::InsufficientCheques),
    };
    let settled = match (txid_attestation, fc.links.last()) {
        (Some(att), Some(tip)) => origin_settled_cl5(att, cheque, tip, is_dev_class),
        _ => false,
    };
    Ok(compute_inherited_scar_txids(fc, &cheque.txid, is_self_redeem, settled))
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
    // KI#146 (2026-09-11) — the chain a redeem verifies must be THIS SEND's:
    // its tip link carries the cheque's txid and the cheque's produced_state_id
    // (the send link's `new_state_id` IS the cheque's `produced_state_id` by
    // construction — `build_fact_link`). The cheque signature covers no chain,
    // so before this ANY chain that verified on its own could be presented in
    // the sender's place, and the redeem link's `sender_anchor` and inherited
    // scars followed the substitute. MEASURED on 57 live cheques before the
    // rule: only the FINALIZER's cheque carries the chain with the send link
    // appended (the first k−1 witnesses attach the sender's PRE-send chain,
    // whose tip is the consumed state), and every complete bundle holds one.
    // So the chooser walks the presented chains in the old priority order and
    // takes the FIRST that is this send's; none qualifying → `None`, which CL5
    // refuses as `RedeemSenderAnchorMissing`. `verify_consistency` has already
    // made every cheque agree on txid and produced_state_id, so `first` speaks
    // for the bundle.
    let first = cheque_bundle.cheques.first()?;
    let is_this_send = |fc: &FactChain| {
        fc.links.last().map_or(false, |tip| {
            ct_eq(&tip.tx_id, &first.txid) && ct_eq(&tip.new_state_id, &first.produced_state_id)
        })
    };
    cheque_bundle
        .fact_chain
        .as_ref()
        .filter(|fc| is_this_send(fc))
        .or_else(|| {
            cheque_bundle
                .cheques
                .iter()
                .filter_map(|c| c.sender_fact_chain.as_ref())
                .find(|fc| is_this_send(fc))
        })
        .or_else(|| inputs_sender_fact_chain.as_ref().filter(|fc| is_this_send(fc)))
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

/// THE one derivation of a CL5 redeem's `required_k` and whether it takes the
/// offline k=0 (receiver-as-witness) profile. Returns `(required_k, is_k0_redeem)`.
///
/// Extracted from `modes::execute_cl5` (2026-09-28, Fork Settlement wave 2b-ii)
/// because the value is now BOUND into the redeem link's FACT commitment (R4):
/// Lambda's CL5 diagnostic mirror (`consensus.rs`, FactInsufficientWitnesses
/// probe) must recompute the SAME commitment Core signed, and CL5 does not
/// surface its k (`PublicOutputs.required_k` is 0 on CL5). Same Pattern-1 shape
/// as `redeem_fact_sender_anchor` / `cl5_inherited_scar_txids` — every consumer
/// calls this, never re-derives it (RULE 1).
///
/// Rules (unchanged from the inline form):
/// * SECURITY-CL5 (H1 fix): the receiver's wallet_id encodes k (3/4/5); CL5
///   MUST honour it so a k=5 receiver requires 5 cheques. Protocol addresses
///   (BURN/DEED/FEE/DWP) default to k=3. Ref: YPX-007, YP §26.17.
/// * CHARGE-fix mirror (§10.3 / §11.4, the validation.rs Step 3 twin): a k=0
///   (Ark) RECEIVER splits by the SENDER's tier —
///   - k≥3 sender → a CHARGE redeem: online, witnessed at the SENDER's k
///     (floor `MIN_FACT_WITNESSES`), so the cheque-count gate and the redeem
///     link are NORMAL validator artifacts;
///   - k=0 sender, OFFLINE (`offline_receiver_witness` — the receiver supplies
///     its signing key) → the true k=0 profile (receiver-as-witness link);
///   - k=0 sender, ONLINE → the §12 SETTLEMENT redeem: a NORMAL k≥3 link.
///     Lambda's online CL5 never supplies `receiver_signing_key`, so it passes
///     `false`; the normal path needs harder-to-forge k=3 cheques, so this is
///     downgrade-safe.
pub fn cl5_redeem_required_k(
    cheque_bundle: &ChequeBundle,
    offline_receiver_witness: bool,
) -> Result<(u8, bool), ValidationError> {
    let receiver_wid = match cheque_bundle.receiver_wallet_id() {
        Some(wid) if !wid.is_empty() => wid,
        _ => return Err(ValidationError::InvalidWalletId),
    };
    let required_k = if receiver_wid != crate::types::BURN_ADDRESS
        && receiver_wid != crate::types::DEED_ADDRESS
        && receiver_wid != crate::types::FEE_ADDRESS
        && !receiver_wid.starts_with(crate::types::DWP_ADDRESS_PREFIX)
    {
        match crate::wallet_id::extract_security_level(receiver_wid) {
            Ok((level, _proof_type)) => level,
            Err(_) => return Err(ValidationError::InvalidWalletId),
        }
    } else {
        3 // protocol addresses default to k=3
    };
    let sender_k = cheque_bundle.cheques.first()
        .and_then(|c| crate::wallet_id::extract_security_level(&c.sender_wallet_id).ok())
        .map(|(k, _)| k)
        .unwrap_or(u8::MAX);
    Ok(if required_k == crate::wallet_id::K_ARK {
        if sender_k == crate::wallet_id::K_ARK && offline_receiver_witness {
            (crate::wallet_id::K_ARK, true) // OFFLINE ⟠ trade — receiver-as-witness
        } else {
            // charge (k≥3 sender) OR ark→ark §12 settlement (online): normal k≥3 redeem
            (sender_k.max(MIN_FACT_WITNESSES as u8), false)
        }
    } else {
        (required_k, false)
    })
}

/// Sign a FACT commitment with Dilithium (ML-DSA-65).
///
/// Computes `compute_fact_commitment(tx_id, prev_sid, new_sid, amount, sender_anchor,
/// is_dev_class, required_k, inherited_scar_txids, burn_target_tx_id)` and signs it.
/// `required_k` MUST be the value the link will declare (`FactLink::required_k`) —
/// the commitment binds it (Fork Settlement R4), so a signature made under any
/// other k fails every verifier. Production signing happens inside Core (CL3/CL5);
/// the in-tree callers are the vector generator and tests.
pub fn sign_fact_commitment(
    dilithium_sk: &[u8],
    tx_id: &[u8; 32],
    previous_state_id: &[u8; 32],
    new_state_id: &[u8; 32],
    amount: u64,
    sender_anchor: Option<&[u8; 32]>,
    is_dev_class: bool,
    required_k: u8,
    inherited_scar_txids: &[[u8; 32]],
    burn_target_tx_id: Option<&[u8; 32]>,
) -> Result<Vec<u8>, crate::types::ValidationError> {
    let commitment = compute_fact_commitment(
        tx_id, previous_state_id, new_state_id, amount, sender_anchor, is_dev_class,
        required_k, inherited_scar_txids, burn_target_tx_id,
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
    // The `required_k` Core's CL3 signed with (Fork Settlement R4) — the caller
    // must pass the value Core RETURNED for that round (`Receipt.required_k` /
    // `PublicOutputs.required_k`), never a re-derivation.
    required_k: u8,
    inherited_scar_txids: &[[u8; 32]],
    burn_target_tx_id: Option<&[u8; 32]>,
    fact_signature: &[u8],
) -> Result<(), crate::types::ValidationError> {
    let commitment = compute_fact_commitment(
        tx_id, consumed_state_id, produced_state_id, amount, sender_anchor, is_dev_class,
        required_k, inherited_scar_txids, burn_target_tx_id,
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

    // `required_k` is the SAME value stamped on the link below — the witnesses
    // must have signed a commitment over it (Fork Settlement R4).
    let commitment = compute_fact_commitment(
        txid, previous_state_id, new_state_id, amount, sender_anchor.as_ref(), is_dev_class,
        required_k, &inherited_scar_txids, burn_target_tx_id.as_ref(),
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
                // YP §26.17.6.5 B2 — the witness carries the REFERENCE to the
                // certificate its Dilithium key came from (the bundle is right
                // here; the chain carries 32 bytes, the bundle travels beside).
                let vbc_hash = sig.vbc_bundle.as_ref()
                    .map(|bundle| crate::vbc::vbc_reference_hash(&bundle.target_vbc))
                    .unwrap_or([0u8; 32]);
                fact_witnesses.push(FactWitness {
                    validator_id: sig.validator_id,
                    validator_pk: dilithium_pk,
                    signature: fact_sig.clone(),
                    vbc_hash,
                });
            }
        }
    }

    // §16 quorum floor for the DILITHIUM witness set. A k=0 Ark link
    // (`required_k == K_ARK`) carries NO validator witnesses offline — its
    // floor-1 witness is the `receiver_witness` attached post-build by the k=0
    // assemblers (`execute_ark_send_finalize` / the k=0 CL5 branch), verified by
    // the P3.2 tier branch — so the Dilithium floor is 0 there. Every online
    // link keeps the absolute 3-floor. The hardcoded `< 3` predates P3.1 and
    // made the positive k=0 assembly path unreachable
    // (`FactInsufficientWitnesses` on every offline finalize); caught by the
    // P3.7 round-trip test.
    // The mint floor is the absolute 3: a link minted with fewer than its own
    // `required_k` witnesses is a SCAR by design (heal-forward partial commit),
    // judged by `has_scars`, not refused here (KI#150 review, 2026-09-12).
    let dilithium_floor: usize = if required_k == crate::wallet_id::K_ARK { 0 } else { 3 };
    if fact_witnesses.len() < dilithium_floor {
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
        burn_proof: None,
        // §1.5.4: on a BURN TX this names the scar being destroyed and is bound
        // into the commitment above, so the k=3 witnesses attest the target.
        // None (→ zero sentinel) for every non-burn link.
        burn_target_tx_id,
        sender_anchor,
        is_dev_class,
        recall_proof: None,
        // KI#59 — attached post-round by the SDK when the wallet clears an
        // own-scar out of order; never set at build time.
        out_of_order_confirmation: None,
        inherited_scar_txids,
        inherited_scar_resolutions: alloc::vec::Vec::new(),
        // k=0 Ark receiver-witness is attached post-build by the extracted k=0
        // builder (P3.5), OUTSIDE the commitment; a normal online link never has one.
        receiver_witness: None,
    };

    let mut chain = existing_chain.cloned().unwrap_or_else(FactChain::new);
    chain.links.push(link);

    // Annotate burn target if this is a burn TX.
    //
    // KI#183 (2026-09-16) — pick the first UNRESOLVED link with that txid, not
    // the first link with that txid. A self-send (heal, burn, genesis claim)
    // writes TWO links under ONE txid: its send link and its self-redeem link.
    // When the REDEEM link is the scar, first-match put the proof on the
    // already-confirmed SEND link, the scar survived, and the wallet healed
    // forever (measured live: soak_r15, wallets 000/002/003 — `issues_found=9,
    // issues_fixed=1` on every fork for two hours, zero sends).
    //
    // A resolved link needs no proof, so skipping it cannot lose anything; two
    // UNRESOLVED links under one txid still take the first, which is correct by
    // value (one burn destroys one amount; a second burn resolves the other).
    // THE RULE LIVES HERE: Core builds and verifies the link, so no layer above
    // can be trusted to choose the target (RULE 5 — the SDK is convenience).
    if let Some(burn_target) = burn_target_tx_id {
        let burn_tx_id = *txid;
        let target_idx = unresolved_target_index(&chain.links, &burn_target);
        if let Some(target_link) = target_idx.map(|i| &mut chain.links[i]) {
            target_link.burn_proof = Some(BurnProof {
                burn_tx_id,
                validator_sigs: burn_witnesses.unwrap_or_default(),
            });
        }
    }

    // YPX-022 RECALL: attach the recall_proof to the failed link so its scar is RESOLVED
    // (verify_fact_chain_inner treats a link with a valid recall_proof as non-scarred).
    // The attestation is Nabla-signed + txid-bound, so it can only resolve a link whose
    // tx_id it actually recalled — but a txid names a TRANSACTION, not a LINK.
    //
    // KI#189 (2026-09-16) — this used to be `find(|l| ct_eq(&l.tx_id, &recall_target))`,
    // first match, under the comment "Same shape as the burn annotation". That comment
    // was true when written and STOPPED being true when KI#183's fix landed on the burn
    // annotation twelve lines above, leaving one rule with two implementations and the
    // stale one here (RULE 3 shape 7 + RULE 1). A self-send writes two links under one
    // txid (YPX-001 §1.2.1), and RECALL exists precisely to recover a FAILED send — so
    // the case where one leg is unresolved and the other is not is RECALL's normal case,
    // not an edge. First-match put the attestation on the already-resolved leg and left
    // the failed one scarred, blocking compression (§1.5) and wedging the wallet — the
    // same ending as KI#183 (burn) and KI#188 (confirmation splice).
    //
    // YPX-022 §2 requires a recall_proof to resolve its link "exactly like burn_proof";
    // sharing the selector is what makes that literally true.
    if let (Some(recall_target), Some(proof)) = (recall_target_tx_id, recall_proof) {
        let target_idx = unresolved_target_index(&chain.links, &recall_target);
        if let Some(target_link) = target_idx.map(|i| &mut chain.links[i]) {
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
            link.required_k,
            &link.inherited_scar_txids,
            link.burn_target_tx_id.as_ref(),
        );
        hasher.update(&link_commitment);
    }
    *hasher.finalize().as_bytes()
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
    // (validator_id, dilithium_pk, dilithium_sk, vbc_hash — YP §26.17.6.5 B2)
    validators: &[([u8; 32], &[u8], &[u8], [u8; 32])],
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
    for &(vid, pk, sk, vbc_hash) in validators {
        let sig = crate::crypto::sign_dilithium(sk, &cp_commitment)?;
        validator_sigs.push(FactWitness {
            validator_id: vid,
            validator_pk: pk.to_vec(),
            signature: sig,
            vbc_hash,
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
    // YP §26.17.6.5 B2 — this validator's own certificate reference.
    vbc_hash: [u8; 32],
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
                    vbc_hash,
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
                    vbc_hash,
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
        // required_k > witnesses.len() so this is a real scar (partial commit)
        // when nabla_confirmation is None. make_healed_link overrides with confirmation.
        make_test_link_k(tx_id, prev_state, new_state, amount, keys, (keys.len() + 1) as u8)
    }

    /// `make_test_link` with an explicit `required_k`. The witnesses sign a
    /// commitment over THAT k (Fork Settlement R4 binds it) — a test that wants
    /// a different k must build the link with it, never assign
    /// `link.required_k` afterwards (that is the R4 attack, and it fails verify).
    fn make_test_link_k(
        tx_id: [u8; 32],
        prev_state: [u8; 32],
        new_state: [u8; 32],
        amount: u64,
        keys: &[DilithiumTestKey],
        required_k: u8,
    ) -> FactLink {
        let commitment =
            compute_fact_commitment(&tx_id, &prev_state, &new_state, amount, None, false, required_k, &[], None);
        let mut witnesses = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let sig = crate::crypto::sign_dilithium(&key.sk, &commitment)
                .expect("test sign_dilithium");
            let mut vid = [0u8; 32];
            vid[0] = i as u8; // Unique validator_id per witness
            witnesses.push(FactWitness {
                validator_id: certified_id(&key.pk),
                validator_pk: key.pk.clone(),
                signature: sig,
                vbc_hash: certified_ref(&key.pk),
            });
        }
        FactLink {
            tx_id,
            previous_state_id: prev_state,
            new_state_id: new_state,
            amount,
            required_k,
            tick: 0,
            witnesses,
            nabla_confirmation: None,
            burn_proof: None,
            burn_target_tx_id: None,
            sender_anchor: None,
            is_dev_class: false,
            recall_proof: None,
            out_of_order_confirmation: None,
            inherited_scar_txids: Vec::new(),
            inherited_scar_resolutions: Vec::new(),
            receiver_witness: None,
        }
    }

    // ── link_is_resolved: THE one definition of a scar (KI#62) ──────────
    //
    // These live here, beside the rule, because the rule lives here. The SDK
    // used to re-derive it from CBOR and the copy dropped the inherited-taint
    // clause, which made inherited scars invisible to the wallet and left
    // `burn_scars` — their only escape — unreachable. Both sides now call
    // `link_is_resolved`, so there is one definition and one place to test it.
    fn bare_link() -> FactLink {
        FactLink {
            tx_id: [1u8; 32],
            previous_state_id: [0u8; 32],
            new_state_id: [2u8; 32],
            amount: 100,
            required_k: 3,
            tick: 0,
            witnesses: Vec::new(),
            nabla_confirmation: None,
            burn_proof: None,
            burn_target_tx_id: None,
            sender_anchor: None,
            is_dev_class: false,
            recall_proof: None,
            out_of_order_confirmation: None,
            inherited_scar_txids: Vec::new(),
            inherited_scar_resolutions: Vec::new(),
            receiver_witness: None,
        }
    }

    #[test]
    fn unregistered_link_is_a_scar() {
        assert!(link_is_scarred(&bare_link()));
        assert!(!link_is_resolved(&bare_link()));
    }

    #[test]
    fn registered_link_with_unresolved_inherited_taint_is_STILL_a_scar() {
        // The clause the SDK copy omitted. A link can be perfectly registered
        // and still be a scar, because the taint is the ORIGIN's to resolve —
        // YPX-001 §1.5.1a, "consent is not cleansing".
        let mut l = bare_link();
        l.nabla_confirmation = Some(crate::types::NablaConfirmation::default());
        assert!(link_is_resolved(&l), "control: registered, no taint => resolved");

        l.inherited_scar_txids = vec![[0xAB; 32]];
        assert!(
            link_is_scarred(&l),
            "registered BUT carrying unresolved inherited taint MUST be a scar —              if a consumer disagrees, the wallet cannot burn its way out (KI#62)"
        );
    }

    /// KI#189 — the RECALL annotation must pick the same link the burn
    /// annotation would. Drives `build_fact_link` itself, not the selector:
    /// a selector-only test still passes if this call site reverts to the
    /// private `find(|l| tx_id == target)` first-match it used until today.
    ///
    /// Shape: a self-send wrote two links under one txid (YPX-001 §1.2.1) —
    /// the SEND leg registered, the SELF-REDEEM leg failed and is the scar.
    /// The wallet then RECALLs that txid. The attestation belongs on the
    /// FAILED leg; first-match put it on the confirmed one and left the scar,
    /// blocking compression (§1.5) exactly as KI#183 and KI#188 did.
    #[test]
    fn a_recall_resolves_the_scarred_link_not_its_confirmed_twin() {
        let txid = [0xC7u8; 32];
        let mut sent = bare_link();                 // send leg — registered
        sent.tx_id = txid;
        sent.new_state_id = [0x21u8; 32];
        sent.nabla_confirmation = Some(crate::types::NablaConfirmation::default());
        let mut failed = bare_link();               // self-redeem leg — the scar
        failed.tx_id = txid;
        failed.previous_state_id = [0x21u8; 32];
        failed.new_state_id = [0x22u8; 32];
        assert!(link_is_resolved(&sent) && link_is_scarred(&failed), "fixture");

        let existing = crate::types::FactChain {
            checkpoint: None,
            links: alloc::vec![sent, failed],
        };
        let att = crate::types::RecallAttestation {
            txid,
            presend_state_hash: [0u8; 32],
            amount: 0,
            recall_tick: 1,
            nabla_node_pk: [0u8; 32],
            nabla_signature: Vec::new(),
            nbc_issuer_pk: Vec::new(),
            nbc_signature: Vec::new(),
            nbc_commitment: Vec::new(),
        };

        // The RECALL self-send's own link extends the chain from [0x22].
        // Real witness sigs over the new link's commitment — build_fact_link
        // requires k valid ones before it reaches the annotation.
        let keys = test_keys();
        let recall_txid = [0xD8u8; 32];
        let commit = compute_fact_commitment(
            &recall_txid, &[0x22u8; 32], &[0x23u8; 32], 0, None, false, 3, &[], None);
        let witness_sigs: Vec<crate::types::WitnessSig> = keys.iter().enumerate().map(|(i, key)| {
            let mut vid = [0u8; 32]; vid[0] = (i + 8) as u8;
            crate::types::WitnessSig {
                validator_id: certified_id(&key.pk),
                validator_pk: key.pk.clone(),
                signature: vec![0u8; 64],
                execution_proof: vec![],
                proof_type: 0,
                availability_attestation: None,
                carrier_type: "test".to_string(),
                carrier_address: "t".to_string(),
                vbc_bundle: Some(crate::types::VBCProofBundle {
                    target_vbc: crate::types::VBC {
                        genesis_lineage: [0u8; 32],
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
                        nabla_registration: None,
                    },
                    supporting_vbcs: vec![],
                    candidacy_pulse: None, renewal_work_receipt: None,
                }),
                fact_signature: Some(crate::crypto::sign_dilithium(&key.sk, &commit).expect("sign")),
                checkpoint_sig: None,
                receipt_signature: None,
                receipt_commitment_sig: None,
                validator_hints: vec![],
                rate_bps: 0,
                slot_amount: 0,
            }
        }).collect();

        let chain = build_fact_link(
            &recall_txid, &[0x22u8; 32], &[0x23u8; 32], 0, 3,
            &witness_sigs, None, None, false, Vec::new(), Some(&existing),
            Some(txid), Some(att),
        ).expect("recall link builds");

        assert!(chain.links[1].recall_proof.is_some(),
                "the recall_proof MUST land on the FAILED self-redeem leg (index 1)");
        assert!(chain.links[0].recall_proof.is_none(),
                "the already-registered send leg MUST NOT be annotated — it needs no proof, \
                 and annotating it leaves the real scar unresolved (KI#189)");
        // Deliberately NOT asserted here: that link 1 now reads RESOLVED.
        // `link_is_resolved` requires `verify_recall_attestation` to pass, i.e.
        // a real Nabla signature this fixture has no cheap way to mint — and
        // that gate is correct and must stay. Resolution GIVEN a valid
        // attestation is already pinned by `recall_proof_resolves_and_is_compressible`.
        // This test owns the question that one cannot answer: WHICH link the
        // proof is attached to (KI#189).
    }

    /// KI#183 — a self-send writes TWO links under one txid. The burn must
    /// resolve the SCARRED one; first-match put the proof on the confirmed
    /// sibling and the scar survived every heal (soak_r15, wallets 000/002/003).
    #[test]
    fn a_burn_targets_the_scarred_link_not_its_confirmed_twin() {
        let txid = [0xA5u8; 32];
        let mut sent = bare_link();          // the self-send's SEND link — registered
        sent.tx_id = txid;
        sent.nabla_confirmation = Some(crate::types::NablaConfirmation::default());
        let mut redeemed = bare_link();      // its SELF-REDEEM link — the scar
        redeemed.tx_id = txid;
        let links = alloc::vec![sent.clone(), redeemed.clone()];
        assert!(link_is_resolved(&links[0]) && link_is_scarred(&links[1]));
        assert_eq!(unresolved_target_index(&links, &txid), Some(1), "the burn resolves the SCAR, not its confirmed twin");

        // Both unresolved: the first is taken — one burn destroys one amount,
        // a second burn resolves the other.
        let both = alloc::vec![redeemed.clone(), redeemed.clone()];
        assert_eq!(unresolved_target_index(&both, &txid), Some(0));

        // Already annotated (nothing unresolved): the existing annotation still reads back.
        let mut burned = redeemed.clone();
        burned.burn_proof = Some(crate::types::BurnProof { burn_tx_id: [9u8; 32], validator_sigs: Vec::new() });
        let resolved_only = alloc::vec![sent, burned];
        assert_eq!(unresolved_target_index(&resolved_only, &txid), Some(0));

        // A txid nobody carries names no link (the relax must not transfer).
        assert_eq!(unresolved_target_index(&links, &[0xFFu8; 32]), None);
    }

    #[test]
    fn a_burn_resolves_inherited_taint_too() {
        // Unconditional by design: the tainted value is destroyed, so there is
        // nothing left to launder (YPX-001 §1.5.1a).
        let mut l = bare_link();
        l.inherited_scar_txids = vec![[0xAB; 32]];
        assert!(link_is_scarred(&l));
        l.burn_proof = Some(crate::types::BurnProof {
            burn_tx_id: [9u8; 32],
            validator_sigs: Vec::new(),
        });
        assert!(link_is_resolved(&l), "a burn discharges inherited taint");
    }

    // SEC-07: 5 keys so make_validators() yields a checkpoint with
    // CHECKPOINT_SIG_THRESHOLD (5) distinct sigs — a finalized checkpoint that
    // passes verify_checkpoint. Link witnesses use the same keys (>= MIN_FACT_WITNESSES).
    /// Five Dilithium keys that the fixture CERTIFIED (YP §26.17.6.5 B2): each
    /// has a depth-0 certificate signed by three test roots, so a link they
    /// witness takes the production binding path. `uncertified_keys` is the
    /// old behaviour — fresh keys nobody vouched for.
    fn test_keys() -> Vec<DilithiumTestKey> {
        certified_validators().iter()
            .map(|v| DilithiumTestKey { pk: v.key.pk.clone(), sk: v.key.sk.clone() })
            .collect()
    }

    fn uncertified_keys(n: usize) -> Vec<DilithiumTestKey> {
        (0..n).map(|_| {
            let (pk_obj, sk_obj) = ml_dsa_65::try_keygen()
                .expect("Dilithium keygen failed");
            DilithiumTestKey {
                pk: pk_obj.into_bytes().to_vec(),
                sk: sk_obj.into_bytes().to_vec(),
            }
        }).collect()
    }

    // ── YP §26.17.6.5 fixture: REAL certificates through the production path ──
    extern crate std;
    use std::sync::OnceLock;
    use crate::types::{VBC, VBCProofBundle};

    /// A validator the fixture certified: three test roots (authorized through
    /// `genesis::test_roots`) signed a depth-0 certificate over its SPHINCS+
    /// identity and its Dilithium witness key.
    struct CertifiedValidator {
        validator_id: [u8; 32],
        key: DilithiumTestKey,
        bundle: VBCProofBundle,
        reference: [u8; 32],
    }

    /// (sphincs_pk, sphincs_sk) triples — the roots of the fixture universe.
    fn test_root_keys() -> &'static Vec<(Vec<u8>, Vec<u8>)> {
        static ROOTS: OnceLock<Vec<(Vec<u8>, Vec<u8>)>> = OnceLock::new();
        ROOTS.get_or_init(|| {
            use fips205::slh_dsa_sha2_128s;
            use fips205::traits::SerDes as SphincsSerDes;
            let roots: Vec<(Vec<u8>, Vec<u8>)> = (0..3).map(|_| {
                let (pk, sk) = slh_dsa_sha2_128s::try_keygen().expect("sphincs keygen");
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }).collect();
            for (pk, _) in &roots {
                crate::genesis::test_roots::authorize(pk.as_slice().try_into().unwrap());
            }
            roots
        })
    }

    /// Issue a depth-0 certificate for a FRESH validator, signed by `roots`
    /// (which need not be the authorized ones — that is how a foreign-root
    /// certificate is made), with the given lifetime.
    fn certify_with(roots: &[(Vec<u8>, Vec<u8>)], issued_at: u64, expires_at: u64) -> CertifiedValidator {
        use fips205::slh_dsa_sha2_128s;
        use fips205::traits::SerDes as SphincsSerDes;
        let (spk, _ssk) = slh_dsa_sha2_128s::try_keygen().expect("sphincs keygen");
        let sphincs_pk = spk.into_bytes().to_vec();
        let (pk_obj, sk_obj) = ml_dsa_65::try_keygen().expect("Dilithium keygen failed");
        let key = DilithiumTestKey { pk: pk_obj.into_bytes().to_vec(), sk: sk_obj.into_bytes().to_vec() };
        let validator_id = crate::crypto::compute_validator_id(&sphincs_pk);
        let mut vbc = VBC {
            genesis_lineage: [0u8; 32],
            network_size_baseline: 0,
            baseline_tick: 0,
            version: 0x09,
            validator_id,
            subject_pubkey_sphincs: sphincs_pk,
            subject_pubkey_dilithium: key.pk.clone(),
            subject_pubkey_ed25519: vec![0x11u8; 32],
            pgp_fingerprint: vec![],
            node_name: alloc::string::String::new(),
            issued_at,
            expires_at,
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
        let reference = crate::vbc::vbc_reference_hash(&vbc);
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None };
        CertifiedValidator { validator_id, key, bundle, reference }
    }

    fn certified_validators() -> &'static Vec<CertifiedValidator> {
        static FIXTURE: OnceLock<Vec<CertifiedValidator>> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let roots = test_root_keys();
            (0..5).map(|_| certify_with(roots, 1_000, u64::MAX)).collect()
        })
    }

    /// The fixture identity behind a Dilithium key: certified → its
    /// certificate's `validator_id` / reference; a fresh uncertified key →
    /// `BLAKE3(pk)` and the zero reference (resolves to nothing).
    fn certified_id(pk: &[u8]) -> [u8; 32] {
        certified_validators().iter().find(|v| v.key.pk.as_slice() == pk)
            .map(|v| v.validator_id)
            .unwrap_or(*blake3::hash(pk).as_bytes())
    }
    fn certified_ref(pk: &[u8]) -> [u8; 32] {
        certified_validators().iter().find(|v| v.key.pk.as_slice() == pk)
            .map(|v| v.reference)
            .unwrap_or([0u8; 32])
    }

    /// The certificate set every fixture chain is verified against.
    fn test_certificates() -> &'static Vec<VBCProofBundle> {
        static CERTS: OnceLock<Vec<VBCProofBundle>> = OnceLock::new();
        CERTS.get_or_init(|| certified_validators().iter().map(|v| v.bundle.clone()).collect())
    }
    fn test_trust() -> FactTrust<'static> {
        FactTrust::new(test_certificates(), None)
    }
    fn test_certified() -> CertifiedSet {
        certify_presented(test_certificates()).expect("fixture certificates verify")
    }

    /// (validator_id, dilithium_pk, dilithium_sk, vbc_hash) for `compress_fact_chain`.
    fn test_validators(keys: &[DilithiumTestKey]) -> Vec<([u8; 32], &[u8], &[u8], [u8; 32])> {
        keys.iter().map(|k| (certified_id(&k.pk), k.pk.as_slice(), k.sk.as_slice(), certified_ref(&k.pk))).collect()
    }
    
    #[test]
    fn test_empty_chain_valid() {
        let chain = FactChain::new();
        let result = verify_fact_chain(&chain, &test_trust());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }
    
    #[test]
    fn test_single_link_chain() {
        let keys = test_keys();
        let link = make_test_link([1u8; 32], [0u8; 32], [2u8; 32], 1000, &keys);
        let chain = FactChain { checkpoint: None, links: vec![link] };
        let result = verify_fact_chain(&chain, &test_trust());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1); // 1 scar (no nabla)
    }
    
    /// KI#145 (2026-09-11) — CLOSED by YP §26.17.6.5 B2. This test pinned the
    /// gap (a witness from a fresh keypair nobody certified passed with a bare
    /// public root key at the end of a list). It now pins the rule: the same
    /// uncertified witnesses are `FactWitnessUncertified`, and the chain is
    /// accepted only when every witness resolves to a certificate presented
    /// with the execution and verified to the roots.
    #[test]
    fn ki145_uncertified_witnesses_are_refused_certified_ones_bind() {
        let fresh = uncertified_keys(3); // no certificate exists for these
        let link = make_test_link([1u8; 32], [0u8; 32], [2u8; 32], 1000, &fresh);
        assert!(link.witnesses.iter().all(|w| w.vbc_hash == [0u8; 32]), "fixture: no reference");
        let chain = FactChain { checkpoint: None, links: vec![link] };
        assert_eq!(verify_fact_chain(&chain, &test_trust()), Err(ValidationError::FactWitnessUncertified));

        // The same shape with certified validators binds — and ONLY with their
        // certificates present: an empty certificate set is a refusal, never a lookup.
        let link = make_test_link([1u8; 32], [0u8; 32], [2u8; 32], 1000, &test_keys()[..3]);
        let chain = FactChain { checkpoint: None, links: vec![link] };
        assert!(verify_fact_chain(&chain, &test_trust()).is_ok());
        assert_eq!(verify_fact_chain(&chain, &FactTrust::new(&[], None)),
                   Err(ValidationError::FactWitnessUncertified));
    }

    /// B2 — a certificate from OTHER roots verifies structurally but not to
    /// this Core's roots: the whole execution is refused (`FactCertificateInvalid`),
    /// so a chain from another network (another worldline) cannot be presented.
    #[test]
    fn b2_certificate_from_foreign_roots_is_refused() {
        use fips205::slh_dsa_sha2_128s;
        use fips205::traits::SerDes as SphincsSerDes;
        let foreign: Vec<(Vec<u8>, Vec<u8>)> = (0..3).map(|_| {
            let (pk, sk) = slh_dsa_sha2_128s::try_keygen().unwrap();
            (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
        }).collect();
        let stranger = certify_with(&foreign, 1_000, u64::MAX);
        let keys = vec![DilithiumTestKey { pk: stranger.key.pk.clone(), sk: stranger.key.sk.clone() }];
        let mut link = make_test_link_k([1u8; 32], [0u8; 32], [2u8; 32], 1000, &keys, 3);
        link.witnesses[0].validator_id = stranger.validator_id;
        link.witnesses[0].vbc_hash = stranger.reference;
        // pad to k=3 with certified witnesses so the ONLY defect is the foreign certificate
        // (every piece signs the SAME k=3 commitment — `required_k` is bound, R4)
        let padded = make_test_link_k([1u8; 32], [0u8; 32], [2u8; 32], 1000, &test_keys()[..2], 3);
        link.witnesses.extend(padded.witnesses);
        let chain = FactChain { checkpoint: None, links: vec![link] };
        let mut certs = test_certificates().clone();
        certs.push(stranger.bundle.clone());
        assert_eq!(verify_fact_chain(&chain, &FactTrust::new(&certs, None)),
                   Err(ValidationError::FactCertificateInvalid));
    }

    /// B2 — the witness must have signed with the CERTIFICATE's Dilithium key
    /// and carry the certificate's validator_id: a valid certificate presented
    /// beside a witness that used another key, or another id, does not bind.
    #[test]
    fn b2_witness_keys_must_match_the_certificate() {
        let certified = &certified_validators()[0];
        let stranger = uncertified_keys(1).remove(0);
        // signed with a stranger's key, but pointing at a real certificate
        let mut link = make_test_link_k([1u8; 32], [0u8; 32], [2u8; 32], 1000,
            &[DilithiumTestKey { pk: stranger.pk.clone(), sk: stranger.sk.clone() }], 3);
        link.witnesses[0].validator_id = certified.validator_id;
        link.witnesses[0].vbc_hash = certified.reference;
        link.witnesses.extend(make_test_link_k([1u8; 32], [0u8; 32], [2u8; 32], 1000, &test_keys()[1..3], 3).witnesses);
        let chain = FactChain { checkpoint: None, links: vec![link] };
        assert_eq!(verify_fact_chain(&chain, &test_trust()), Err(ValidationError::FactWitnessUncertified));

        // right key, wrong validator_id
        let mut link = make_test_link_k([1u8; 32], [0u8; 32], [2u8; 32], 1000, &test_keys()[..3], 3);
        link.witnesses[0].validator_id = [0xEE; 32];
        let chain = FactChain { checkpoint: None, links: vec![link] };
        assert_eq!(verify_fact_chain(&chain, &test_trust()), Err(ValidationError::FactWitnessUncertified));
    }

    /// B2 — a PROVISIONAL certificate (a candidate's, §5.2.2a) verifies to the
    /// roots yet certifies no witness: k=3 forged witnesses must not cost three
    /// free candidacies.
    #[test]
    fn b2_provisional_certificate_cannot_witness() {
        let candidate = certify_with(test_root_keys(), 1_000, 1_000 + 6 * 3600);
        assert!(crate::validation::vbc_is_provisional(1_000, 1_000 + 6 * 3600));
        let mut link = make_test_link_k([1u8; 32], [0u8; 32], [2u8; 32], 1000,
            &[DilithiumTestKey { pk: candidate.key.pk.clone(), sk: candidate.key.sk.clone() }], 3);
        link.witnesses[0].validator_id = candidate.validator_id;
        link.witnesses[0].vbc_hash = candidate.reference;
        link.witnesses.extend(make_test_link_k([1u8; 32], [0u8; 32], [2u8; 32], 1000, &test_keys()[..2], 3).witnesses);
        let chain = FactChain { checkpoint: None, links: vec![link] };
        let mut certs = test_certificates().clone();
        certs.push(candidate.bundle.clone());
        assert_eq!(verify_fact_chain(&chain, &FactTrust::new(&certs, None)),
                   Err(ValidationError::FactWitnessUncertified));
    }

    /// B1 — the chain must start at the opening state the verifier derives for
    /// the wallet; with a checkpoint, that is the checkpoint's genesis_state_id.
    #[test]
    fn b1_chain_must_start_at_the_derived_opening_state() {
        let keys = test_keys();
        let origin = [0x0Au8; 32];
        let link = make_test_link([1u8; 32], origin, [2u8; 32], 1000, &keys[..3]);
        let chain = FactChain { checkpoint: None, links: vec![link] };
        assert!(verify_fact_chain(&chain, &FactTrust::new(test_certificates(), Some(origin))).is_ok());
        assert_eq!(verify_fact_chain(&chain, &FactTrust::new(test_certificates(), Some([0x0Bu8; 32]))),
                   Err(ValidationError::FactOriginInvalid));

        // compressed: the checkpoint's genesis_state_id is the origin
        let chain = make_chain(&keys, &vec![true; 8]);
        let compressed = compress_fact_chain(chain, &test_validators(&keys)).unwrap();
        let cp_origin = compressed.checkpoint.as_ref().unwrap().genesis_state_id;
        assert!(verify_fact_chain(&compressed, &FactTrust::new(test_certificates(), Some(cp_origin))).is_ok());
        assert_eq!(verify_fact_chain(&compressed, &FactTrust::new(test_certificates(), Some([0x0Bu8; 32]))),
                   Err(ValidationError::FactOriginInvalid));
    }

    /// B3 — a checkpoint's cosigners are bound like witnesses: an uncertified
    /// cosigner (even with a valid Dilithium signature) does not count.
    #[test]
    fn b3_checkpoint_cosigners_must_be_certified() {
        let keys = test_keys();
        let chain = make_chain(&keys, &vec![true; 8]);
        let mut compressed = compress_fact_chain(chain, &test_validators(&keys)).unwrap();
        assert!(verify_fact_chain(&compressed, &test_trust()).is_ok());
        let cp = compressed.checkpoint.as_mut().unwrap();
        let stranger = uncertified_keys(1).remove(0);
        let commitment = compute_checkpoint_commitment(cp);
        cp.validator_sigs[0] = FactWitness {
            validator_id: *blake3::hash(&stranger.pk).as_bytes(),
            validator_pk: stranger.pk.clone(),
            signature: crate::crypto::sign_dilithium(&stranger.sk, &commitment).unwrap(),
            vbc_hash: [0u8; 32],
        };
        assert_eq!(verify_fact_chain(&compressed, &test_trust()), Err(ValidationError::FactWitnessUncertified));
    }

    /// The reference is over the SIGNED certificate, not the bundle's layout:
    /// a stamp or a candidacy Pulse beside the certificate does not move it.
    #[test]
    fn vbc_reference_hash_is_over_the_signed_certificate_only() {
        let v = &certified_validators()[0];
        let mut with_pulse = v.bundle.clone();
        with_pulse.supporting_vbcs.push(v.bundle.target_vbc.clone());
        assert_eq!(crate::vbc::vbc_reference_hash(&with_pulse.target_vbc), v.reference);
        let mut other = v.bundle.target_vbc.clone();
        other.issued_at += 1;
        assert_ne!(crate::vbc::vbc_reference_hash(&other), v.reference, "a re-issued certificate is another reference");
    }

    #[test]
    fn test_chain_continuity() {
        let keys = test_keys();
        let link1 = make_test_link([1u8; 32], [0u8; 32], [2u8; 32], 1000, &keys);
        let link2 = make_test_link([3u8; 32], [2u8; 32], [4u8; 32], 500, &keys);
        let chain = FactChain { checkpoint: None, links: vec![link1, link2] };
        let result = verify_fact_chain(&chain, &test_trust());
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_chain_break_detected() {
        let keys = test_keys();
        let link1 = make_test_link([1u8; 32], [0u8; 32], [2u8; 32], 1000, &keys);
        let link2 = make_test_link([3u8; 32], [99u8; 32], [4u8; 32], 500, &keys); // BREAK
        let chain = FactChain { checkpoint: None, links: vec![link1, link2] };
        let result = verify_fact_chain(&chain, &test_trust());
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
            burn_proof: None,
            burn_target_tx_id: None,
            sender_anchor: None,
            is_dev_class,
            recall_proof: None,
            out_of_order_confirmation: None,
            inherited_scar_txids: Vec::new(),
            inherited_scar_resolutions: Vec::new(),
            receiver_witness: None,
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
        assert!(verify_fact_chain(&chain, &test_trust()).is_err());
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
        assert!(verify_fact_chain(&make(MAX_FACT_DEPTH + 1), &test_trust()).is_ok(),
            "depth {} is fine under the travel model", MAX_FACT_DEPTH + 1);
        // Only past FACT_HARD_CEILING is it rejected.
        assert!(matches!(verify_fact_chain(&make(FACT_HARD_CEILING + 1), &test_trust()),
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
        let result = verify_fact_chain(&chain, &test_trust());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 10); // all 10 are scars
    }
    
    #[test]
    fn test_insufficient_witnesses_rejected() {
        let keys = test_keys();
        let mut link = make_test_link([1u8; 32], [0u8; 32], [2u8; 32], 1000, &keys);
        link.witnesses.truncate(2); // Only 2, need 3
        let chain = FactChain { checkpoint: None, links: vec![link] };
        let result = verify_fact_chain(&chain, &test_trust());
        assert!(result.is_err());
    }
    
    #[test]
    fn test_bad_signature_rejected() {
        let keys = test_keys();
        let mut link = make_test_link([1u8; 32], [0u8; 32], [2u8; 32], 1000, &keys);
        link.witnesses[0].signature = vec![0u8; 64]; // corrupted
        let chain = FactChain { checkpoint: None, links: vec![link] };
        let result = verify_fact_chain(&chain, &test_trust());
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
        h.update(b"AXIOM_FACT_CONFIRM");
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

    /// Build a genuine BURN TX link (send to BURN_ADDRESS) that destroyed the
    /// scar `target` for `amount`. Mirrors production `build_fact_link`: the
    /// witnesses sign `compute_fact_commitment(.., burn_target=Some(target))`,
    /// so the burn's target is k-witnessed and cannot be re-pointed. Returns
    /// the burn link; attach `BurnProof { burn_tx_id: <its tx_id>, validator_sigs }`
    /// to the target link to resolve it.
    fn make_burn_link(
        tx_id: [u8; 32],
        prev_state: [u8; 32],
        new_state: [u8; 32],
        amount: u64,
        target: [u8; 32],
        keys: &[DilithiumTestKey],
    ) -> FactLink {
        let commitment = compute_fact_commitment(
            &tx_id, &prev_state, &new_state, amount, None, false, keys.len() as u8, &[], Some(&target),
        );
        let mut witnesses = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let sig = crate::crypto::sign_dilithium(&key.sk, &commitment)
                .expect("test sign_dilithium");
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            witnesses.push(FactWitness {
                validator_id: certified_id(&key.pk),
                validator_pk: key.pk.clone(),
                signature: sig,
                vbc_hash: certified_ref(&key.pk),
            });
        }
        FactLink {
            tx_id,
            previous_state_id: prev_state,
            new_state_id: new_state,
            amount,
            required_k: keys.len() as u8, // fully witnessed — the burn TX itself is not a scar
            tick: 0,
            witnesses,
            nabla_confirmation: None,
            burn_proof: None,
            burn_target_tx_id: Some(target),
            sender_anchor: None,
            is_dev_class: false,
            recall_proof: None,
            out_of_order_confirmation: None,
            inherited_scar_txids: Vec::new(),
            inherited_scar_resolutions: Vec::new(),
            receiver_witness: None,
        }
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
        assert!(verify_fact_link(&good, &test_certified()).is_ok());

        let mut tampered = good.clone();
        // Replace the conf with one bound to a different transition.
        tampered.nabla_confirmation = Some(sign_nabla_confirmation(&[0x99; 32], &[0x98; 32]));
        assert_eq!(
            verify_fact_link(&tampered, &test_certified()),
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

        let validators = test_validators(&keys);

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

        let validators = test_validators(&keys);

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

        let validators = test_validators(&keys);

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

        let validators = test_validators(&keys);

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

        let validators = test_validators(&keys);

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
        let validators = test_validators(&keys);

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

    /// KI#173 bug 3 — `FactLink.receiver_contact` was removed with the YPX-001
    /// §1.5.3 push path. Links already stored in wallets carry that key (Lambda
    /// filled it on every send link); they must still decode, and the removal
    /// must not change what the link commits to.
    #[test]
    fn stored_link_with_the_removed_receiver_contact_still_decodes() {
        let keys = test_keys();
        let link = make_test_link([1u8; 32], [0u8; 32], [2u8; 32], 1000, &keys);
        let mut bytes = alloc::vec::Vec::new();
        ciborium::into_writer(&link, &mut bytes).unwrap();
        let mut value: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        let map = match &mut value { ciborium::Value::Map(m) => m, _ => panic!("link is a map") };
        map.push((
            ciborium::Value::Text("receiver_contact".into()),
            ciborium::Value::Map(alloc::vec![
                (ciborium::Value::Text("wallet_id".into()), ciborium::Value::Text("bob@example.com/a3f7b232".into())),
                (ciborium::Value::Text("email".into()), ciborium::Value::Text("bob@example.com".into())),
            ]),
        ));
        let mut old_bytes = alloc::vec::Vec::new();
        ciborium::into_writer(&value, &mut old_bytes).unwrap();
        let decoded: FactLink = ciborium::from_reader(old_bytes.as_slice()).unwrap();
        assert_eq!(decoded.tx_id, link.tx_id);
        assert_eq!(decoded.witnesses.len(), link.witnesses.len());
        let commit = |l: &FactLink| compute_fact_commitment(
            &l.tx_id, &l.previous_state_id, &l.new_state_id, l.amount,
            l.sender_anchor.as_ref(), l.is_dev_class, l.required_k, &l.inherited_scar_txids,
            l.burn_target_tx_id.as_ref());
        assert_eq!(commit(&decoded), commit(&link));
    }

    #[test]
    fn test_scar_count() {
        let keys = test_keys();
        let mut link1 = make_test_link([1u8; 32], [0u8; 32], [2u8; 32], 1000, &keys);
        link1.nabla_confirmation = Some(sign_nabla_confirmation(&[0u8; 32], &[2u8; 32])); // healed
        let link2 = make_test_link([3u8; 32], [2u8; 32], [4u8; 32], 500, &keys); // scarred
        let chain = FactChain { checkpoint: None, links: vec![link1, link2] };
        let result = verify_fact_chain(&chain, &test_trust());
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
        // Self-consistent burned link: the link burns itself, so its
        // commitment-bound `burn_target_tx_id` names its own tx_id and the
        // amount trivially matches. Passes the §1.5.4 chain-scoped burn check
        // (used by the compression tests, which care about resolved-ness, not
        // the two-link send/burn split). make_burn_link signs the commitment
        // WITH the burn target so the witnesses attest it.
        let mut link = make_burn_link(tx_id, prev_state, new_state, amount, tx_id, keys);
        link.burn_proof = Some(crate::types::BurnProof {
            burn_tx_id: tx_id,
            validator_sigs: link.witnesses.clone(),
        });
        link
    }

    // ── YPX-001 §1.5.1a scar inheritance + §1.5.1b settled origin ───────
    // (CORE RULE, 2026-07-12; clearing rule REPLACED 2026-09-28, KI#221 /
    // AXIOM_DESIGN_ForkSettlement.md §3.) Pins: derivation (unresolved incl.
    // the cheque's OWN origin − settled cheque origin − ark, transitive,
    // sorted, self-redeem empty), the settled-origin predicate in both forms,
    // commitment binding (strip ⇒ sig fail), the signed payload binding
    // (origin + registered tick), and the compression defence in depth.

    /// A registered SEND leg's preimage and the txid it recomputes to.
    fn origin_leg(amount: u64) -> (crate::types::WitnessPreimage, u64, [u8; 32]) {
        let p = crate::types::WitnessPreimage {
            consumed_state_id: [0x31; 32],
            client_pk: [0xA1; 32],
            wallet_seq: 7,
            receiver_wallet_id: "receiver@test.com#42".into(),
            amount,
            nonce: 99,
        };
        let epoch = 500;
        let txid = p.txid(epoch);
        (p, epoch, txid)
    }

    /// An attestation vouching for `preimage` (kind Send) as registered at
    /// `registered_at`, signed at `nabla_tick`. UNSIGNED: the settled-origin
    /// predicate judges CLEARING, not validity — validity is
    /// `verify_fact_link_internal`'s job (pinned separately below).
    fn origin_att(
        txid: [u8; 32],
        preimage: &crate::types::WitnessPreimage,
        epoch: u64,
        registered_at: u64,
        nabla_tick: u64,
        status: &str,
    ) -> crate::types::NablaTxidAttestation {
        crate::types::NablaTxidAttestation {
            txid,
            status: status.into(),
            nabla_tick,
            origin: Some(crate::types::OriginRecord {
                preimage: preimage.clone(),
                epoch,
                kind: crate::types::LegKind::Send,
            }),
            sender_registered_at_tick: registered_at,
            // A HEALTHY vouching node (ForkSettlement §9h [R53]); the unhealthy
            // case is `unhealthy_oods_attestation_never_settles`.
            oods_size: 100,
            oods_healthy: true,
            // A vouching node signs `Vouched` with its origin (§9p consistency).
            origin_status: crate::types::OriginVouchStatus::Vouched,
            ..Default::default()
        }
    }

    /// The register VALUES the floors below are pinned to (ForkSettlement Q1):
    /// real 40 ticks = 200 s, dev twin 8 ticks = 40 s. A register edit must
    /// be a deliberate edit here too.
    #[test]
    fn scar_settle_registers_are_the_ruled_values() {
        assert_eq!(crate::validation::SCAR_SETTLE_TICKS.ticks(), 40);
        assert_eq!(crate::validation::SCAR_SETTLE_TICKS_DEV.ticks(), 8);
        assert_eq!(crate::validation::SCAR_SETTLE_TICKS.to_secs(), 200);
        assert_eq!(crate::validation::SCAR_SETTLE_TICKS_DEV.to_secs(), 40);
    }

    /// W7a (spec R52i) — `settle_floor_secs` IS the floor `origin_settle_ready_at`
    /// adds, for both twins; Nabla's vouch / door WAIT read this, never a copy.
    /// MUTATION: return the real floor for dev (or a hard-coded 48-tick value)
    /// → the twin / equality assertions go red.
    #[test]
    fn settle_floor_secs_is_the_one_floor_both_twins() {
        assert_eq!(settle_floor_secs(false), crate::validation::SCAR_SETTLE_TICKS.to_secs());
        assert_eq!(settle_floor_secs(true), crate::validation::SCAR_SETTLE_TICKS_DEV.to_secs());
        assert_eq!((settle_floor_secs(false), settle_floor_secs(true)), (200, 40));
        let (p, epoch, txid) = origin_leg(5_000);
        let att = origin_att(txid, &p, epoch, 1_000, 1_000, "NOT_REDEEMED");
        for dev in [false, true] {
            assert_eq!(origin_settle_ready_at(&att, &txid, dev), Some(1_000 + settle_floor_secs(dev)),
                "ready_at = registered_at + settle_floor_secs (dev={dev})");
        }
    }

    /// ForkSettlement §9h [R53] — a vouch signed while the node's OWN OODS
    /// reading was UNHEALTHY never settles, in every form: no ready time, the
    /// link form fails at any tick, the CL5 form fails, and the whole CL5
    /// inherit decision inherits the cheque's origin. The same attestation
    /// with a HEALTHY reading settles at `registered_at + floor` (control).
    /// MUTATION: delete the `if !att.oods_healthy { return None; }` gate in
    /// `origin_settle_ready_at` → THIS test goes red (the unhealthy
    /// assertions).
    #[test]
    fn unhealthy_oods_attestation_never_settles() {
        let keys = test_keys();
        let (p, epoch, txid) = origin_leg(5_000);
        let healthy = origin_att(txid, &p, epoch, 1_000, 1_200, "NOT_REDEEMED");
        assert!(healthy.oods_healthy, "fixture: origin_att is a healthy node");
        let mut unhealthy = healthy.clone();
        unhealthy.oods_healthy = false;
        unhealthy.oods_size = 10; // e.g. eclipsed: < 1/3 of its baseline

        for dev in [false, true] {
            assert_eq!(origin_settle_ready_at(&healthy, &txid, dev), Some(1_000 + settle_floor_secs(dev)),
                "control: healthy + floor settles (dev={dev})");
            assert_eq!(origin_settle_ready_at(&unhealthy, &txid, dev), None,
                "an UNHEALTHY vouch has no ready time — it is never Settling (dev={dev})");
            for tick in [1_000u64, 1_200, 1_000_000] {
                let mut u = unhealthy.clone();
                u.nabla_tick = tick;
                assert!(!origin_settled_link(&u, &txid, dev),
                    "an UNHEALTHY vouch never settles, even far past the floor (tick={tick}, dev={dev})");
            }
        }
        assert!(origin_settled_link(&healthy, &txid, false), "control: healthy at the floor settles");

        let mut tip = bare_link();
        tip.tx_id = txid;
        tip.previous_state_id = p.consumed_state_id;
        let cheque = origin_cheque(txid, &p.receiver_wallet_id, p.amount);
        assert!(origin_settled_cl5(&healthy, &cheque, &tip, false), "control: CL5 form settles when healthy");
        assert!(!origin_settled_cl5(&unhealthy, &cheque, &tip, false), "CL5 form: unhealthy never settles");

        // Through the whole CL5 inherit decision: unhealthy ⇒ the origin IS inherited.
        let mut chain = FactChain::new();
        chain.links.push(make_test_link(txid, p.consumed_state_id, [0x44; 32], p.amount, &keys));
        let bundle = crate::types::ChequeBundle { cheques: vec![cheque], fact_chain: None };
        assert!(cl5_inherited_scar_txids(Some(&chain), &bundle, Some(&healthy), false, false).unwrap().is_empty());
        assert_eq!(cl5_inherited_scar_txids(Some(&chain), &bundle, Some(&unhealthy), false, false).unwrap(), vec![txid],
            "an unhealthy vouch leaves the cheque's origin inherited");
    }

    /// [R53] the OODS reading is SIGNED: `txid_attest_payload` binds both
    /// `oods_size` and `oods_healthy`, so a relay cannot flip an unhealthy
    /// node's attestation to healthy. MUTATION: drop either `hasher.update`
    /// in the builder → red.
    #[test]
    fn txid_attest_payload_binds_oods_reading() {
        const U: crate::types::OriginVouchStatus = crate::types::OriginVouchStatus::Unknown;
        let base = crate::crypto::txid_attest_payload(&[9u8; 32], "NOT_REDEEMED", 7, None, 0, 100, true, U);
        assert_ne!(base, crate::crypto::txid_attest_payload(&[9u8; 32], "NOT_REDEEMED", 7, None, 0, 100, false, U),
            "flipping oods_healthy changes the signed payload");
        assert_ne!(base, crate::crypto::txid_attest_payload(&[9u8; 32], "NOT_REDEEMED", 7, None, 0, 101, true, U),
            "changing oods_size changes the signed payload");
    }

    /// ForkSettlement §9p: the origin STATUS is SIGNED — every one of the three
    /// values gives a distinct payload, so a relay cannot turn a node's `Held`
    /// into `Unknown` (or `Vouched`) under the same signature. MUTATION: drop
    /// the `origin_status` `hasher.update` in `crypto::txid_attest_payload` →
    /// red (and `inherited_resolution_payload_binds_origin_and_registration_tick`
    /// red at its status-flip case).
    #[test]
    fn txid_attest_payload_binds_origin_status() {
        use crate::types::OriginVouchStatus as S;
        let at = |st: S| crate::crypto::txid_attest_payload(&[9u8; 32], "NOT_REDEEMED", 7, None, 0, 100, true, st);
        assert_ne!(at(S::Unknown), at(S::Held), "Unknown vs Held must sign differently");
        assert_ne!(at(S::Unknown), at(S::Vouched), "Unknown vs Vouched must sign differently");
        assert_ne!(at(S::Held), at(S::Vouched), "Held vs Vouched must sign differently");
        assert_eq!(
            [S::Unknown.payload_byte(), S::Vouched.payload_byte(), S::Held.payload_byte()],
            [0x00, 0x01, 0x02],
            "the bound byte is fixed (spec §9p), never the serde form");
        assert_eq!(S::default(), S::Unknown, "Default is fail-closed Unknown");
    }

    /// ForkSettlement §9p — a `Held` or `Unknown` status NEVER settles, and the
    /// settle rule is otherwise UNCHANGED: the same vouched record that settles
    /// at the floor under `Vouched` settles in neither the link form nor the
    /// CL5 form when it is labelled `Held` / `Unknown` (even a malformed label
    /// with the origin still present — the settle rule does not lean on the
    /// validity check). MUTATION: delete the `origin_status != Vouched`
    /// conjunct in `origin_settle_ready_at` → red at the `Held` case.
    #[test]
    fn held_or_unknown_origin_status_never_settles() {
        use crate::types::OriginVouchStatus as S;
        let (p, epoch, txid) = origin_leg(5_000);
        let vouched = origin_att(txid, &p, epoch, 1_000, 1_000 + 200, "NOT_REDEEMED");
        assert_eq!(vouched.origin_status, S::Vouched);
        assert!(origin_settled_link(&vouched, &txid, false), "control: Vouched settles at the floor, as before");
        let mut tip = bare_link();
        tip.tx_id = txid;
        tip.previous_state_id = p.consumed_state_id;
        let cheque = origin_cheque(txid, &p.receiver_wallet_id, p.amount);
        assert!(origin_settled_cl5(&vouched, &cheque, &tip, false), "control: CL5 form settles under Vouched");
        for st in [S::Held, S::Unknown] {
            let mut a = vouched.clone();
            a.origin_status = st;
            assert_eq!(origin_settle_ready_at(&a, &txid, false), None, "{st:?} has no ready time");
            assert!(!origin_settled_link(&a, &txid, false), "{st:?} never settles (link form)");
            assert!(!origin_settled_cl5(&a, &cheque, &tip, false), "{st:?} never settles (CL5 form)");
            let mut far = a.clone();
            far.nabla_tick = 1_000_000_000;
            assert!(!origin_settled_link(&far, &txid, false), "{st:?} never settles, however late");
            a.origin = None;
            a.sender_registered_at_tick = 0;
            assert!(txid_attestation_origin_consistent(&a), "{st:?} + no origin is well-formed");
            assert!(!origin_settled_link(&a, &txid, false), "{st:?} (well-formed) never settles");
        }
    }

    /// ForkSettlement §9p — THE consistency rule, every combination:
    /// `Vouched` ⇔ `origin.is_some()`. MUTATION: `txid_attestation_origin_consistent`
    /// returns `true` → red (and CL5's
    /// `cl5_refuses_an_attestation_whose_origin_status_disagrees_with_its_origin`).
    #[test]
    fn origin_status_consistency_rule() {
        use crate::types::OriginVouchStatus as S;
        let (p, epoch, txid) = origin_leg(5_000);
        let with = origin_att(txid, &p, epoch, 1_000, 1_200, "NOT_REDEEMED");
        let mut without = with.clone();
        without.origin = None;
        for (st, has, ok) in [
            (S::Vouched, true, true), (S::Vouched, false, false),
            (S::Held, false, true), (S::Held, true, false),
            (S::Unknown, false, true), (S::Unknown, true, false),
        ] {
            let mut a = if has { with.clone() } else { without.clone() };
            a.origin_status = st;
            assert_eq!(txid_attestation_origin_consistent(&a), ok, "{st:?} origin={has}");
        }
    }

    /// §1.5.1b link form — every conjunct fails closed on its own.
    #[test]
    fn origin_settled_link_floor_binding_and_fail_closed() {
        let (p, epoch, txid) = origin_leg(5_000);
        let reg = 1_000u64;
        // Real floor: 200 s. Exactly at the floor clears (inclusive edge)…
        assert!(origin_settled_link(&origin_att(txid, &p, epoch, reg, reg + 200, "NOT_REDEEMED"), &txid, false),
            "attested exactly settle-floor after registration must clear (inclusive)");
        // …one second under does NOT.
        assert!(!origin_settled_link(&origin_att(txid, &p, epoch, reg, reg + 199, "NOT_REDEEMED"), &txid, false),
            "one second under the settle floor must NOT clear");
        // Dev twin honoured: a dev-class link clears at 40 s, not before…
        assert!(origin_settled_link(&origin_att(txid, &p, epoch, reg, reg + 40, "NOT_REDEEMED"), &txid, true),
            "dev-class: the 8-tick (40 s) twin floor applies");
        assert!(!origin_settled_link(&origin_att(txid, &p, epoch, reg, reg + 39, "NOT_REDEEMED"), &txid, true),
            "dev-class: one second under the twin floor must NOT clear");
        // …and the twin does not leak to a real-class link.
        assert!(!origin_settled_link(&origin_att(txid, &p, epoch, reg, reg + 40, "NOT_REDEEMED"), &txid, false),
            "real-class: the dev twin must not apply");
        // 0 = not registered / contested ⇒ never clears, however late.
        assert!(!origin_settled_link(&origin_att(txid, &p, epoch, 0, 1_000_000, "NOT_REDEEMED"), &txid, false),
            "sender_registered_at_tick == 0 must never clear");
        // origin None ⇒ never clears.
        let mut none = origin_att(txid, &p, epoch, reg, reg + 10_000, "NOT_REDEEMED");
        none.origin = None;
        assert!(!origin_settled_link(&none, &txid, false), "origin None must never clear");
        // kind Redeem ⇒ never an origin [R11].
        let mut redeem = origin_att(txid, &p, epoch, reg, reg + 10_000, "NOT_REDEEMED");
        redeem.origin.as_mut().unwrap().kind = crate::types::LegKind::Redeem;
        assert!(!origin_settled_link(&redeem, &txid, false), "a REDEEM-kind leg must never clear");
        // A preimage that recomputes to a DIFFERENT txid ⇒ never clears.
        let (other_p, _, other_txid) = origin_leg(5_001);
        assert_ne!(other_txid, txid);
        let wrong = origin_att(txid, &other_p, epoch, reg, reg + 10_000, "NOT_REDEEMED");
        assert!(!origin_settled_link(&wrong, &txid, false),
            "a preimage recomputing to a different txid must never clear");
        // Wrong epoch ⇒ the recompute differs ⇒ never clears.
        let mut wrong_epoch = origin_att(txid, &p, epoch, reg, reg + 10_000, "NOT_REDEEMED");
        wrong_epoch.origin.as_mut().unwrap().epoch = epoch + 1;
        assert!(!origin_settled_link(&wrong_epoch, &txid, false), "wrong epoch must never clear");
        // An attestation ABOUT another txid never clears this one, even if its
        // origin recomputes to this txid (cross-splice).
        let mut about_other = origin_att(txid, &p, epoch, reg, reg + 10_000, "NOT_REDEEMED");
        about_other.txid = other_txid;
        assert!(!origin_settled_link(&about_other, &txid, false),
            "an attestation about a different txid must never clear this one");
        // Status is not an input: a settled REGISTERED origin clears under any
        // status; REDEEMED / BURNED WITHOUT a settled origin never clear.
        for st in ["REDEEMED", "BURNED"] {
            let mut bare = crate::types::NablaTxidAttestation { txid, status: st.into(), nabla_tick: reg + 10_000, ..Default::default() };
            assert!(!origin_settled_link(&bare, &txid, false), "{st} without a settled origin must never clear");
            bare.sender_registered_at_tick = reg;
            assert!(!origin_settled_link(&bare, &txid, false), "{st} with a tick but no origin must never clear");
        }
    }

    /// ForkSettlement §4 / R3 (wave 5) — the ONE ready-time definition: Some(reg + floor)
    /// on both twins, None on every conjunct that fails closed. Mutations that must
    /// turn THIS test red: drop the floor term (Some(reg)); return Some for tick 0.
    #[test]
    fn origin_settle_ready_at_is_registered_plus_floor_both_twins() {
        let (p, epoch, txid) = origin_leg(5_000);
        let reg = 1_000u64;
        let att = origin_att(txid, &p, epoch, reg, reg, "NOT_REDEEMED");
        assert_eq!(origin_settle_ready_at(&att, &txid, false), Some(reg + 200), "real floor = 40 ticks = 200 s");
        assert_eq!(origin_settle_ready_at(&att, &txid, true), Some(reg + 40), "dev twin = 8 ticks = 40 s");
        // The ready time is independent of when the node signed (nabla_tick).
        let late = origin_att(txid, &p, epoch, reg, reg + 9_999, "REDEEMED");
        assert_eq!(origin_settle_ready_at(&late, &txid, false), Some(reg + 200));
        // Fail-closed conjuncts ⇒ None.
        assert_eq!(origin_settle_ready_at(&origin_att(txid, &p, epoch, 0, 9_999, "NOT_REDEEMED"), &txid, false), None,
            "sender_registered_at_tick == 0 is NOT vouched (never Settling)");
        let mut none = att.clone();
        none.origin = None;
        assert_eq!(origin_settle_ready_at(&none, &txid, false), None, "origin None");
        let mut redeem = att.clone();
        redeem.origin.as_mut().unwrap().kind = crate::types::LegKind::Redeem;
        assert_eq!(origin_settle_ready_at(&redeem, &txid, false), None, "Redeem kind");
        let (other_p, _, other_txid) = origin_leg(5_001);
        assert_eq!(origin_settle_ready_at(&origin_att(txid, &other_p, epoch, reg, reg, "NOT_REDEEMED"), &txid, false), None,
            "preimage recomputing to another txid");
        assert_eq!(origin_settle_ready_at(&att, &other_txid, false), None, "att.txid != the asked txid");
    }

    /// `origin_settled_link` IS the ready-time comparison — on a grid of ticks around
    /// both edges it equals `ready_at.is_some_and(|r| tick >= r)`. Mutation: re-inline
    /// a private floor copy with `>` in `origin_settled_link` → red at the edge.
    #[test]
    fn origin_settled_link_is_ready_at_comparison() {
        let (p, epoch, txid) = origin_leg(5_000);
        for reg in [0u64, 1, 1_000] {
            for dev in [false, true] {
                for tick in (reg..reg + 260).chain([u64::MAX]) {
                    let att = origin_att(txid, &p, epoch, reg, tick, "NOT_REDEEMED");
                    let ready = origin_settle_ready_at(&att, &txid, dev);
                    assert_eq!(origin_settled_link(&att, &txid, dev), ready.is_some_and(|r| tick >= r),
                        "reg={reg} dev={dev} tick={tick}");
                }
            }
        }
        // The inclusive edge is reachable (not vacuous): exactly at ready_at clears.
        let at = origin_att(txid, &p, epoch, 1_000, 1_200, "NOT_REDEEMED");
        assert!(origin_settled_link(&at, &txid, false));
    }

    /// `inherited_unresolved_txids` is THE filter; `inherited_unresolved()` is its
    /// count. Mutation: ignore resolutions in `inherited_unresolved_txids` → red.
    #[test]
    fn inherited_unresolved_txids_matches_count() {
        let (p, epoch, settled_txid) = origin_leg(5_000);
        let (_, _, open_txid) = origin_leg(6_000);
        let mut link = bare_link();
        link.inherited_scar_txids = vec![settled_txid, open_txid];
        assert_eq!(link.inherited_unresolved_txids().copied().collect::<Vec<_>>(), vec![settled_txid, open_txid]);
        link.inherited_scar_resolutions = vec![origin_att(settled_txid, &p, epoch, 1_000, 1_200, "NOT_REDEEMED")];
        assert_eq!(link.inherited_unresolved_txids().copied().collect::<Vec<_>>(), vec![open_txid],
            "a settled resolution removes exactly its own txid");
        assert_eq!(link.inherited_unresolved(), link.inherited_unresolved_txids().count());
        assert_eq!(link.inherited_unresolved(), 1);
    }

    /// A minimal cheque for the CL5 form (the fields the predicate reads are
    /// `txid`, `receiver_wallet_id`, `amount`; the rest is inert here).
    fn origin_cheque(txid: [u8; 32], receiver: &str, amount: u64) -> crate::types::ValidatorCheque {
        crate::types::ValidatorCheque {
            fact_certificates: Vec::new(), recall_target_tx_id: None, txid,
            validator_id: [1; 32], validator_pk: vec![1; 32], signature: vec![0; 64],
            execution_proof: vec![], vbc_bundle: None, carrier_type: "test".into(),
            carrier_address: "v@test.com".into(), sender_wallet_id: "sender@test.com#42".into(),
            receiver_wallet_id: receiver.into(), amount, rate_bps: 10, reference: String::new(),
            epoch: 500, created_at: 0, state_hash: [0x33; 32], produced_state_id: [0x44; 32],
            sender_fact_chain: None, zkp_nonce: None, proof_type: 1,
            dmap_input_hash: [0; 32], dmap_output_hash: [0; 32], oracle_claim: None,
            nabla_hint: None, sender_wallet_pk: None,
        }
    }

    /// §1.5.1b CL5 form — the link form plus agreement with the cheque in hand
    /// and the verified sender tip [R5].
    #[test]
    fn origin_settled_cl5_binds_cheque_and_sender_tip() {
        let (p, epoch, txid) = origin_leg(5_000);
        let att = origin_att(txid, &p, epoch, 1_000, 1_200, "NOT_REDEEMED");
        let mut tip = bare_link();
        tip.tx_id = txid;
        tip.previous_state_id = p.consumed_state_id;
        let cheque = origin_cheque(txid, &p.receiver_wallet_id, p.amount);
        assert!(origin_settled_cl5(&att, &cheque, &tip, false), "all conjuncts hold ⇒ settled");

        // Receiver mismatch — the leg registered to someone else.
        assert!(!origin_settled_cl5(&att, &origin_cheque(txid, "mallory@test.com#1", p.amount), &tip, false),
            "receiver mismatch must fail");
        // Amount mismatch.
        assert!(!origin_settled_cl5(&att, &origin_cheque(txid, &p.receiver_wallet_id, p.amount + 1), &tip, false),
            "amount mismatch must fail");
        // The registered leg consumed a state that is NOT this send's parent.
        let mut other_tip = tip.clone();
        other_tip.previous_state_id = [0x32; 32];
        assert!(!origin_settled_cl5(&att, &cheque, &other_tip, false),
            "consumed_state_id != sender_tip.previous_state_id must fail");
        // The link-form conjuncts still apply (one second under the floor).
        let early = origin_att(txid, &p, epoch, 1_000, 1_199, "NOT_REDEEMED");
        assert!(!origin_settled_cl5(&early, &cheque, &tip, false), "under the floor must fail at CL5 too");
    }

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
        // L4: unresolved, and it IS the cheque being redeemed → INHERITED
        // (KI#221 / §1.5.1a — the old `tx_id != cheque.txid` exclusion was the leak).
        chain.links.push(make_test_link([4u8; 32], [3u8; 32], [4u8; 32], 5, &keys));

        let set = compute_inherited_scar_txids(&chain, &[4u8; 32], false, false);
        let expected: Vec<[u8; 32]> = vec![[1u8; 32], [4u8; 32], [0xEE; 32]]
            .into_iter().collect::<alloc::collections::BTreeSet<_>>().into_iter().collect();
        assert_eq!(set, expected, "L1 + the cheque's OWN unresolved origin + L2's transitive txid, sorted");

        // CL5 proved the cheque's origin SETTLED ⇒ only that txid drops out;
        // every other unresolved sender link is still inherited.
        let settled = compute_inherited_scar_txids(&chain, &[4u8; 32], false, true);
        assert!(!settled.contains(&[4u8; 32]), "a SETTLED cheque origin is not inherited (Q2)");
        assert!(settled.contains(&[1u8; 32]) && settled.contains(&[0xEE; 32]) && settled.len() == 2,
            "the settled skip touches the cheque's own txid ONLY");

        // Self-redeem inherits nothing.
        assert!(compute_inherited_scar_txids(&chain, &[4u8; 32], true, false).is_empty());

        // KI#59 out-of-order confirmation resolves the link's OWN transition
        // (consistent with link_is_resolved — ForkSettlement §3.1).
        let mut ooo = chain.clone();
        ooo.links[0].out_of_order_confirmation = Some(crate::types::OutOfOrderConfirmation {
            txid: [1u8; 32], new_state_id: [1u8; 32], nabla_tick: 0, nabla_node_pk: [0; 32],
            nabla_signature: vec![], nbc_issuer_pk: vec![], nbc_signature: vec![], nbc_commitment: vec![],
        });
        assert!(!compute_inherited_scar_txids(&ooo, &[4u8; 32], false, false).contains(&[1u8; 32]),
            "an out-of-order-confirmed link's own transition is resolved");

        // Transitive entry: REDEEMED / BURNED do NOT clear it; only a SETTLED
        // REGISTERED origin does.
        let (p, epoch, origin_txid) = origin_leg(5_000);
        let mut chain2 = chain.clone();
        chain2.links[1].inherited_scar_txids = vec![origin_txid];
        for st in ["REDEEMED", "BURNED"] {
            let mut c = chain2.clone();
            c.links[1].inherited_scar_resolutions = vec![
                crate::types::NablaTxidAttestation { txid: origin_txid, status: st.into(), nabla_tick: 10_000, ..Default::default() }
            ];
            assert!(compute_inherited_scar_txids(&c, &[4u8; 32], false, false).contains(&origin_txid),
                "a {st} attestation must NOT clear an inherited origin (KI#221)");
        }
        let mut unsettled = chain2.clone();
        unsettled.links[1].inherited_scar_resolutions = vec![origin_att(origin_txid, &p, epoch, 1_000, 1_199, "REDEEMED")];
        assert!(compute_inherited_scar_txids(&unsettled, &[4u8; 32], false, false).contains(&origin_txid),
            "a REGISTERED origin attested one second before settle must NOT clear");
        let mut cleared = chain2.clone();
        cleared.links[1].inherited_scar_resolutions = vec![origin_att(origin_txid, &p, epoch, 1_000, 1_200, "REDEEMED")];
        let set2 = compute_inherited_scar_txids(&cleared, &[4u8; 32], false, false);
        assert!(set2.contains(&[1u8; 32]) && !set2.contains(&origin_txid),
            "a SETTLED REGISTERED origin clears the transitive entry");
    }

    /// KI#180 (kept) — a NOT_REDEEMED attachment proves nothing: taint is not
    /// laundered one hop on.
    #[test]
    fn not_redeemed_attestation_does_not_drop_a_transitive_txid() {
        let mut l = bare_link();
        l.nabla_confirmation = Some(crate::types::NablaConfirmation::default());
        l.inherited_scar_txids = vec![[0xEE; 32]];
        l.inherited_scar_resolutions = vec![
            crate::types::NablaTxidAttestation { txid: [0xEE; 32], status: "NOT_REDEEMED".into(), ..Default::default() }
        ];
        let chain = FactChain { checkpoint: None, links: vec![l] };
        let set = compute_inherited_scar_txids(&chain, &[4u8; 32], false, false);
        assert!(set.contains(&[0xEE; 32]), "NOT_REDEEMED must keep the origin txid in the inherited set");
    }

    /// ForkSettlement Q2 — the WHOLE CL5 inherit decision (the function
    /// `execute_cl5` calls at its inherit site): a real sender chain whose tip
    /// IS the cheque's send (KI#146) plus an earlier unresolved link.
    #[test]
    fn cl5_inherits_cheque_origin_unless_settled() {
        let keys = test_keys();
        let (p, epoch, txid) = origin_leg(5_000);
        let mut chain = FactChain::new();
        // An earlier unresolved send (its register failed) — always inherited.
        chain.links.push(make_test_link([0x11; 32], [0x30; 32], p.consumed_state_id, 5, &keys));
        // The tip: THIS send, unconfirmed at witness time (every honest cheque).
        chain.links.push(make_test_link(txid, p.consumed_state_id, [0x44; 32], p.amount, &keys));
        let bundle = crate::types::ChequeBundle {
            cheques: vec![origin_cheque(txid, &p.receiver_wallet_id, p.amount)],
            fact_chain: None,
        };

        // Settled attestation ⇒ the cheque's origin is NOT inherited.
        let settled = origin_att(txid, &p, epoch, 1_000, 1_200, "NOT_REDEEMED");
        let set = cl5_inherited_scar_txids(Some(&chain), &bundle, Some(&settled), false, false).unwrap();
        assert_eq!(set, vec![[0x11; 32]], "settled ⇒ only the OTHER unresolved link is inherited");

        // Unsettled (one second under the floor) ⇒ it IS inherited.
        let early = origin_att(txid, &p, epoch, 1_000, 1_199, "NOT_REDEEMED");
        let set = cl5_inherited_scar_txids(Some(&chain), &bundle, Some(&early), false, false).unwrap();
        assert!(set.contains(&txid) && set.contains(&[0x11; 32]), "unsettled ⇒ the cheque's origin IS inherited");

        // Contested / not registered (tick 0) ⇒ inherited.
        let contested = origin_att(txid, &p, epoch, 0, 1_200, "NOT_REDEEMED");
        assert!(cl5_inherited_scar_txids(Some(&chain), &bundle, Some(&contested), false, false).unwrap().contains(&txid));

        // No attestation (k=0 offline) ⇒ never settled ⇒ inherited.
        assert!(cl5_inherited_scar_txids(Some(&chain), &bundle, None, false, false).unwrap().contains(&txid));

        // Dev twin through the CL5 path: 40 s settles a dev-class bundle, not a real one.
        let dev = origin_att(txid, &p, epoch, 1_000, 1_040, "NOT_REDEEMED");
        assert!(!cl5_inherited_scar_txids(Some(&chain), &bundle, Some(&dev), false, true).unwrap().contains(&txid));
        assert!(cl5_inherited_scar_txids(Some(&chain), &bundle, Some(&dev), false, false).unwrap().contains(&txid));

        // A settled attestation for a leg that consumed a DIFFERENT state is not
        // THIS send ⇒ inherited.
        let mut forked_p = p.clone();
        forked_p.consumed_state_id = [0x32; 32];
        let forked_txid = forked_p.txid(epoch);
        let mut forked_chain = chain.clone();
        forked_chain.links[1].tx_id = forked_txid;
        let forked_bundle = crate::types::ChequeBundle {
            cheques: vec![origin_cheque(forked_txid, &p.receiver_wallet_id, p.amount)],
            fact_chain: None,
        };
        let forked_att = origin_att(forked_txid, &forked_p, epoch, 1_000, 1_200, "NOT_REDEEMED");
        assert!(cl5_inherited_scar_txids(Some(&forked_chain), &forked_bundle, Some(&forked_att), false, false)
            .unwrap().contains(&forked_txid),
            "an origin whose consumed state is not the sender tip's parent must not settle");

        // Fail-closed arms preserved.
        assert_eq!(cl5_inherited_scar_txids(None, &bundle, Some(&settled), false, false),
            Err(ValidationError::RedeemSenderAnchorMissing));
        assert!(cl5_inherited_scar_txids(None, &bundle, Some(&settled), true, false).unwrap().is_empty());
        assert!(cl5_inherited_scar_txids(Some(&chain), &bundle, Some(&early), true, false).unwrap().is_empty());
    }

    /// ForkSettlement §9g [R52a] / spec T18 — the H-0 attack. Each leg of a
    /// parallel fork is GENUINELY confirmed by the door that saw it first; a
    /// colluding receiver splices that confirmation onto the TIP of its copy of
    /// the sender chain (the chain is outside the cheque signature, KI#146).
    /// A confirmed tip is NOT a settled origin: the cheque's origin IS still
    /// inherited unless CL5 proved it SETTLED. Driven through the WHOLE CL5
    /// decision (`cl5_inherited_scar_txids`, the function `execute_cl5` calls).
    ///
    /// MUTATION (RULE 6 3a): restore `nabla_confirmation` /
    /// `out_of_order_confirmation` as own-resolving for the tip in
    /// `compute_inherited_scar_txids` → THIS test goes red on the
    /// "confirmed tip + UNSETTLED attestation" assertions.
    #[test]
    fn cl5_confirmed_tip_origin_is_inherited_unless_settled() {
        let keys = test_keys();
        let (p, epoch, txid) = origin_leg(5_000);
        let mut chain = FactChain::new();
        // An EARLIER sender link, genuinely confirmed — a NON-tip link: its own
        // transition stays resolved (regression guard for the unchanged rule).
        let mut earlier = make_test_link([0x11; 32], [0x30; 32], p.consumed_state_id, 5, &keys);
        earlier.nabla_confirmation = Some(sign_nabla_confirmation(&[0x30; 32], &p.consumed_state_id));
        chain.links.push(earlier);
        // An earlier link resolved by a KI#59 out-of-order confirmation — also
        // a NON-tip link, also unchanged.
        let mut ooo_earlier = make_test_link([0x12; 32], [0x29; 32], [0x28; 32], 5, &keys);
        ooo_earlier.out_of_order_confirmation = Some(crate::types::OutOfOrderConfirmation {
            txid: [0x12; 32], new_state_id: [0x28; 32], nabla_tick: 0, nabla_node_pk: [0; 32],
            nabla_signature: vec![], nbc_issuer_pk: vec![], nbc_signature: vec![], nbc_commitment: vec![],
        });
        chain.links.push(ooo_earlier);
        // The TIP: THIS send, carrying the door's genuine first-seen
        // confirmation (the H-0 splice).
        let mut tip = make_test_link(txid, p.consumed_state_id, [0x44; 32], p.amount, &keys);
        tip.nabla_confirmation = Some(sign_nabla_confirmation(&p.consumed_state_id, &[0x44; 32]));
        chain.links.push(tip.clone());
        assert!(link_is_resolved(&tip),
            "fixture: the tip's confirmation is genuine-looking — the SENDER's own scar view still honours it");
        let bundle = crate::types::ChequeBundle {
            cheques: vec![origin_cheque(txid, &p.receiver_wallet_id, p.amount)],
            fact_chain: None,
        };

        // H-0: confirmed tip + UNSETTLED origin (one second under the floor)
        // ⇒ the cheque's origin IS inherited.
        let early = origin_att(txid, &p, epoch, 1_000, 1_199, "NOT_REDEEMED");
        let set = cl5_inherited_scar_txids(Some(&chain), &bundle, Some(&early), false, false).unwrap();
        assert_eq!(set, vec![txid],
            "a confirmed tip with an UNSETTLED origin must be inherited — and ONLY it (non-tip confirmed links stay resolved)");
        // Contested / absent (registered_at 0) and no attestation at all ⇒ inherited.
        let contested = origin_att(txid, &p, epoch, 0, 1_200, "NOT_REDEEMED");
        assert!(cl5_inherited_scar_txids(Some(&chain), &bundle, Some(&contested), false, false).unwrap().contains(&txid),
            "a confirmed tip with a contested origin must be inherited");
        assert!(cl5_inherited_scar_txids(Some(&chain), &bundle, None, false, false).unwrap().contains(&txid),
            "a confirmed tip with no attestation must be inherited");

        // The same splice via a KI#59 out-of-order confirmation on the tip.
        let mut ooo_chain = chain.clone();
        let t = ooo_chain.links.last_mut().unwrap();
        t.nabla_confirmation = None;
        t.out_of_order_confirmation = Some(crate::types::OutOfOrderConfirmation {
            txid, new_state_id: [0x44; 32], nabla_tick: 0, nabla_node_pk: [0; 32],
            nabla_signature: vec![], nbc_issuer_pk: vec![], nbc_signature: vec![], nbc_commitment: vec![],
        });
        assert_eq!(cl5_inherited_scar_txids(Some(&ooo_chain), &bundle, Some(&early), false, false).unwrap(), vec![txid],
            "an ooo-confirmed tip with an UNSETTLED origin must be inherited");

        // SETTLED origin ⇒ skipped (the only thing that skips it), confirmed or not.
        let settled = origin_att(txid, &p, epoch, 1_000, 1_200, "NOT_REDEEMED");
        assert!(cl5_inherited_scar_txids(Some(&chain), &bundle, Some(&settled), false, false).unwrap().is_empty(),
            "a SETTLED origin is not inherited even with a confirmed tip");
        assert!(cl5_inherited_scar_txids(Some(&ooo_chain), &bundle, Some(&settled), false, false).unwrap().is_empty());

        // Regression: a confirmed NON-tip link is still own-resolved when the
        // SAME links are judged for a different cheque (none of them is the tip
        // for cheque [0x99]) — the rule changed for the cheque's own link only.
        let other = compute_inherited_scar_txids(&chain, &[0x99; 32], false, false);
        assert!(other.is_empty(), "confirmed / ooo-confirmed non-tip links stay resolved, got {other:?}");
        // …and burn / recall on the tip are unchanged (a burned send cannot be
        // redeemed at all; not R52a's concern).
        let mut burned = chain.clone();
        burned.links.last_mut().unwrap().burn_proof = Some(crate::types::BurnProof { burn_tx_id: [0xB0; 32], validator_sigs: vec![] });
        assert!(!compute_inherited_scar_txids(&burned, &txid, false, false).contains(&txid));
    }

    #[test]
    fn inherited_set_is_commitment_bound() {
        // Same link data, different inherited sets ⇒ different commitments —
        // stripping the taint invalidates every witness Dilithium signature.
        let a = compute_fact_commitment(&[1u8;32], &[2u8;32], &[3u8;32], 9, None, false, 3, &[], None);
        let b = compute_fact_commitment(&[1u8;32], &[2u8;32], &[3u8;32], 9, None, false, 3, &[[7u8;32]], None);
        let c = compute_fact_commitment(&[1u8;32], &[2u8;32], &[3u8;32], 9, None, false, 3, &[[7u8;32],[8u8;32]], None);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    /// Fork Settlement R4 (§3.3a, 2026-09-28): `required_k` is bound into the
    /// FACT commitment. Same link data with k = 0 / 3 / 5 ⇒ three distinct
    /// commitments.
    #[test]
    fn fact_commitment_binds_required_k() {
        let c = |k: u8| compute_fact_commitment(
            &[1u8;32], &[2u8;32], &[3u8;32], 9, None, false, k, &[], None);
        let (k0, k3, k5) = (c(0), c(3), c(5));
        assert_ne!(k0, k3, "k=0 (Ark) and k=3 must sign different bytes");
        assert_ne!(k3, k5, "k=3 and k=5 must sign different bytes");
        assert_ne!(k0, k5);
    }

    /// Fork Settlement R4 — THE attack. A k=5 link signed by 5 real witnesses;
    /// the holder edits `required_k` AFTER signing:
    ///   * to 3 — the quorum downgrade (`verify_link_witness_quorum` / the tier
    ///     threshold would read the lower k);
    ///   * to 0 — the Ark launder: `compute_inherited_scar_txids` skips every
    ///     `required_k == 0` link, so a colluding receiver could set the tip to 0
    ///     and inherit NOTHING.
    /// Both edits must fail verification; the untouched link must verify.
    #[test]
    fn link_required_k_edit_invalidates_witness_sigs() {
        let keys = test_keys();
        assert_eq!(keys.len(), 5);
        let link = make_test_link_k([0x61; 32], [0x62; 32], [0x63; 32], 777, &keys, 5);
        verify_fact_link(&link, &test_certified()).expect("control: the untouched k=5 link verifies");
        assert!(verify_link_witness_quorum(&link), "control: quorum check passes");

        let mut downgraded = link.clone();
        downgraded.required_k = 3;
        assert_eq!(verify_fact_link(&downgraded, &test_certified()), Err(ValidationError::FactInvalidSignature),
            "k edited 5 → 3 after signing must invalidate the witness signatures");
        assert!(!verify_link_witness_quorum(&downgraded), "quorum hygiene must reject the downgrade too");

        let mut laundered = link.clone();
        laundered.required_k = crate::wallet_id::K_ARK;
        assert_eq!(verify_fact_link(&laundered, &test_certified()), Err(ValidationError::FactInvalidSignature),
            "k edited 5 → 0 (Ark inheritance launder) must invalidate the witness signatures");
        // The motive, stated: an unverified k=0 tip WOULD escape inheritance.
        let chain = FactChain { checkpoint: None, links: vec![laundered] };
        assert!(compute_inherited_scar_txids(&chain, &[0x61; 32], false, false).is_empty(),
            "the launder's payoff (k=0 ⇒ not inherited) — which is why the k must be signed");
    }

    /// The extracted CL5 profile (`cl5_redeem_required_k`) — the ONE derivation
    /// `execute_cl5` and Lambda's CL5 diagnostic mirror both call (RULE 1).
    /// Pins every branch: tier from the receiver id; protocol address → 3; the
    /// k=0 receiver split (charge / offline ⟠ / §12 settlement); missing id.
    #[test]
    fn cl5_redeem_required_k_matches_execute_cl5_profile() {
        let pk = [0x5Au8; 32];
        let ids = crate::wallet_id::generate_all_wallet_ids("r-k@test.com", "42", &pk).expect("ids");
        let id_k = |k: u8| ids.iter().find(|(_, kk, _, _)| *kk == k).expect("tier id").0.clone();
        let bundle = |sender: &str, receiver: &str| {
            let mut c = origin_cheque([0x77; 32], receiver, 5);
            c.sender_wallet_id = sender.into();
            crate::types::ChequeBundle { cheques: vec![c], fact_chain: None }
        };
        let (k0, k3, k5) = (id_k(0), id_k(3), id_k(5));
        assert_eq!(cl5_redeem_required_k(&bundle(&k3, &k5), false), Ok((5, false)), "receiver tier k=5");
        assert_eq!(cl5_redeem_required_k(&bundle(&k3, &k3), true), Ok((3, false)), "receiver tier k=3");
        assert_eq!(cl5_redeem_required_k(&bundle(&k5, &k0), false), Ok((5, false)), "CHARGE: sender's k");
        assert_eq!(cl5_redeem_required_k(&bundle(&k0, &k0), true), Ok((0, true)), "OFFLINE ⟠ trade");
        assert_eq!(cl5_redeem_required_k(&bundle(&k0, &k0), false), Ok((3, false)), "§12 settlement: floor 3");
        assert_eq!(cl5_redeem_required_k(&bundle(&k3, crate::types::BURN_ADDRESS), false), Ok((3, false)),
            "protocol address defaults to k=3");
        assert_eq!(cl5_redeem_required_k(&bundle(&k3, ""), false), Err(ValidationError::InvalidWalletId));
    }

    #[test]
    fn inherited_unresolved_blocks_resolution_and_compression() {
        let keys = test_keys();
        let (p, epoch, origin_txid) = origin_leg(5_000);
        let mut link = make_test_link([1u8; 32], [0u8; 32], [1u8; 32], 5, &keys);
        link.nabla_confirmation = Some(sign_nabla_confirmation(&[0u8; 32], &[1u8; 32]));
        assert!(link.is_resolved(), "own-confirmed link with no inherited taint resolves");

        link.inherited_scar_txids = vec![origin_txid];
        assert!(!link.is_resolved(),
            "unresolved inherited taint MUST keep the link scarred — the \
             compression prefix (take_while is_resolved) can never cover it");
        assert_eq!(link.inherited_unresolved(), 1);

        // NOT_REDEEMED, REDEEMED (consumed ≠ backed) and BURNED (would launder
        // downstream) never clear — KI#221, superseding KI#180's rule.
        for st in ["NOT_REDEEMED", "REDEEMED", "BURNED"] {
            link.inherited_scar_resolutions = vec![
                crate::types::NablaTxidAttestation { txid: origin_txid, status: st.into(), nabla_tick: 10_000, ..Default::default() }
            ];
            assert_eq!(link.inherited_unresolved(), 1, "{st} must not clear inherited taint");
            assert!(!link.is_resolved());
            assert!(!link_is_resolved(&link));
        }

        // A REGISTERED origin one second before settle: still scarred.
        link.inherited_scar_resolutions = vec![origin_att(origin_txid, &p, epoch, 1_000, 1_199, "REDEEMED")];
        assert_eq!(link.inherited_unresolved(), 1, "unsettled origin must not clear");
        // Settled: clears.
        link.inherited_scar_resolutions.push(origin_att(origin_txid, &p, epoch, 1_000, 1_200, "REDEEMED"));
        assert_eq!(link.inherited_unresolved(), 0);
        assert!(link.is_resolved() && link_is_resolved(&link), "a SETTLED REGISTERED origin clears the inherited scar");
        // The link's own k-signed class selects the floor: dev link clears at 40 s.
        link.inherited_scar_resolutions = vec![origin_att(origin_txid, &p, epoch, 1_000, 1_040, "NOT_REDEEMED")];
        assert_eq!(link.inherited_unresolved(), 1, "real-class link: 40 s is under the floor");
        link.is_dev_class = true;
        assert_eq!(link.inherited_unresolved(), 0, "dev-class link: the twin floor applies");
    }

    /// A Nabla writer the attestation trust anchor accepts (the KI#205 shape):
    /// fresh Ed25519 node key, NBC SPHINCS+-signed by a fresh issuer registered
    /// through `nabla_genesis::test_roots` (cfg(test) only).
    fn origin_nabla_writer() -> (ed25519_dalek::SigningKey, Vec<u8>, Vec<u8>, Vec<u8>) {
        use fips205::slh_dsa_sha2_128s;
        use fips205::traits::{KeyGen, SerDes};
        let node = ed25519_dalek::SigningKey::from_bytes(&[0x43u8; 32]);
        let node_pk = node.verifying_key().to_bytes();
        let (issuer_pk, issuer_sk) = {
            let mut rng = rand_core::OsRng;
            let (pk, sk) = slh_dsa_sha2_128s::try_keygen_with_rng(&mut rng).expect("keygen");
            (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
        };
        crate::nabla_genesis::test_roots::authorize(issuer_pk.clone().try_into().unwrap());
        let mut nbc_commitment = b"AXIOM_NBC_ORIGIN_TEST".to_vec();
        nbc_commitment.extend_from_slice(&node_pk);
        let nbc_signature = crate::crypto::sign_sphincs(
            &issuer_sk, blake3::hash(&nbc_commitment).as_bytes()).expect("sphincs sign");
        (node, issuer_pk, nbc_signature, nbc_commitment)
    }

    /// Pass-4 RULE 5 confirmation (ForkSettlement §3.2 table): a stored
    /// resolution is hard-verified BEFORE it is counted, and `origin` +
    /// `sender_registered_at_tick` are INSIDE the signed payload — so a genuine
    /// but UNSETTLED attestation cannot be re-dated or re-pointed into a
    /// settled one after the fact.
    #[test]
    fn inherited_resolution_payload_binds_origin_and_registration_tick() {
        use ed25519_dalek::Signer;
        let keys = test_keys();
        let (node, issuer_pk, nbc_signature, nbc_commitment) = origin_nabla_writer();
        let (p, epoch, origin_txid) = origin_leg(5_000);
        let inherited = alloc::vec![origin_txid];
        let commitment = compute_fact_commitment(
            &[1u8;32], &[0u8;32], &[1u8;32], 5, None, false, (keys.len() + 1) as u8, &inherited, None);
        let mut link = make_test_link([1u8; 32], [0u8; 32], [1u8; 32], 5, &keys);
        link.witnesses = keys.iter().map(|key| crate::types::FactWitness {
            validator_id: certified_id(&key.pk),
            validator_pk: key.pk.clone(),
            signature: crate::crypto::sign_dilithium(&key.sk, &commitment).unwrap(),
            vbc_hash: certified_ref(&key.pk),
        }).collect();
        link.inherited_scar_txids = inherited;

        // A GENUINE attestation, signed one second before settle (unsettled).
        let mut att = origin_att(origin_txid, &p, epoch, 1_000, 1_199, "REDEEMED");
        let sign = |a: &crate::types::NablaTxidAttestation| node.sign(&crate::crypto::txid_attest_payload(
            &a.txid, &a.status, a.nabla_tick, a.origin.as_ref(), a.sender_registered_at_tick,
            a.oods_size, a.oods_healthy, a.origin_status)).to_bytes().to_vec();
        att.nabla_node_pk = node.verifying_key().to_bytes();
        att.nbc_issuer_pk = issuer_pk;
        att.nbc_signature = nbc_signature;
        att.nbc_commitment = nbc_commitment;
        att.nabla_signature = sign(&att);
        link.inherited_scar_resolutions = vec![att.clone()];
        assert!(verify_fact_link(&link, &test_certified()).is_ok(), "a genuine resolution verifies");
        assert_eq!(link.inherited_unresolved(), 1, "…and, being unsettled, does not clear");

        // Re-date the registration so it would read as settled: REJECTED.
        let mut redated = att.clone();
        redated.sender_registered_at_tick = 999;
        assert!(origin_settled_link(&redated, &origin_txid, false), "(the tampered copy WOULD clear if counted)");
        link.inherited_scar_resolutions = vec![redated];
        assert!(verify_fact_link(&link, &test_certified()).is_err(),
            "sender_registered_at_tick is signed — re-dating must reject the chain");

        // Swap in a different origin record: REJECTED.
        let mut repointed = att.clone();
        repointed.origin.as_mut().unwrap().preimage.nonce += 1;
        link.inherited_scar_resolutions = vec![repointed];
        assert!(verify_fact_link(&link, &test_certified()).is_err(),
            "origin is signed — swapping the preimage must reject the chain");

        // Strip the origin: REJECTED (None has its own encoding).
        let mut stripped = att.clone();
        stripped.origin = None;
        link.inherited_scar_resolutions = vec![stripped];
        assert!(verify_fact_link(&link, &test_certified()).is_err(),
            "origin presence is signed — stripping it must reject the chain");

        // ForkSettlement §9p — the ORIGIN STATUS is signed. A GENUINE `Held`
        // statement (no origin, well-formed) verifies as a stored resolution…
        let mut held = att.clone();
        held.origin = None;
        held.sender_registered_at_tick = 0;
        held.origin_status = crate::types::OriginVouchStatus::Held;
        held.nabla_signature = sign(&held);
        link.inherited_scar_resolutions = vec![held.clone()];
        assert!(verify_fact_link(&link, &test_certified()).is_ok(), "a genuine Held resolution is VALID");
        assert_eq!(link.inherited_unresolved(), 1, "…and clears nothing");
        // …re-labelled `Unknown` (still well-formed) under the SAME signature: REJECTED.
        let mut relabelled = held.clone();
        relabelled.origin_status = crate::types::OriginVouchStatus::Unknown;
        assert!(txid_attestation_origin_consistent(&relabelled), "(the relabel is well-formed)");
        link.inherited_scar_resolutions = vec![relabelled];
        assert!(verify_fact_link(&link, &test_certified()).is_err(),
            "origin_status is signed — flipping Held → Unknown must reject the chain");
        // A MALFORMED statement with a GENUINE signature (Vouched, no origin): REJECTED.
        let mut malformed = held.clone();
        malformed.origin_status = crate::types::OriginVouchStatus::Vouched;
        malformed.nabla_signature = sign(&malformed);
        assert!(!txid_attestation_signature_valid(&malformed), "Vouched without an origin is invalid");
        link.inherited_scar_resolutions = vec![malformed];
        assert!(verify_fact_link(&link, &test_certified()).is_err(),
            "a genuinely signed but malformed status must reject the chain");
        // …and Held WITH the origin (genuinely signed): REJECTED.
        let mut held_with_origin = att.clone();
        held_with_origin.origin_status = crate::types::OriginVouchStatus::Held;
        held_with_origin.nabla_signature = sign(&held_with_origin);
        link.inherited_scar_resolutions = vec![held_with_origin];
        assert!(verify_fact_link(&link, &test_certified()).is_err(),
            "Held WITH an origin (genuinely signed) must reject the chain");
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
            &[1u8;32], &[0u8;32], &[1u8;32], 5, None, false, (keys.len() + 1) as u8, &inherited, None);
        let mut witnesses = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let sig = crate::crypto::sign_dilithium(&key.sk, &commitment).unwrap();
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            witnesses.push(crate::types::FactWitness {
                validator_id: certified_id(&key.pk),
                validator_pk: key.pk.clone(),
                signature: sig,
                vbc_hash: certified_ref(&key.pk),
            });
        }
        let mut link = make_test_link([1u8; 32], [0u8; 32], [1u8; 32], 5, &keys);
        link.witnesses = witnesses;
        link.inherited_scar_txids = inherited;

        // Bare link (unresolved inherited, no resolutions): verify passes —
        // taint present is a VALID state, just scarred.
        assert!(verify_fact_link(&link, &test_certified()).is_ok(),
            "commitment-bound inherited set must verify");

        // Attach a forged resolution: self-signed attestation, no NBC. Signed
        // over the ONE builder (the hand-rolled payload copy that stood here
        // was replaced 2026-09-28 — Pattern 1 / RULE 1).
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x66; 32]);
        let payload = crate::crypto::txid_attest_payload(&[9u8; 32], "REDEEMED", 7, None, 0, 0, false,
            crate::types::OriginVouchStatus::Unknown);
        link.inherited_scar_resolutions = vec![crate::types::NablaTxidAttestation {
            txid: [9u8; 32],
            status: "REDEEMED".into(),
            nabla_node_pk: sk.verifying_key().to_bytes(),
            nabla_signature: sk.sign(&payload).to_bytes().to_vec(),
            nabla_tick: 7,
            ..Default::default()
        }];
        assert!(verify_fact_link(&link, &test_certified()).is_err(),
            "self-signed resolution without NBC anchor MUST reject the chain");

        // Resolution for a txid NOT in the inherited set: reject.
        link.inherited_scar_resolutions = vec![crate::types::NablaTxidAttestation {
            txid: [0xAA; 32],
            ..Default::default()
        }];
        assert!(verify_fact_link(&link, &test_certified()).is_err(),
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

        let validators = test_validators(&keys);

        let split_at = 7 - FACT_KEEP; // 7 compressible burned links
        let result = compress_fact_chain(chain, &validators).unwrap();
        assert_eq!(result.links.len(), 10 - split_at);
        assert!(result.checkpoint.is_some());
        assert_eq!(result.checkpoint.unwrap().compressed_count, split_at as u64);
    }

    #[test]
    fn recall_proof_resolves_and_is_compressible() {
        // YPX-022 / Audit#3: a recall_proof resolves the link (the sub-quorum send
        // was reclaimed, no value moved), so it counts toward the compressible
        // resolved prefix. Before the fix compression used the recall-BLIND
        // `is_resolved`, so a recalled link never compressed and the wallet wedged
        // at FACT_HARD_CEILING.
        let mut link = bare_link();
        assert!(!link.is_resolved(), "a plain link is a scar");
        link.recall_proof = Some(crate::types::RecallAttestation {
            txid: link.tx_id,
            presend_state_hash: [0u8; 32],
            amount: link.amount,
            recall_tick: 1,
            nabla_node_pk: [0u8; 32],
            nabla_signature: Vec::new(),
            nbc_issuer_pk: Vec::new(),
            nbc_signature: Vec::new(),
            nbc_commitment: Vec::new(),
        });
        assert!(link.is_resolved(), "a recall_proof link is resolved → compressible");
        // The verified free-fn rejects this DUMMY (unsigned) proof — that is the
        // intended structural-vs-verified split. A real chain is verified upstream
        // (verify_fact_chain_inner) before any post-verify consumer sees it, so the
        // structural check here can only ever act on already-verified proofs.
        assert!(!link_is_resolved(&link),
            "verified predicate rejects an unsigned recall proof");
    }

    #[test]
    fn ooo_confirmation_resolves_structurally_verified_rejects_unsigned() {
        // KI#59: an out-of-order confirmation is a THIRD scar-resolution path.
        // Mirrors recall_proof_resolves_and_is_compressible: the structural
        // FactLink::is_resolved counts a present confirmation (post-verify form,
        // safe because verify_fact_chain_inner runs first), while the verified
        // link_is_resolved rejects an unsigned dummy.
        let mut link = bare_link();
        assert!(!link.is_resolved(), "a plain link is a scar");
        link.out_of_order_confirmation = Some(crate::types::OutOfOrderConfirmation {
            txid: link.tx_id,
            new_state_id: link.new_state_id,
            nabla_tick: 1,
            nabla_node_pk: [0u8; 32],
            nabla_signature: Vec::new(),
            nbc_issuer_pk: Vec::new(),
            nbc_signature: Vec::new(),
            nbc_commitment: Vec::new(),
        });
        assert!(link.is_resolved(), "an ooo-confirmed link is resolved structurally");
        assert!(!link_is_resolved(&link),
            "verified predicate rejects an unsigned ooo confirmation");
    }

    #[test]
    fn ooo_confirmation_wrong_txid_or_state_never_resolves() {
        // KI#59 fork-disambiguation (the load-bearing binding): the verified
        // predicate requires att.txid == link.tx_id AND att.new_state_id ==
        // link.new_state_id. A confirmation carrying a DIFFERENT state (the fork
        // sibling B→C' while this link is B→C) can never resolve THIS link — even
        // before signature verification, the ct_eq state check short-circuits to
        // false, so a wallet cannot mark both forks resolved.
        let mut link = bare_link();
        let base = crate::types::OutOfOrderConfirmation {
            txid: link.tx_id,
            new_state_id: link.new_state_id,
            nabla_tick: 1,
            nabla_node_pk: [0u8; 32],
            nabla_signature: Vec::new(),
            nbc_issuer_pk: Vec::new(),
            nbc_signature: Vec::new(),
            nbc_commitment: Vec::new(),
        };
        // Wrong state (fork sibling): fails the state binding before verify.
        let mut wrong_state = base.clone();
        wrong_state.new_state_id = [0xAB; 32];
        assert_ne!(wrong_state.new_state_id, link.new_state_id);
        link.out_of_order_confirmation = Some(wrong_state);
        assert!(!link_is_resolved(&link), "wrong new_state must NOT resolve this link");
        // Wrong txid: fails the txid binding.
        let mut wrong_txid = base;
        wrong_txid.txid = [0xCD; 32];
        link.out_of_order_confirmation = Some(wrong_txid);
        assert!(!link_is_resolved(&link), "wrong txid must NOT resolve this link");
    }

    #[test]
    fn verify_ooo_confirmation_rejects_bad_sig_and_missing_nbc() {
        // KI#59: verify_ooo_confirmation is the reject path (mirror of
        // verify_recall_attestation). A garbage Nabla sig → OooConfirmationInvalid;
        // an empty NBC anchor → OooConfirmationInvalid.
        let att = crate::types::OutOfOrderConfirmation {
            txid: [7u8; 32],
            new_state_id: [8u8; 32],
            nabla_tick: 1,
            nabla_node_pk: [0u8; 32],
            nabla_signature: vec![0u8; 64], // not a valid Ed25519 sig over the payload
            nbc_issuer_pk: Vec::new(),
            nbc_signature: Vec::new(),
            nbc_commitment: Vec::new(),
        };
        assert!(matches!(
            crate::validation::verify_ooo_confirmation(&att),
            Err(crate::types::ValidationError::OooConfirmationInvalid)
        ), "a bad Nabla signature must reject");
    }

    #[test]
    fn verify_link_witness_quorum_accepts_valid_rejects_tampered_and_underwitnessed() {
        // KI#59 — the self-contained k-witness quorum Nabla checks before signing
        // an out-of-order confirmation (griefing hygiene).
        let keys = test_keys();
        assert!(keys.len() >= MIN_FACT_WITNESSES, "fixture needs >= floor-3 keys");
        let link = make_test_link([1u8; 32], [0u8; 32], [1u8; 32], 100, &keys);
        assert!(verify_link_witness_quorum(&link), "a k-witnessed link passes");

        // Under-witnessed (< floor 3) → refused ("UNDERWITNESSED").
        let mut few = link.clone();
        few.witnesses.truncate(MIN_FACT_WITNESSES - 1);
        assert!(!verify_link_witness_quorum(&few), "< 3 witnesses fails");

        // Tampered state: the witnesses signed the ORIGINAL commitment, so swapping
        // new_state_id makes every Dilithium sig fail — a griefer cannot get Nabla to
        // attest a (txid, state) the k validators never signed.
        let mut tampered = link;
        tampered.new_state_id = [0xEE; 32];
        assert!(!verify_link_witness_quorum(&tampered), "tampered new_state fails the sig check");
    }

    #[test]
    fn is_resolved_matches_link_is_resolved() {
        // Drift-guard (cited by the fact.rs + types.rs comments): the structural
        // `FactLink::is_resolved` and the verified `link_is_resolved` encode ONE rule
        // and must agree on every path that does not hinge on recall-signature
        // verification — burn, plain scar, and (upstream-verified) nabla/inherited.
        let keys = test_keys();
        let plain = make_test_link([1u8; 32], [0u8; 32], [1u8; 32], 100, &keys); // scar
        let burned = make_burned_link([2u8; 32], [1u8; 32], [2u8; 32], 100, &keys);
        for l in [&plain, &burned] {
            assert_eq!(l.is_resolved(), link_is_resolved(l),
                "is_resolved and link_is_resolved must agree on non-recall links");
        }
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

        let validators = test_validators(&keys);

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
        let link1 = make_burned_link([1u8; 32], [0u8; 32], [2u8; 32], 1000, &keys); // self-burn, resolved
        let link2 = make_test_link([3u8; 32], [2u8; 32], [4u8; 32], 500, &keys); // scarred

        let chain = FactChain { checkpoint: None, links: vec![link1, link2] };
        let result = verify_fact_chain(&chain, &test_trust());
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
    fn burn_proof_copied_from_another_link_rejected() {
        // THE COPY FORGE (2026-07-17). `BurnProof.validator_sigs` is only a
        // clone of the burn link's own witnesses and binds nothing about the
        // target. Attacker genuinely burns a 1-atom scar, then copies that same
        // BurnProof onto a 1000-atom scar. Before the burn-target binding this
        // passed verify_fact_chain and made the 1000-atom link is_resolved().
        let keys = test_keys();

        // Scar A: valuable (1000). Scar B: cheap (1), genuinely burned.
        let scar_a = make_test_link([0xA1; 32], [0x00; 32], [0xA2; 32], 1000, &keys);
        let scar_b = make_test_link([0xB1; 32], [0xA2; 32], [0xB2; 32], 1, &keys);
        // Genuine burn TX destroying scar B for its exact amount (1).
        let burn = make_burn_link([0xCC; 32], [0xB2; 32], [0xC2; 32], 1, scar_b.tx_id, &keys);

        let genuine_proof = crate::types::BurnProof {
            burn_tx_id: burn.tx_id,
            validator_sigs: burn.witnesses.clone(),
        };

        let mut scar_b = scar_b;
        scar_b.burn_proof = Some(genuine_proof.clone()); // legitimate
        let mut scar_a = scar_a;
        scar_a.burn_proof = Some(genuine_proof); // ATTACK: same proof on the 1000 scar

        let chain = FactChain { checkpoint: None, links: vec![scar_a, scar_b, burn] };
        let verdict = verify_fact_chain(&chain, &test_trust());

        // The named burn link's witnessed target is scar B, not scar A, and its
        // amount (1) != scar A's (1000) — either mismatch rejects the chain.
        // The money-safety boundary is verify_fact_chain: a chain carrying the
        // copied proof is REJECTED, so it is never accepted, stored, or
        // compressed. (is_resolved() is a per-link predicate with no chain
        // context, so it alone cannot catch a cross-link copy — which is
        // exactly why the chain-scoped check exists and is always run first.)
        assert!(
            matches!(verdict, Err(ValidationError::BurnTargetMismatch)
                            | Err(ValidationError::BurnAmountMismatch)),
            "copied burn proof must be rejected, got {:?}", verdict,
        );
    }

    #[test]
    fn burning_one_scar_does_not_lift_the_others() {
        // Answer to "multiple scars in a chain — burn one, do all lift?": NO.
        // Resolution is per-link (burn_proof is a per-link field bound to that
        // link's exact tx_id + amount). Each scar needs its own matched burn.
        let keys = test_keys();

        // Three independent classic scars, chained.
        let scar_a = make_test_link([0xA1; 32], [0x00; 32], [0xA2; 32], 100, &keys);
        let scar_b = make_test_link([0xB1; 32], [0xA2; 32], [0xB2; 32], 50, &keys);
        let scar_c = make_test_link([0xC1; 32], [0xB2; 32], [0xC2; 32], 25, &keys);
        // Genuinely burn ONLY scar_b (matched target + amount 50).
        let burn = make_burn_link([0xDD; 32], [0xC2; 32], [0xD2; 32], 50, scar_b.tx_id, &keys);
        let mut scar_b = scar_b;
        scar_b.burn_proof = Some(crate::types::BurnProof {
            burn_tx_id: burn.tx_id,
            validator_sigs: burn.witnesses.clone(),
        });

        // Only scar_b is resolved; A and C remain scars.
        assert!(!scar_a.is_resolved(), "scar A must stay scarred");
        assert!(scar_b.is_resolved(), "scar B was burned → resolved");
        assert!(!scar_c.is_resolved(), "scar C must stay scarred");

        let chain = FactChain {
            checkpoint: None,
            links: alloc::vec![scar_a, scar_b, scar_c, burn],
        };
        // 4 links: A scar, B resolved, C scar, burn-TX pending → 3 scars remain.
        let scars = verify_fact_chain(&chain, &test_trust()).expect("chain must verify");
        assert_eq!(scars, 3, "burning B lifts only B; A, C, and the pending burn TX remain");
        assert!(!chain.links[0].is_resolved()); // A
        assert!(chain.links[1].is_resolved());  // B (burned)
        assert!(!chain.links[2].is_resolved()); // C
    }

    #[test]
    fn burn_clears_inherited_taint_but_confirmation_alone_does_not() {
        // §1.5.1a + §1.5.4: a receiver holds tainted money — a Nabla-CONFIRMED
        // redeem link that inherited an unresolved origin txid. Confirmation
        // alone must NOT resolve it (consent/own-confirmation is not cleansing).
        // Burning it (destroying the value) MUST resolve it — the holder's
        // escape hatch when the origin never resolves.
        let keys = test_keys();

        // Confirmed-but-tainted link (the victim's redeem). The inherited set is
        // bound into the commitment, so sign WITH it (mutating after signing
        // would invalidate the witness sigs).
        let inherited = alloc::vec![[0x9E; 32]]; // origin txid, unresolved
        let commitment = compute_fact_commitment(
            &[0xD1; 32], &[0x00; 32], &[0xD2; 32], 100, None, false, (keys.len() + 1) as u8, &inherited, None);
        let mut witnesses = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let sig = crate::crypto::sign_dilithium(&key.sk, &commitment).unwrap();
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            witnesses.push(FactWitness {
                validator_id: certified_id(&key.pk), validator_pk: key.pk.clone(), signature: sig,
                vbc_hash: certified_ref(&key.pk),
            });
        }
        let mut tainted = make_test_link([0xD1; 32], [0x00; 32], [0xD2; 32], 100, &keys);
        tainted.witnesses = witnesses;
        tainted.inherited_scar_txids = inherited;
        tainted.nabla_confirmation = Some(sign_nabla_confirmation(&[0x00; 32], &[0xD2; 32]));

        assert!(!tainted.is_resolved(),
            "confirmed-but-inherited-tainted link must stay scarred");
        assert_eq!(tainted.inherited_unresolved(), 1);

        // Burn it: a genuine burn TX destroying its exact amount.
        let burn = make_burn_link([0xCC; 32], [0xD2; 32], [0xC2; 32], 100, tainted.tx_id, &keys);
        tainted.burn_proof = Some(crate::types::BurnProof {
            burn_tx_id: burn.tx_id,
            validator_sigs: burn.witnesses.clone(),
        });

        // Now resolved — the tainted value is destroyed, nothing left to launder.
        assert!(tainted.is_resolved(), "a burned link is resolved despite inherited taint");

        // And the whole chain verifies (burn binding satisfied): the tainted
        // link no longer counts as a scar; only the pending burn TX does.
        let chain = FactChain { checkpoint: None, links: vec![tainted, burn] };
        let scars = verify_fact_chain(&chain, &test_trust()).expect("burn of a tainted link must verify");
        assert_eq!(scars, 1, "tainted link resolved by burn; burn TX pending confirmation");
        assert!(chain.links[0].is_resolved());
    }

    #[test]
    fn burn_proof_genuine_two_link_pair_accepted() {
        // The honest counterpart: a real burn of a real scar resolves it.
        let keys = test_keys();
        let scar = make_test_link([0xA1; 32], [0x00; 32], [0xA2; 32], 500, &keys);
        let burn = make_burn_link([0xCC; 32], [0xA2; 32], [0xC2; 32], 500, scar.tx_id, &keys);
        let mut scar = scar;
        scar.burn_proof = Some(crate::types::BurnProof {
            burn_tx_id: burn.tx_id,
            validator_sigs: burn.witnesses.clone(),
        });
        let chain = FactChain { checkpoint: None, links: vec![scar, burn] };
        let scars = verify_fact_chain(&chain, &test_trust()).expect("genuine burn pair must verify");
        // The target scar is resolved; the burn TX link is itself a normal send
        // that is pending Nabla confirmation, so it counts as 1 pending scar
        // until confirmed — exactly the production lifecycle.
        assert_eq!(scars, 1, "target resolved; burn TX link pending confirmation");
        assert!(chain.links[0].is_resolved(), "the burned target must read resolved");
        assert!(!chain.links[1].is_resolved(), "the burn TX link is pending until confirmed");
    }

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
        let err = verify_fact_chain(&chain, &test_trust()).unwrap_err();
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
        let err = verify_fact_chain(&chain, &test_trust()).unwrap_err();
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
        let err = verify_fact_chain(&chain, &test_trust()).unwrap_err();
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
        assert!(verify_fact_chain(&chain, &test_trust()).is_ok(),
            "depth-9 chain verifies under the travel model");

        // The legacy immediate-compress wrappers were deleted 2026-08-18 — depth
        // is bounded by FACT_HARD_CEILING (protocol) + the operator's
        // max_fact_links, and compression is exclusively the SEC-07 checkpoint
        // (propose -> co-sign -> finalize). Nothing else gates depth.
        assert_eq!(verify_fact_chain(&chain, &test_trust()).unwrap(), 0,
            "all links resolved — zero scars");
    }

    // ── Adversarial FACT chain compression tests ─────────────────

    /// Helper: build validator tuples from test keys for compress_fact_chain.
    fn make_validators(keys: &[DilithiumTestKey]) -> Vec<([u8; 32], &[u8], &[u8], [u8; 32])> {
        test_validators(keys)
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
        let verify_scar_count = verify_fact_chain(&compressed, &test_trust()).unwrap();
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
        assert!(verify_fact_chain(&compressed, &test_trust()).is_ok());

        // Tamper with checkpoint's final_state_id
        compressed.checkpoint.as_mut().unwrap().final_state_id = [0xFFu8; 32];

        // Two possible failure modes:
        // 1. Checkpoint signature verification fails (commitment changed)
        // 2. Chain continuity fails (first link's previous_state_id != tampered final_state_id)
        // Either way, verify must reject.
        let result = verify_fact_chain(&compressed, &test_trust());
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

        let scar_count = verify_fact_chain(&chain, &test_trust()).unwrap();
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

        let result = verify_fact_chain(&chain, &test_trust());
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
        let scar_count = verify_fact_chain(&result, &test_trust()).unwrap();
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
        assert!(verify_fact_chain(&compressed, &test_trust()).is_ok());

        // Forge the root_hash
        let original_root = compressed.checkpoint.as_ref().unwrap().root_hash;
        compressed.checkpoint.as_mut().unwrap().root_hash = [0xDEu8; 32];
        assert_ne!(compressed.checkpoint.as_ref().unwrap().root_hash, original_root);

        // Verification must fail: the Dilithium signatures were computed over a
        // commitment that includes the original root_hash, so forging it breaks
        // the signature check.
        let result = verify_fact_chain(&compressed, &test_trust());
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
        assert!(verify_fact_chain(&compressed, &test_trust()).is_ok());

        let original = compressed.checkpoint.as_ref().unwrap().total_amount;
        compressed.checkpoint.as_mut().unwrap().total_amount = original.wrapping_add(1_000_000);

        let result = verify_fact_chain(&compressed, &test_trust());
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
        (certified_id(&keys[i].pk), keys[i].pk.as_slice(), keys[i].sk.as_slice())
    }
    fn validator4(keys: &[DilithiumTestKey], i: usize) -> ([u8; 32], &[u8], &[u8], [u8; 32]) {
        (certified_id(&keys[i].pk), keys[i].pk.as_slice(), keys[i].sk.as_slice(), certified_ref(&keys[i].pk))
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
        advance_fact_checkpoint(&mut chain, vid, pk, sk, certified_ref(pk), false).unwrap();
        assert!(chain.checkpoint.is_none(), "unhealthy view must not PROPOSE");
        assert_eq!(chain.links.len(), 10, "no links may be touched");

        // Same chain, healthy view → proposes normally (control).
        advance_fact_checkpoint(&mut chain, vid, pk, sk, certified_ref(pk), true).unwrap();
        assert!(chain.checkpoint.is_some(), "healthy view proposes");

        // A provisional proposal must also not advance under an unhealthy view.
        let (vid2, pk2, sk2) = validator_i(&keys, 1);
        let sigs_before = chain.checkpoint.as_ref().unwrap().validator_sigs.len();
        advance_fact_checkpoint(&mut chain, vid2, pk2, sk2, certified_ref(pk2), false).unwrap();
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
        advance_fact_checkpoint(&mut chain, vid, pk, sk, certified_ref(pk), true).unwrap();

        let cp = chain.checkpoint.as_ref().expect("proposal created");
        assert!(cp.pending_links > 0, "provisional: links retained");
        assert_eq!(cp.validator_sigs.len(), 1, "proposer signs once");
        // covered links still physically present (10 links, none deleted yet)
        assert_eq!(chain.links.len(), 10);
        // and the chain still verifies (through the real links, no k=5 gate yet)
        assert!(verify_fact_chain(&chain, &test_trust()).is_ok(), "provisional chain must verify");
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
            advance_fact_checkpoint(&mut chain, vid, pk, sk, certified_ref(pk), true).unwrap();
            let cp = chain.checkpoint.as_ref().unwrap();
            assert_eq!(cp.validator_sigs.len(), i + 1);
            assert!(cp.pending_links > 0, "still provisional below threshold");
            assert_eq!(chain.links.len(), 10, "no links deleted below threshold");
            assert!(verify_fact_chain(&chain, &test_trust()).is_ok());
        }
        // threshold-th distinct validator → finalize.
        let (vid, pk, sk) = validator_i(&keys, CHECKPOINT_SIG_THRESHOLD - 1);
        advance_fact_checkpoint(&mut chain, vid, pk, sk, certified_ref(pk), true).unwrap();
        let cp = chain.checkpoint.as_ref().unwrap();
        assert_eq!(cp.validator_sigs.len(), CHECKPOINT_SIG_THRESHOLD);
        assert_eq!(cp.pending_links, 0, "finalized: links deleted");
        assert_eq!(chain.links.len(), FACT_KEEP, "kept FACT_KEEP tail, dropped covered");
        assert!(verify_fact_chain(&chain, &test_trust()).is_ok(), "finalized threshold-sig checkpoint verifies");
    }

    #[test]
    fn test_sec07_advance_dedup_same_validator() {
        // The same validator advancing twice must NOT add a second signature.
        let keys = test_keys();
        let mut chain = make_chain(&keys, &vec![true; 10]);
        let (vid, pk, sk) = validator_i(&keys, 0);
        advance_fact_checkpoint(&mut chain, vid, pk, sk, certified_ref(pk), true).unwrap();
        advance_fact_checkpoint(&mut chain, vid, pk, sk, certified_ref(pk), true).unwrap();
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
        let validators: Vec<([u8;32],&[u8],&[u8],[u8;32])> = (0..under).map(|i| validator4(&keys, i)).collect();
        let compressed = compress_fact_chain(chain, &validators).unwrap();
        assert_eq!(compressed.checkpoint.as_ref().unwrap().pending_links, 0);
        assert_eq!(compressed.checkpoint.as_ref().unwrap().validator_sigs.len(), under);
        assert!(matches!(verify_fact_chain(&compressed, &test_trust()),
            Err(ValidationError::FactInsufficientWitnesses)),
            "finalized checkpoint below CHECKPOINT_SIG_THRESHOLD sigs must be rejected");
    }

    #[test]
    fn test_sec07_finalized_5_sigs_accepted() {
        // Finalized with 5 distinct sigs verifies.
        let keys = test_keys();
        let chain = make_chain(&keys, &vec![true; 10]);
        let validators: Vec<([u8;32],&[u8],&[u8],[u8;32])> = (0..5).map(|i| validator4(&keys, i)).collect();
        let compressed = compress_fact_chain(chain, &validators).unwrap();
        assert_eq!(compressed.checkpoint.as_ref().unwrap().validator_sigs.len(), 5);
        assert!(verify_fact_chain(&compressed, &test_trust()).is_ok());
    }

    #[test]
    fn test_sec07_finalized_duplicate_validator_rejected() {
        // 5 valid sigs that share a validator_id → forgeable by one validator.
        let keys = test_keys();
        let chain = make_chain(&keys, &vec![true; 10]);
        let validators: Vec<([u8;32],&[u8],&[u8],[u8;32])> = (0..5).map(|i| validator4(&keys, i)).collect();
        let mut compressed = compress_fact_chain(chain, &validators).unwrap();
        let sig0 = compressed.checkpoint.as_ref().unwrap().validator_sigs[0].clone();
        compressed.checkpoint.as_mut().unwrap().validator_sigs = vec![sig0.clone(); 5];
        assert!(matches!(verify_fact_chain(&compressed, &test_trust()),
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
        advance_fact_checkpoint(&mut chain, vid, pk, sk, certified_ref(pk), true).unwrap();
        assert!(verify_fact_chain(&chain, &test_trust()).is_ok());
        // Tamper: claim the checkpoint covers a different number of leading links.
        let real = chain.checkpoint.as_ref().unwrap().pending_links;
        chain.checkpoint.as_mut().unwrap().pending_links = real + 1;
        assert!(verify_fact_chain(&chain, &test_trust()).is_err(),
            "mismatched pending_links vs root_hash must be rejected");
    }

    #[test]
    fn test_sec07_provisional_verifies_with_few_sigs() {
        // Explicitly: a provisional checkpoint with only 2 sigs still verifies,
        // because the covered links are present and self-verify. No deadlock.
        let keys = test_keys();
        let mut chain = make_chain(&keys, &vec![true; 10]);
        advance_fact_checkpoint(&mut chain, validator_i(&keys,0).0, validator_i(&keys,0).1, validator_i(&keys,0).2, certified_ref(validator_i(&keys,0).1), true).unwrap();
        advance_fact_checkpoint(&mut chain, validator_i(&keys,1).0, validator_i(&keys,1).1, validator_i(&keys,1).2, certified_ref(validator_i(&keys,1).1), true).unwrap();
        let cp = chain.checkpoint.as_ref().unwrap();
        assert_eq!(cp.validator_sigs.len(), 2);
        assert!(cp.pending_links > 0);
        assert!(verify_fact_chain(&chain, &test_trust()).is_ok(),
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
        let validators: Vec<([u8;32],&[u8],&[u8],[u8;32])> = (0..5).map(|i| validator4(&keys, i)).collect();
        let compressed = compress_fact_chain(chain, &validators).unwrap();
        let real = compute_checkpoint_commitment(compressed.checkpoint.as_ref().unwrap());
        assert_eq!(stub_commitment, real,
            "advance's signed commitment must equal compress_fact_chain's checkpoint");
    }

    fn redeem_stub_cheque(sender_fact_chain: Option<FactChain>) -> crate::types::ValidatorCheque {
        redeem_stub_cheque_for([0u8; 32], [0u8; 32], sender_fact_chain)
    }

    /// A stub cheque for the send `txid` that produced `produced_state_id`.
    fn redeem_stub_cheque_for(txid: [u8; 32], produced_state_id: [u8; 32], sender_fact_chain: Option<FactChain>) -> crate::types::ValidatorCheque {
        crate::types::ValidatorCheque {
            fact_certificates: alloc::vec::Vec::new(),
            recall_target_tx_id: None,
            txid,
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
            produced_state_id,
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

    /// KI#146 — the chooser keeps the CL5 priority (bundle copy, then each
    /// cheque's chain, then the Lambda fallback) but only among chains whose
    /// TIP is this send: tx_id == cheque.txid and new_state_id == produced.
    #[test]
    fn redeem_fact_chain_ref_follows_core_cl5_priority_among_this_sends_chains() {
        let keys = test_keys();
        let send_tx = [9u8; 32];
        let produced = [0xEEu8; 32];
        // the finalizer's chain: the send link appended
        let this_send = FactChain {
            checkpoint: None,
            links: vec![make_test_link(send_tx, [0u8; 32], produced, 1, &keys)],
        };
        // a second copy of it, distinguishable by amount, for the priority checks
        let this_send_alt = FactChain {
            checkpoint: None,
            links: vec![make_test_link(send_tx, [0u8; 32], produced, 2, &keys)],
        };
        // the PRE-send chain a non-final witness attaches: tip is another tx
        let pre_send = FactChain {
            checkpoint: None,
            links: vec![make_test_link([8u8; 32], [0u8; 32], [0xDDu8; 32], 1, &keys)],
        };

        // tier 1: the bundle copy wins when it is this send's
        let bundle = ChequeBundle {
            cheques: vec![redeem_stub_cheque_for(send_tx, produced, Some(this_send.clone()))],
            fact_chain: Some(this_send_alt.clone()),
        };
        assert_eq!(redeem_fact_chain_ref(&bundle, &None).unwrap().links[0].amount, 2);

        // tier 2: a bundle copy that is NOT this send's (the pre-send chain the
        // receiver copied off the first cheque) is skipped; the finalizer's
        // cheque chain is taken even when it is not the first cheque
        let bundle = ChequeBundle {
            cheques: vec![
                redeem_stub_cheque_for(send_tx, produced, Some(pre_send.clone())),
                redeem_stub_cheque_for(send_tx, produced, Some(this_send.clone())),
            ],
            fact_chain: Some(pre_send.clone()),
        };
        assert_eq!(redeem_fact_chain_ref(&bundle, &None).unwrap().links[0].amount, 1);
        assert_eq!(redeem_fact_sender_anchor(&bundle, &None), Some(produced));

        // tier 3: the Lambda fallback is taken only when it is this send's
        let bundle = ChequeBundle {
            cheques: vec![redeem_stub_cheque_for(send_tx, produced, Some(pre_send.clone()))],
            fact_chain: None,
        };
        assert_eq!(redeem_fact_chain_ref(&bundle, &Some(this_send_alt.clone())).unwrap().links[0].amount, 2);
        assert!(redeem_fact_chain_ref(&bundle, &Some(pre_send.clone())).is_none(),
            "no presented chain is this send's — nothing is chosen (CL5 refuses)");

        // a chain of ANOTHER wallet that verifies on its own is not this send's
        let stranger = FactChain {
            checkpoint: None,
            links: vec![make_test_link([7u8; 32], [0x10u8; 32], [0x11u8; 32], 5, &keys)],
        };
        let bundle = ChequeBundle {
            cheques: vec![redeem_stub_cheque_for(send_tx, produced, Some(stranger.clone()))],
            fact_chain: Some(stranger),
        };
        assert!(redeem_fact_chain_ref(&bundle, &None).is_none());
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

        verify_fact_link(&chain_decoded.links[0], &test_certified())
            .expect("decoded link must still verify");
    }

    // P3.2 (YPX-010 §11): a k=0 Ark ⟠-trade link verifies via the RECEIVER's own
    // Ed25519 wallet key — no validators — and rejects a missing/forged/padded witness.
    #[test]
    fn k0_ark_link_verified_by_receiver_witness_only() {
        use ed25519_dalek::{Signer, SigningKey};
        use crate::types::{FactLink, ReceiverWitness};

        let tx_id = [0x11u8; 32];
        let prev = [0x22u8; 32];
        let new = [0x33u8; 32];
        let amount = 5_000u64;

        // The receiver's wallet key signs the SAME commitment k=3 witnesses would sign.
        let recv_sk = SigningKey::from_bytes(&[0x5Au8; 32]);
        let recv_pk = recv_sk.verifying_key().to_bytes();
        let commitment = compute_fact_commitment(
            &tx_id, &prev, &new, amount, None, false, crate::wallet_id::K_ARK, &[], None);
        let sig = recv_sk.sign(&commitment).to_bytes();

        let base = || FactLink {
            tx_id, previous_state_id: prev, new_state_id: new, amount,
            required_k: crate::wallet_id::K_ARK, // k=0 = Ark
            tick: 0,
            witnesses: alloc::vec::Vec::new(), // NO validators on a k=0 link
            nabla_confirmation: None, burn_proof: None,
            burn_target_tx_id: None, sender_anchor: None, is_dev_class: false,
            recall_proof: None,
            out_of_order_confirmation: None,
            inherited_scar_txids: alloc::vec::Vec::new(),
            inherited_scar_resolutions: alloc::vec::Vec::new(),
            receiver_witness: Some(ReceiverWitness { receiver_pk: recv_pk, signature: sig }),
        };

        // (1) Valid receiver-witness → accepted with ZERO validators.
        verify_fact_link(&base(), &test_certified()).expect("k=0 link with a valid receiver witness must verify");

        // (2) Missing receiver_witness → rejected.
        let mut no_rw = base();
        no_rw.receiver_witness = None;
        assert_eq!(verify_fact_link(&no_rw, &test_certified()), Err(ValidationError::ArkReceiverWitnessMissing));

        // (3) Tampered signature → rejected as INVALID (not missing).
        let mut bad_sig = base();
        if let Some(rw) = bad_sig.receiver_witness.as_mut() { rw.signature[0] ^= 0xFF; }
        assert_eq!(verify_fact_link(&bad_sig, &test_certified()), Err(ValidationError::ArkReceiverWitnessInvalid));

        // (4) S1 (§11): a k=0 link carrying a NablaConfirmation is malformed → rejected.
        let mut with_conf = base();
        with_conf.nabla_confirmation = Some(crate::types::NablaConfirmation {
            nabla_node_id: [0xBBu8; 32], nabla_signature: alloc::vec![0u8; 64],
            root_hash: [0xCCu8; 32], synced_to_tick: 1, ..Default::default()
        });
        assert_eq!(verify_fact_link(&with_conf, &test_certified()), Err(ValidationError::ArkK0NablaConfirmationForbidden));

        // (5) A wrong key (not the signer) → invalid.
        let mut wrong_pk = base();
        let other = SigningKey::from_bytes(&[0x99u8; 32]).verifying_key().to_bytes();
        if let Some(rw) = wrong_pk.receiver_witness.as_mut() { rw.receiver_pk = other; }
        assert_eq!(verify_fact_link(&wrong_pk, &test_certified()), Err(ValidationError::ArkReceiverWitnessInvalid));
    }

    /// §12.2 SETTLED k=0 links (P3.8 fix, reviewed and approved 2026-07-19): a k=0
    /// link with NON-EMPTY witnesses takes the settled shape — the Dilithium
    /// quorum (full k≥3 floor) is the proof, the receiver-witness is verified
    /// only WHEN CARRIED, and S1's confirmation ban does not apply (§12.2 —
    /// settlement's whole point is the confirmation). Pre-fix,
    /// `verify_k0_ark_receiver_witness` ran unconditionally and every
    /// post-settlement wallet's chain rejected on its next tx (ark_soak5).
    #[test]
    fn k0_settled_link_verifies_via_dilithium_quorum() {
        use ed25519_dalek::{Signer, SigningKey};
        let keys = test_keys();
        let mut link = make_test_link_k(
            [0x71u8; 32], [0x22u8; 32], [0x33u8; 32], 5_000, &keys[..3], crate::wallet_id::K_ARK);

        // (1) Settled shape: Dilithium ×3, NO receiver_witness (Lambda's
        // rebuilt settlement link doesn't carry one) → verifies.
        link.receiver_witness = None;
        verify_fact_link(&link, &test_certified()).expect("settled k=0 link must verify via the Dilithium quorum");

        // (2) The receiver-witness is verified WHEN carried: a valid one
        // passes, a tampered one rejects INVALID.
        let recv_sk = SigningKey::from_bytes(&[0x5Au8; 32]);
        let commitment = compute_fact_commitment(
            &link.tx_id, &link.previous_state_id, &link.new_state_id, link.amount,
            None, false, link.required_k, &[], None,
        );
        let rw = crate::types::ReceiverWitness {
            receiver_pk: recv_sk.verifying_key().to_bytes(),
            signature: recv_sk.sign(&commitment).to_bytes(),
        };
        let mut with_rw = link.clone();
        with_rw.receiver_witness = Some(rw.clone());
        verify_fact_link(&with_rw, &test_certified()).expect("settled k=0 link with a valid carried RW must verify");
        let mut bad_rw = link.clone();
        let mut tampered = rw;
        tampered.signature[0] ^= 0xFF;
        bad_rw.receiver_witness = Some(tampered);
        assert_eq!(verify_fact_link(&bad_rw, &test_certified()), Err(ValidationError::ArkReceiverWitnessInvalid),
            "a carried-but-forged RW must reject");

        // (3) Settled links keep the FULL k≥3 Dilithium floor — 2 witnesses
        // is not a settled link, and without an RW it isn't offline either.
        let mut short = make_test_link_k(
            [0x72u8; 32], [0x22u8; 32], [0x33u8; 32], 5_000, &keys[..2], crate::wallet_id::K_ARK);
        short.receiver_witness = None;
        assert_eq!(verify_fact_link(&short, &test_certified()), Err(ValidationError::FactInsufficientWitnesses));

        // (4) S1's ban is scoped to the OFFLINE shape: a settled link carrying
        // a (here structurally bogus) confirmation must NOT reject with the
        // S1 code — it proceeds to the confirmation's own verification.
        let mut with_conf = link.clone();
        with_conf.nabla_confirmation = Some(crate::types::NablaConfirmation {
            nabla_node_id: [0xBBu8; 32], nabla_signature: alloc::vec![0u8; 64],
            root_hash: [0xCCu8; 32], synced_to_tick: 1, ..Default::default()
        });
        assert_ne!(verify_fact_link(&with_conf, &test_certified()), Err(ValidationError::ArkK0NablaConfirmationForbidden),
            "S1 must not fire on a SETTLED link — the conf is judged on its own signature");
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
            h.update(b"AXIOM_FACT_CONFIRM");
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
        assert_eq!(link_after.required_k, link.required_k, "required_k mutated");

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
        verify_fact_link(link_after, &test_certified()).expect(
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
            h.update(b"AXIOM_FACT_CONFIRM");
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
        verify_fact_link(&chain_after.links[0], &test_certified()).expect("link[0] verify");
        verify_fact_link(&chain_after.links[1], &test_certified()).expect("link[1] verify");
        // Last link must verify with confirmation now attached
        verify_fact_link(&chain_after.links[2], &test_certified()).expect("link[2] verify");
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
        let commitment = compute_fact_commitment(&tx_id, &prev, &new, amount, Some(&anchor), false, 4, &[], None);
        let mut witnesses = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let sig = crate::crypto::sign_dilithium(&key.sk, &commitment).expect("sign");
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            witnesses.push(FactWitness {
                validator_id: certified_id(&key.pk),
                validator_pk: key.pk.clone(),
                signature: sig,
                vbc_hash: certified_ref(&key.pk),
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
            burn_proof: None,
            burn_target_tx_id: None,
            sender_anchor: Some(anchor),
            is_dev_class: false,
            recall_proof: None,
            out_of_order_confirmation: None,
            inherited_scar_txids: Vec::new(),
            inherited_scar_resolutions: Vec::new(),
            receiver_witness: None,
        };
        verify_fact_link(&link, &test_certified()).expect("pre-roundtrip redeem link must verify");

        let chain = FactChain { checkpoint: None, links: vec![link.clone()] };
        let mut chain_bytes = Vec::new();
        ciborium::into_writer(&chain, &mut chain_bytes).expect("encode");

        // Pure round-trip without mutation
        let chain_decoded: FactChain = ciborium::from_reader(&chain_bytes[..]).expect("decode");
        assert_eq!(chain_decoded.links[0].sender_anchor, Some(anchor),
                   "sender_anchor must round-trip exactly");
        verify_fact_link(&chain_decoded.links[0], &test_certified())
            .expect("redeem link with sender_anchor must verify after pure round-trip");

        // Round-trip via Value
        let value: Value = ciborium::from_reader(&chain_bytes[..]).expect("decode value");
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf).expect("re-encode value");
        let chain_after: FactChain = ciborium::from_reader(&buf[..]).expect("decode after value");
        assert_eq!(chain_after.links[0].sender_anchor, Some(anchor),
                   "sender_anchor must survive Value round-trip");
        verify_fact_link(&chain_after.links[0], &test_certified())
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
        let commit0 = compute_fact_commitment(&tx0, &prev0, &new0, amount, None, true, 3, &[], None);
        let mut wits0 = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let sig = crate::crypto::sign_dilithium(&key.sk, &commit0).expect("sign 0");
            let mut vid = [0u8; 32]; vid[0] = i as u8;
            wits0.push(FactWitness {
                validator_id: certified_id(&key.pk),
                validator_pk: key.pk.clone(),
                signature: sig,
                vbc_hash: certified_ref(&key.pk),
            });
        }
        let link0 = FactLink {
            tx_id: tx0,
            previous_state_id: prev0,
            new_state_id: new0,
            amount, required_k: 3, tick: 0,
            witnesses: wits0,
            nabla_confirmation: None,
            burn_proof: None,
            burn_target_tx_id: None,
            sender_anchor: None,
            is_dev_class: true,
            recall_proof: None,
            out_of_order_confirmation: None,
            inherited_scar_txids: Vec::new(),
            inherited_scar_resolutions: Vec::new(),
            receiver_witness: None,
        };

        // Build link 1 chained from link 0's tip but with is_dev_class=FALSE
        // (the attack — a class boundary crossed mid-chain).
        let tx1: [u8; 32] = [0xB0; 32];
        let new1: [u8; 32] = [0xB1; 32];
        let commit1 = compute_fact_commitment(&tx1, &new0, &new1, amount, None, false, 3, &[], None);
        let mut wits1 = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let sig = crate::crypto::sign_dilithium(&key.sk, &commit1).expect("sign 1");
            let mut vid = [0u8; 32]; vid[0] = (i + 4) as u8;
            wits1.push(FactWitness {
                validator_id: certified_id(&key.pk),
                validator_pk: key.pk.clone(),
                signature: sig,
                vbc_hash: certified_ref(&key.pk),
            });
        }
        let link1 = FactLink {
            tx_id: tx1,
            previous_state_id: new0,
            new_state_id: new1,
            amount, required_k: 3, tick: 0,
            witnesses: wits1,
            nabla_confirmation: None,
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

        let chain = FactChain { checkpoint: None, links: vec![link0, link1] };
        let result = verify_fact_chain(&chain, &test_trust());
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
        let commit = compute_fact_commitment(&tx_tip, &[0u8; 32], &new_tip, amount, None, true, 3, &[], None);
        let mut wits = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let sig = crate::crypto::sign_dilithium(&key.sk, &commit).expect("sign tip");
            let mut vid = [0u8; 32]; vid[0] = i as u8;
            wits.push(FactWitness {
                validator_id: certified_id(&key.pk),
                validator_pk: key.pk.clone(),
                signature: sig,
                vbc_hash: certified_ref(&key.pk),
            });
        }
        let tip_link = FactLink {
            tx_id: tx_tip,
            previous_state_id: [0u8; 32],
            new_state_id: new_tip,
            amount, required_k: 3, tick: 0,
            witnesses: wits,
            nabla_confirmation: None,
            burn_proof: None,
            burn_target_tx_id: None,
            sender_anchor: None,
            is_dev_class: true,
            recall_proof: None,
            out_of_order_confirmation: None,
            inherited_scar_txids: Vec::new(),
            inherited_scar_resolutions: Vec::new(),
            receiver_witness: None,
        };
        let existing = FactChain { checkpoint: None, links: vec![tip_link] };

        // Try to append a link with is_dev_class=false. Build the
        // witness sigs for the NEW link's commitment (so verify_dilithium
        // succeeds and we hit the sticky-class check, not the sig check).
        let tx_new: [u8; 32] = [0xDD; 32];
        let new_new: [u8; 32] = [0xDE; 32];
        let new_commit = compute_fact_commitment(&tx_new, &new_tip, &new_new, amount, None, false, 3, &[], None);
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
                        genesis_lineage: [0u8; 32],
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
                        nabla_registration: None,
                    },
                    supporting_vbcs: vec![],
                    candidacy_pulse: None, renewal_work_receipt: None,
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
            &witness_sigs, None, None,
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
        let commit = compute_fact_commitment(&tx_tip, &[0u8; 32], &real_tip, amount, None, false, 3, &[], None);
        let mut wits = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let sig = crate::crypto::sign_dilithium(&key.sk, &commit).expect("sign tip");
            let mut vid = [0u8; 32]; vid[0] = i as u8;
            wits.push(FactWitness {
                validator_id: certified_id(&key.pk),
                validator_pk: key.pk.clone(),
                signature: sig,
                vbc_hash: certified_ref(&key.pk),
            });
        }
        let tip_link = FactLink {
            tx_id: tx_tip,
            previous_state_id: [0u8; 32],
            new_state_id: real_tip,
            amount, required_k: 3, tick: 0,
            witnesses: wits,
            nabla_confirmation: None,
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
        let existing = FactChain { checkpoint: None, links: vec![tip_link] };

        // Build a new link with a STALE previous_state_id — the
        // exact shape of the uj corruption (the SDK's wallet.state_id
        // drifted from chain.tip.new_state_id and shipped the stale
        // value as previous_state_id).
        let tx_new: [u8; 32] = [0xCC; 32];
        let stale_prev: [u8; 32] = [0xDE; 32];   // ← NOT real_tip
        let new_new: [u8; 32] = [0xCD; 32];
        let new_commit = compute_fact_commitment(&tx_new, &stale_prev, &new_new, amount, None, false, 3, &[], None);
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
                        genesis_lineage: [0u8; 32],
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
                        nabla_registration: None,
                    },
                    supporting_vbcs: vec![],
                    candidacy_pulse: None, renewal_work_receipt: None,
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
            &witness_sigs, None, None,
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
        let new_commit = compute_fact_commitment(&tx_new, &prev, &new, amount, None, false, 3, &[], None);
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
                        genesis_lineage: [0u8; 32],
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
                        nabla_registration: None,
                    },
                    supporting_vbcs: vec![],
                    candidacy_pulse: None, renewal_work_receipt: None,
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
            &witness_sigs, None, None,
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
        let std_result = verify_fact_chain(&chain, &test_trust());
        assert!(
            matches!(std_result, Err(ValidationError::FactInvalidSignature)),
            "standard verify_fact_chain MUST reject corrupt scar sig — got {:?}",
            std_result,
        );

        // burn_retire variant pointing at the same tx_id MUST accept.
        let burn_target = [0xAAu8; 32];
        let relax_result = verify_fact_chain_burn_retire(&chain, &burn_target, &test_trust());
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
        let result = verify_fact_chain_burn_retire(&chain, &burn_target, &test_trust());
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
        let result = verify_fact_chain_burn_retire(&chain, &burn_target, &test_trust());
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
        let result = verify_fact_chain_burn_retire(&chain, &burn_target, &test_trust());
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
        let result = verify_fact_chain_burn_retire(&chain, &unrelated_target, &test_trust());
        assert!(
            matches!(result, Err(ValidationError::FactInvalidSignature)),
            "verify_fact_chain_burn_retire MUST reject when burn_target_tx_id \
             matches no link (relax does not transfer) — got {:?}",
            result,
        );
    }
}
