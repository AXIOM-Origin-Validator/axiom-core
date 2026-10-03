//! YPX-009 Silicon Pulse — the ONE builder for the proof's signature
//! payload (Pattern 1), shared by Lambda (signs), Nabla (verifies before
//! gossiping) and Core CL8 (the §5.2.2e candidacy rule). Until 2026-09-08
//! the builder lived in `nabla/src/gossip.rs` and Lambda re-typed the same
//! bytes inline; now both call here.
//!
//! §5.2.2e (`AXIOM_DESIGN_ValidatorJoin.md`, ruled 2026-09-08): a PROVISIONAL
//! certificate request must carry the candidate's own Pulse proof — the
//! signed record that a Lambda+Core pair ran, ingested real transactions and
//! passed an audit. Verified here, in Core, fail-closed.

use crate::errors::CoreResult;
use crate::types::{ValidationError, VBCProofBundle, PULSE_EPOCH_LENGTH_TICKS};
use crate::wire_client::PulseProofRequest;

/// Candidacy floor on the proof's measured Argon2id throughput
/// (`protocol_core.toml`). `0` = "ran the audit chain at all" — the
/// operational bar as ruled ("a machine set up and ran the pulse check");
/// a positive floor adds "on silicon fit for service". RULED 0 on
/// 2026-09-08 ("measure, then set").
pub const PULSE_CANDIDACY_MIN_ARGON2ID_PER_SEC: u64 =
    crate::validation::protocol_gen::PULSE_CANDIDACY_MIN_ARGON2ID_PER_SEC;
/// How many Pulse epochs (`PULSE_EPOCH_LENGTH_TICKS` each) a candidacy proof
/// may lag the request's own epoch (derived from `tx.epoch`, the tick Core
/// already trusts).
pub const PULSE_CANDIDACY_MAX_EPOCH_AGE: u64 =
    crate::validation::protocol_gen::PULSE_CANDIDACY_MAX_EPOCH_AGE;
/// Minimum entries a candidacy proof must have chained. A SELF-AUDIT
/// (`axiom_dmap_vm::self_audit_pulse`) chains this many synthetic digests
/// with the real 32 MB Argon2id — that work IS the sybil cost (§40.2).
pub const PULSE_CANDIDACY_MIN_ENTRIES: u64 =
    crate::validation::protocol_gen::PULSE_CANDIDACY_MIN_ENTRIES;

/// YPX-009 §5.3: BLAKE3("AXIOM_PULSE_PROOF" || validator_pk || epoch_le ||
/// full_accumulator || audit_hash [|| attested_tick_le]).
///
/// §5.2.2e part iii (2026-09-10): a CANDIDACY proof also binds the
/// Nabla-attested tick it was seeded with — `attested_tick = Some(t)`. The
/// suffix is appended ONLY then (the non-zero-only-suffix pattern of
/// `compute_vbc_signing_payload_bytes`), so a running validator's live Pulse
/// (`None`) keeps a byte-identical payload and every existing signature stays
/// valid. ONE builder for Lambda (signs), Nabla (verifies), Core (candidacy)
/// and the SDK/tool producers.
pub fn pulse_proof_sign_payload(
    validator_pk: &[u8; 32],
    epoch: u64,
    full_accumulator: &[u8; 32],
    audit_hash: &[u8; 32],
    attested_tick: Option<u64>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_PULSE_PROOF");
    hasher.update(validator_pk);
    hasher.update(&epoch.to_le_bytes());
    hasher.update(full_accumulator);
    hasher.update(audit_hash);
    if let Some(t) = attested_tick {
        hasher.update(&t.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// The BLAKE3 seed of self-audit entry `i` — `("AXIOM_SELF_AUDIT", pk, tick, i)`.
/// ONE definition, used by the producer (`axiom_dmap_vm::self_audit_pulse`)
/// and the issuers' replay (`verify_self_audit_sample`): a new attested tick is
/// a new chain (KI#142 — the old `(pk, i)` seed made the work reusable).
pub fn self_audit_entry_seed(validator_pk: &[u8; 32], tick: u64, i: u32) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_SELF_AUDIT");
    h.update(validator_pk);
    h.update(&tick.to_le_bytes());
    h.update(&i.to_le_bytes());
    *h.finalize().as_bytes()
}

/// YPX-009 §5.3: Ed25519 over the payload, under the proof's own validator key.
pub fn verify_pulse_proof_sig(validator_pk: &[u8; 32], signature: &[u8], payload: &[u8; 32]) -> bool {
    signature.len() == 64 && crate::crypto::verify_ed25519(validator_pk, payload, signature).is_ok()
}

/// The proof's epoch, as the AVM derives it (`tick / PULSE_EPOCH_LENGTH_TICKS`).
pub fn pulse_epoch_of_tick(tick: u64) -> u64 {
    tick / PULSE_EPOCH_LENGTH_TICKS
}

/// How far (in ticks) the proof's seed tick may sit from the request round's
/// attested tick (`protocol_core.toml`). The self-audit takes seconds and the
/// TARDIS tick advances meanwhile; one epoch of slack keeps the proof fresh
/// per round without demanding equality.
pub const PULSE_CANDIDACY_TICK_SLACK: u64 =
    crate::validation::protocol_gen::PULSE_CANDIDACY_TICK_SLACK;

/// §5.2.2e — the checks on a candidacy proof (five from part i, three from part
/// iii). ⚠ Corrected 2026-09-21 (RULE 3 shape 7): this said "called only on the
/// provisional arm (a full certificate needs the stake, not a Pulse)". That is
/// stale post-KI#168 — issuance carries NO stake check (a VBC is a candidate
/// until Nabla stamps it, `modes.rs::execute_cl8`), so CL8 sets
/// `requires_candidacy_pulse` for EVERY 3-issuer VBC, full or renewal. The
/// candidacy Pulse is the per-key machine cost paid on every issuance; Q2-b's
/// `verify_renewal_work_receipt` is the orthogonal did-work gate on renewals.
/// `tx_epoch` is the request transaction's epoch; `round_attested_tick` is the
/// tick of the round's own `oods_attestation` — the same value CL8 binds the
/// certificate's stamp to, already refused when absent (`VBCNoAttestedTick`).
pub fn verify_candidacy_pulse(bundle: &VBCProofBundle, tx_epoch: u64, round_attested_tick: u64) -> CoreResult<()> {
    let p: &PulseProofRequest = bundle
        .candidacy_pulse
        .as_ref()
        .ok_or(ValidationError::VbcCandidacyPulseMissing)?;
    // 1. The proof is the CANDIDATE's: its validator key is the certificate's
    //    Ed25519 subject (= the stake wallet's key, §5.5.3). A proof lifted
    //    from a running validator's gossip cannot be pinned to another key.
    if bundle.target_vbc.subject_pubkey_ed25519.as_slice() != p.validator_pk.as_slice() {
        return Err(ValidationError::VbcCandidacyPulseInvalid);
    }
    // 6. (part iii) The proof carries the tick it was seeded with — otherwise
    //    it is the reusable `(pk, i)` work of KI#142.
    let seed_tick = p.attested_tick.ok_or(ValidationError::VbcCandidacyPulseUntimed)?;
    // 2. Signed by that key over the shared payload — which binds the tick.
    let payload = pulse_proof_sign_payload(&p.validator_pk, p.epoch, &p.full_accumulator, &p.audit_hash, Some(seed_tick));
    if !verify_pulse_proof_sig(&p.validator_pk, &p.signature, &payload) {
        return Err(ValidationError::VbcCandidacyPulseInvalid);
    }
    // 7. (part iii) The seed tick is THIS round's: within the slack of the
    //    Nabla-attested tick the request carries (verified at CL2 like every
    //    send's; CL8 binds the certificate's stamp to the same value). A
    //    proof seeded at some other time — precomputed, or lifted from an
    //    earlier request — fails here.
    if seed_tick.abs_diff(round_attested_tick) > PULSE_CANDIDACY_TICK_SLACK {
        return Err(ValidationError::VbcCandidacyPulseInvalid);
    }
    // 8. (part iii) The proof's epoch IS the seed tick's epoch (the producer
    //    derives one from the other; a mismatch is a hand-assembled proof).
    if pulse_epoch_of_tick(seed_tick) != p.epoch {
        return Err(ValidationError::VbcCandidacyPulseInvalid);
    }
    // 3. Real content, and enough of it: at least PULSE_CANDIDACY_MIN_ENTRIES
    //    chained (the self-audit's cost), a non-empty sample, a real hash
    //    (YPX-009 §5.2 items 4–5).
    if (p.entry_count as u64) < PULSE_CANDIDACY_MIN_ENTRIES || p.sample_size == 0 || p.audit_hash == [0u8; 32] {
        return Err(ValidationError::VbcCandidacyPulseInvalid);
    }
    // 4. Fresh against the tick Core already trusts.
    let request_epoch = pulse_epoch_of_tick(tx_epoch);
    if request_epoch.abs_diff(p.epoch) > PULSE_CANDIDACY_MAX_EPOCH_AGE {
        return Err(ValidationError::VbcCandidacyPulseInvalid);
    }
    // 5. Throughput floor (register; 0 = ran at all).
    if p.argon2id_per_sec < PULSE_CANDIDACY_MIN_ARGON2ID_PER_SEC {
        return Err(ValidationError::VbcCandidacyPulseInvalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::VBC;
    use alloc::vec;
    use alloc::vec::Vec;

    fn candidate() -> (ed25519_dalek::SigningKey, VBCProofBundle) {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x51u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let target = VBC {
            genesis_lineage: [0u8; 32],
            network_size_baseline: 9,
            baseline_tick: 1_000_000,
            version: 0x09,
            validator_id: [1u8; 32],
            subject_pubkey_sphincs: vec![2u8; 32],
            subject_pubkey_dilithium: vec![0u8; 1952],
            subject_pubkey_ed25519: pk.to_vec(),
            pgp_fingerprint: Vec::new(),
            node_name: alloc::string::String::new(),
            proof_cap: alloc::string::String::new(),
            issued_at: 1_000_000,
            expires_at: 1_000_000 + 3600, // provisional
            chain_depth: 1,
            issuer_set: vec![vec![3u8; 32], vec![4u8; 32], vec![5u8; 32]],
            signatures: Vec::new(),
            max_tx: 0,
            founding_vbc_hash: [0u8; 32],
            nabla_registration: None,
        };
        (sk, VBCProofBundle { target_vbc: target, supporting_vbcs: Vec::new(), candidacy_pulse: None, renewal_work_receipt: None })
    }

    /// A proof SEEDED at `seed_tick` (part iii): epoch derived from it, the
    /// tick bound into the signature and carried as `attested_tick`.
    fn proof_for(sk: &ed25519_dalek::SigningKey, seed_tick: u64) -> PulseProofRequest {
        use ed25519_dalek::Signer;
        let validator_pk = sk.verifying_key().to_bytes();
        let epoch = pulse_epoch_of_tick(seed_tick);
        let full_accumulator = [7u8; 32];
        let audit_hash = [8u8; 32];
        let payload = pulse_proof_sign_payload(&validator_pk, epoch, &full_accumulator, &audit_hash, Some(seed_tick));
        PulseProofRequest {
            validator_pk, epoch, full_accumulator, entry_count: 64, sample_size: 7, audit_hash,
            argon2id_per_sec: 21, signature: sk.sign(&payload).to_bytes().to_vec(),
            attested_tick: Some(seed_tick),
        }
    }

    const TICK: u64 = 1_000_000;

    #[test]
    fn a_provisional_request_without_a_pulse_is_refused_missing() {
        let (_, b) = candidate();
        assert_eq!(verify_candidacy_pulse(&b, TICK, TICK), Err(ValidationError::VbcCandidacyPulseMissing));
    }

    #[test]
    fn the_candidates_own_fresh_signed_proof_is_accepted() {
        let (sk, mut b) = candidate();
        b.candidacy_pulse = Some(proof_for(&sk, TICK));
        assert_eq!(verify_candidacy_pulse(&b, TICK, TICK), Ok(()));
    }

    #[test]
    fn a_proof_under_another_validators_key_is_refused() {
        let (_, mut b) = candidate();
        let other = ed25519_dalek::SigningKey::from_bytes(&[0x52u8; 32]);
        b.candidacy_pulse = Some(proof_for(&other, TICK));
        assert_eq!(verify_candidacy_pulse(&b, TICK, TICK), Err(ValidationError::VbcCandidacyPulseInvalid));
    }

    #[test]
    fn a_tampered_proof_is_refused() {
        let (sk, mut b) = candidate();
        let mut p = proof_for(&sk, TICK);
        p.audit_hash[0] ^= 1; // covered by the signature: it no longer verifies
        b.candidacy_pulse = Some(p);
        assert_eq!(verify_candidacy_pulse(&b, TICK, TICK), Err(ValidationError::VbcCandidacyPulseInvalid));
    }

    #[test]
    fn an_empty_audit_is_refused() {
        let (sk, mut b) = candidate();
        let mut p = proof_for(&sk, TICK);
        p.entry_count = 0; // not signed over, but content rules apply regardless
        b.candidacy_pulse = Some(p);
        assert_eq!(verify_candidacy_pulse(&b, TICK, TICK), Err(ValidationError::VbcCandidacyPulseInvalid));
    }

    #[test]
    fn a_thin_self_audit_below_the_entry_floor_is_refused() {
        let (sk, mut b) = candidate();
        let mut p = proof_for(&sk, TICK);
        p.entry_count = (PULSE_CANDIDACY_MIN_ENTRIES as u32).saturating_sub(1);
        b.candidacy_pulse = Some(p);
        assert_eq!(verify_candidacy_pulse(&b, TICK, TICK), Err(ValidationError::VbcCandidacyPulseInvalid));
    }

    #[test]
    fn a_stale_proof_is_refused() {
        let (sk, mut b) = candidate();
        // Seeded (and attested) a whole max-age + 1 epochs before the request's
        // clock: the seed/round pair agrees, the epoch-age check (4) refuses.
        let stale_tick = TICK.saturating_sub((PULSE_CANDIDACY_MAX_EPOCH_AGE + 1) * PULSE_EPOCH_LENGTH_TICKS);
        b.candidacy_pulse = Some(proof_for(&sk, stale_tick));
        assert_eq!(verify_candidacy_pulse(&b, TICK, stale_tick), Err(ValidationError::VbcCandidacyPulseInvalid));
    }

    // ── part iii (KI#142) ───────────────────────────────────────────────

    #[test]
    fn a_proof_without_a_seed_tick_is_refused_untimed() {
        let (sk, mut b) = candidate();
        let mut p = proof_for(&sk, TICK);
        p.attested_tick = None; // the reusable (pk, i) work of KI#142
        b.candidacy_pulse = Some(p);
        assert_eq!(verify_candidacy_pulse(&b, TICK, TICK), Err(ValidationError::VbcCandidacyPulseUntimed));
    }

    #[test]
    fn a_proof_seeded_outside_the_rounds_slack_is_refused() {
        let (sk, mut b) = candidate();
        // Fresh by epoch age, but seeded for a DIFFERENT round's tick — a
        // precomputed or lifted proof.
        let elsewhere = TICK.saturating_sub(PULSE_CANDIDACY_TICK_SLACK + 1);
        b.candidacy_pulse = Some(proof_for(&sk, elsewhere));
        assert_eq!(verify_candidacy_pulse(&b, TICK, TICK), Err(ValidationError::VbcCandidacyPulseInvalid));
        // Inside the slack it is this round's.
        let (sk2, mut b2) = candidate();
        b2.candidacy_pulse = Some(proof_for(&sk2, TICK.saturating_sub(PULSE_CANDIDACY_TICK_SLACK)));
        assert_eq!(verify_candidacy_pulse(&b2, TICK, TICK), Ok(()));
    }

    #[test]
    fn a_proof_whose_epoch_disagrees_with_its_seed_tick_is_refused() {
        use ed25519_dalek::Signer;
        let (sk, mut b) = candidate();
        let mut p = proof_for(&sk, TICK);
        p.epoch += 1; // re-signed with a hand-picked epoch: not the producer's
        let payload = pulse_proof_sign_payload(&p.validator_pk, p.epoch, &p.full_accumulator, &p.audit_hash, Some(TICK));
        p.signature = sk.sign(&payload).to_bytes().to_vec();
        b.candidacy_pulse = Some(p);
        assert_eq!(verify_candidacy_pulse(&b, TICK, TICK), Err(ValidationError::VbcCandidacyPulseInvalid));
    }
}
