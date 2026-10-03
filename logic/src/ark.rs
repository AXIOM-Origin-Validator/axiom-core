//! §6.9 / YPX-010: Ark Mode ⟠ — Offline Operation & Confidence Index
//!
//! Etymology: "Ark" is both the literal vessel that carries value through the
//! flood (loss of connectivity → return to dry land) and the canonical
//! backronym **A**synchronous **R**esilience **K**etch (a ketch: a small,
//! resilient two-masted vessel). An "Ark wallet" is a wallet whose `wallet_id`
//! encodes the Ark security tier (`K_ARK=0, PROOF_TYPE_ARK`; see
//! `wallet_id.rs::WALLET_ID_PARAMS[0]`). It is the **k=0 tier address of the
//! SAME keypair** as its normal (k=3/4/5) wallet — one Ed25519 key derives all
//! 7 tier addresses via `generate_all_wallet_ids` (YP §11.9.1). "Same owner"
//! for charge/unload/self-ark is therefore the shared `pk` (`verify_pk_binding`),
//! not a certificate or an email-string match. (An earlier two-keypair +
//! PairBinding design was retired 2026-07-17 — see YPX-010 §10 and
//! `AXIOM_DESIGN_WalletPairCollapse.md`.) Offline value is never un-backed; it
//! goes recoverable, waiting for witnessing (see the load → flood → recede
//! lifecycle below).
//!
//! Ark mode enables offline value transfer between Ark wallets (k=0).
//! Both sender and receiver run Core/AVM locally with DMAP — no validators,
//! no k=3. Value is pre-loaded from normal wallets (k=3 required) and
//! reconciled back to normal wallets when connectivity resumes (k=3 required).
//!
//! The Confidence Index (CI) is computed by the RECEIVER from the sender's
//! FACT chain. All five factors are offline-verifiable. Core is the law.
//!
//! Five trust factors (YPX-010 §2):
//!   1. K=3 staleness — time since last online validation
//!   2. Ark TX count — behavioral consistency signal
//!   3. Stakes ratio — skin in the game (K=3 balance / Ark amount)
//!   4. TX vs history — anomaly detection
//!   5. Validator ecosystem depth — settlement risk
//!
//! Research foundations: disaster infrastructure (FCC DIRS), behavioural fraud
//! detection (Jurgovsky 2018), rational choice economics (Becker 1968),
//! skin-in-the-game (Taleb 2018), disaster sociology (Quarantelli).

use crate::types::{
    ArkArtifact, ConfidenceIndex, TxKind,
    ARK_ARTIFACT_DOMAIN, CI_DOMAIN,
};

// ── Staleness bands (YPX-010 §2 Factor 1) ─────────────────────────────────

/// FRESH: K=3 within 30 minutes. Network almost certainly live.
pub const STALENESS_FRESH_SECS: u64 = crate::validation::protocol_gen::STALENESS_FRESH_SECS;
/// WARM: K=3 within 5 hours. Within battery backup window.
pub const STALENESS_WARM_SECS: u64 = crate::validation::protocol_gen::STALENESS_WARM_SECS;
/// STALE: K=3 within 12 hours. Past battery, within FCC 12h mandatory backup.
pub const STALENESS_STALE_SECS: u64 = crate::validation::protocol_gen::STALENESS_STALE_SECS;
// Beyond STALE = COLD. Past all mandatory backup. Tier 2+ disaster.

// ── Ark TX count thresholds (YPX-010 §2 Factor 2) ─────────────────────────

pub const ARK_TX_HIGH: u64 = 15;
pub const ARK_TX_MEDIUM: u64 = 4;
// Below MEDIUM = LOW (1-3), 0 = NONE

// ── Stakes ratio thresholds (YPX-010 §2 Factor 3) ─────────────────────────

/// SAFE: K=3 balance >= 10x Ark TX amount. Fraud is irrational.
pub const STAKES_SAFE_MULTIPLIER: u64 = 10;
/// MODERATE: 3-10x. Fraud is costly but not catastrophic.
pub const STAKES_MODERATE_MULTIPLIER: u64 = 3;
// Below MODERATE = THIN (1-3x). Below 1x = UNDERWATER (always RED).

// ── Liveness gate L (paper3 §7.1 / §6) ────────────────────────────────────

/// The Δ, in seconds, past which a sender's last-k=3 anchor is "unexplained-stale"
/// WHEN the receiver has measured the network to be live (a Nabla-attested current
/// tick). Same second-basis as compute_staleness. Small by design: the demo only
/// needs a Cold sender to exceed it. §6 calibration knob.
pub const L_DELTA_SECS: u64 = 10;

// ── CI status levels ───────────────────────────────────────────────────────

/// Confidence Index status (YPX-010 §4)
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CIStatus {
    /// Low risk — normal offline acceptance
    Green,
    /// Moderate risk — reduced limits or extra caution
    Yellow,
    /// High risk — offline payment discouraged or refused
    Red,
}

/// Staleness band (YPX-010 §2 Factor 1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Staleness {
    Fresh,  // < 30 min
    Warm,   // 30 min – 5 hours
    Stale,  // 5 – 12 hours
    Cold,   // > 12 hours
}

/// Stakes level (YPX-010 §2 Factor 3)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StakesLevel {
    Safe,       // >= 10x
    Moderate,   // 3-10x
    Thin,       // 1-3x
    Underwater, // < 1x (always RED)
}

/// TX count level (YPX-010 §2 Factor 2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArkTxLevel {
    High,   // > 15
    Medium, // 4-15
    Low,    // 1-3
    None,   // 0
}

/// Ecosystem depth (YPX-010 §2 Factor 5)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcosystemDepth {
    Deep,    // >= 3 validators
    Shallow, // 1-2
    Unknown, // 0
}

// ── Factor computation ─────────────────────────────────────────────────────

pub fn compute_staleness(last_k3_at: u64, current_time: u64) -> Staleness {
    let elapsed = current_time.saturating_sub(last_k3_at);
    if elapsed < STALENESS_FRESH_SECS { Staleness::Fresh }
    else if elapsed < STALENESS_WARM_SECS { Staleness::Warm }
    else if elapsed < STALENESS_STALE_SECS { Staleness::Stale }
    else { Staleness::Cold }
}

pub fn compute_stakes_level(k3_balance: u64, ark_amount: u64) -> StakesLevel {
    if ark_amount == 0 { return StakesLevel::Safe; }
    let ratio = k3_balance / ark_amount;
    if ratio >= STAKES_SAFE_MULTIPLIER { StakesLevel::Safe }
    else if ratio >= STAKES_MODERATE_MULTIPLIER { StakesLevel::Moderate }
    else if k3_balance >= ark_amount { StakesLevel::Thin }
    else { StakesLevel::Underwater }
}

pub fn compute_ark_tx_level(count: u64) -> ArkTxLevel {
    if count > ARK_TX_HIGH { ArkTxLevel::High }
    else if count >= ARK_TX_MEDIUM { ArkTxLevel::Medium }
    else if count >= 1 { ArkTxLevel::Low }
    else { ArkTxLevel::None }
}

pub fn compute_ecosystem_depth(validator_count: u8) -> EcosystemDepth {
    if validator_count >= 3 { EcosystemDepth::Deep }
    else if validator_count >= 1 { EcosystemDepth::Shallow }
    else { EcosystemDepth::Unknown }
}

/// Check if transaction amount is anomalous vs history (YPX-010 §2 Factor 4)
pub fn is_amount_anomalous(current_amount: u64, mean_amount: u64) -> bool {
    if mean_amount == 0 { return false; } // no history to compare
    // Anomalous if > 3x the historical mean
    current_amount > mean_amount.saturating_mul(3)
}

// ── CI factor readers (YPX-010 §3.4 / BUILD_ARK §3.4) ─────────────────────

/// P3.6 §3.4 — read the five CI factors + override flags from a sender's FACT chain.
///
/// Runs at an ONLINE k=3 send: `k3_balance` / `k3_tick` are the CURRENT k=3 state (this
/// send is the freshest last-k=3 the receiver will later measure live staleness
/// against), and `prior_chain` is the sender's chain BEFORE this send's link. Everything
/// else is derived from the chain through existing accessors — no new chain state. Core
/// stamps the result into the sender's k=3 receipt (the P3.6 commitment binding) so the
/// k witnesses sign the factors; the offline receiver then verifies those signatures and
/// recomputes the SAME factors from the SAME chain to confirm they match (§11.6). The
/// receiver adds the live staleness factor itself (`evaluate_ci`'s `live_tick`) — no
/// past signature can carry "now."
pub fn compute_ci_factors(
    prior_chain: &crate::types::FactChain,
    wallet_pk: &[u8],
    k3_balance: u64,
    k3_tick: u64,
) -> ConfidenceIndex {
    use crate::wallet_id::K_ARK;
    let links = &prior_chain.links;

    // Index of the most recent k≥3 (online-settled) link. k=0 links AFTER it are the
    // "since last k=3" offline spends the receiver weighs as Factor 2.
    let last_k3_idx = links
        .iter()
        .rposition(|l| (l.required_k as usize) >= crate::fact::MIN_FACT_WITNESSES);

    // Factor 2: Ark (k=0) tx count since the last k=3 (whole chain if never online).
    let ark_tx_count_since_k3 = match last_k3_idx {
        Some(i) => links[i + 1..].iter().filter(|l| l.required_k == K_ARK).count() as u64,
        None => links.iter().filter(|l| l.required_k == K_ARK).count() as u64,
    };

    // Factor 4: mean amount of prior Ark (k=0) links (0 if none).
    let (ark_sum, ark_n) = links
        .iter()
        .filter(|l| l.required_k == K_ARK)
        .fold((0u128, 0u64), |(s, n), l| (s + l.amount as u128, n + 1));
    let ark_tx_mean_amount = if ark_n > 0 { (ark_sum / ark_n as u128) as u64 } else { 0 };

    // Factor 5: distinct validators that witnessed prior links (ecosystem depth).
    let mut seen: alloc::vec::Vec<[u8; 32]> = alloc::vec::Vec::new();
    for l in links {
        for w in &l.witnesses {
            if !seen.iter().any(|v| v == &w.validator_id) {
                seen.push(w.validator_id);
            }
        }
    }
    let ark_validator_count = seen.len().min(u8::MAX as usize) as u8;

    // Overrides (§3). A scar on the presented k=3 chain is disqualifying; the wallet
    // has done a k=3 iff it is doing one now (k3_tick set) or its chain already carries
    // one. `conflict_count` is a Nabla-layer ban signal (a caught double-spend surfaces
    // as the settlement fork-ban, §12.3, not on an honest verifying chain) → 0 here.
    let has_any_k3 = k3_tick > 0 || last_k3_idx.is_some();
    // §10.4.1 scoping (BUILD §3.4): the scar OVERRIDE reads the presented k=3
    // chain only — an unresolved k=0 (Ark) link is the NORMAL state of every
    // not-yet-settled offline trade and already feeds Factor 2 via
    // `ark_tx_count_since_k3`; counting it here would hard-RED every second
    // consecutive offline spend.
    let has_fact_scar = links
        .iter()
        .any(|l| l.required_k != K_ARK && !l.is_resolved());

    ConfidenceIndex {
        wallet_pk: wallet_pk.to_vec(),
        last_k3_at: k3_tick,
        ark_tx_count_since_k3,
        k3_balance,
        ark_tx_mean_amount,
        ark_validator_count,
        has_fact_scar,
        has_any_k3,
        conflict_count: 0,
        // The Core-stamped CI is authenticated by the receipt's k-witness signatures
        // (P3.6), NOT a separate Lambda-issued CI credential (retired, Phase 0).
        validator_signature: alloc::vec::Vec::new(),
        issuer_validator_pk: alloc::vec::Vec::new(),
    }
}

// ── CI evaluation (YPX-010 §3-4) ──────────────────────────────────────────

/// Evaluate the Confidence Index: the 5 sender-derived factors (YPX-010) plus the
/// receiver's liveness gate L (paper3 §7.1).
///
/// This is the core evaluation function. The receiver computes the CI factors from
/// the sender's FACT chain and supplies its OWN `live_tick` measurement, then calls
/// this to get GREEN/YELLOW/RED. `live_tick = None` means the receiver is also dark
/// (L neutral); `Some(t)` means the receiver reached the network and t is the
/// Nabla-attested current tick.
///
/// `sender_nabla_healthy` is the sender's carried Nabla health — the receiver reads
/// it from the presented k=3 receipt's `oods_flag.healthy` (YPX-021). It is
/// **TIGHTEN-ONLY** (paper3 v0.18 §6): `false` applies one conservative step-down
/// to the final score and can never raise it, and it can never rescue the L clamp
/// (`receiver-live ∧ sender-stale → RED` fires first regardless). One-directional
/// on purpose: the flag is self-inducible (a sender can self-eclipse its Nabla view),
/// so honoring `healthy == false` as an *excuse* for staleness would hand the sender
/// a switch to disable L. Health corroborates a deeper outage; it never explains one
/// away.
///
/// Core is the law — this function is the sole authority on CI status.
pub fn evaluate_ci(
    ci: &ConfidenceIndex,
    current_time: u64,
    ark_amount: u64,
    live_tick: Option<u64>,
    sender_nabla_healthy: bool,
) -> CIStatus {
    // === Unconditional overrides (YPX-010 §3) ===

    // Liveness gate L (paper3 §7.1) — the receiver's OWN measurement, not sender data,
    // so it is a parameter, not a ConfidenceIndex field. `live_tick` is the Nabla-attested
    // current tick IFF the receiver reached the network (None = both dark). When the world
    // is provably live and the sender's last k=3 is stale beyond Δ, the staleness is
    // *unexplained* → RED, regardless of the sender's history/ecosystem strength. This is
    // placed with the unconditional overrides ON PURPOSE: it must fire before the
    // compensatory base_ci matrix that otherwise caps a strong-but-stale sender at YELLOW.
    if let Some(t) = live_tick {
        if t.saturating_sub(ci.last_k3_at) > L_DELTA_SECS {
            return CIStatus::Red;
        }
    }

    // FACT scar present → always RED
    if ci.has_fact_scar {
        return CIStatus::Red;
    }

    // No K=3 ever → always RED
    if !ci.has_any_k3 {
        return CIStatus::Red;
    }

    // Any prior double-spend → always RED
    if ci.conflict_count > 0 {
        return CIStatus::Red;
    }

    // Stakes underwater → always RED
    let stakes = compute_stakes_level(ci.k3_balance, ark_amount);
    if stakes == StakesLevel::Underwater {
        return CIStatus::Red;
    }

    // Ecosystem unknown + significant amount → always RED
    let ecosystem = compute_ecosystem_depth(ci.ark_validator_count);
    if ecosystem == EcosystemDepth::Unknown && ark_amount > ci.ark_tx_mean_amount.saturating_mul(2) {
        return CIStatus::Red;
    }

    // === Compute factors ===

    let staleness = compute_staleness(ci.last_k3_at, current_time);
    let tx_level = compute_ark_tx_level(ci.ark_tx_count_since_k3);
    let anomalous = is_amount_anomalous(ark_amount, ci.ark_tx_mean_amount);

    // === CI Matrix evaluation (YPX-010 §4) ===

    let base_ci = match staleness {
        Staleness::Fresh => evaluate_fresh(stakes, anomalous, ecosystem),
        Staleness::Warm => evaluate_warm(tx_level, stakes, anomalous, ecosystem),
        Staleness::Stale => evaluate_stale(tx_level, stakes, anomalous, ecosystem),
        Staleness::Cold => evaluate_cold(tx_level, stakes, ecosystem),
    };

    // === Settlement modifier (YPX-010 §4.5) ===
    let scored = apply_settlement_modifier(base_ci, ecosystem);

    // === Sender-health tighten (paper3 v0.18 §6 — TIGHTEN-ONLY) ===
    apply_sender_health_tighten(scored, sender_nabla_healthy)
}

fn evaluate_fresh(stakes: StakesLevel, anomalous: bool, ecosystem: EcosystemDepth) -> CIStatus {
    if anomalous { return CIStatus::Yellow; }
    match (stakes, ecosystem) {
        (StakesLevel::Safe, EcosystemDepth::Deep) => CIStatus::Green,
        (StakesLevel::Safe, EcosystemDepth::Shallow) => CIStatus::Yellow,
        (StakesLevel::Safe, EcosystemDepth::Unknown) => CIStatus::Yellow,
        (StakesLevel::Moderate, _) => CIStatus::Green,
        (StakesLevel::Thin, _) => CIStatus::Yellow,
        _ => CIStatus::Red,
    }
}

fn evaluate_warm(tx: ArkTxLevel, stakes: StakesLevel, anomalous: bool, eco: EcosystemDepth) -> CIStatus {
    if anomalous { return CIStatus::Red; }
    match (tx, stakes, eco) {
        (ArkTxLevel::High, StakesLevel::Safe, EcosystemDepth::Deep) => CIStatus::Green,
        (ArkTxLevel::High, StakesLevel::Safe, _) => CIStatus::Yellow,
        (ArkTxLevel::High, StakesLevel::Moderate, EcosystemDepth::Deep) => CIStatus::Green,
        (ArkTxLevel::High, StakesLevel::Moderate, _) => CIStatus::Yellow,
        (ArkTxLevel::Medium, StakesLevel::Safe, EcosystemDepth::Deep) => CIStatus::Green,
        (ArkTxLevel::Medium, StakesLevel::Safe, _) => CIStatus::Yellow,
        (ArkTxLevel::Medium, StakesLevel::Moderate, EcosystemDepth::Deep) => CIStatus::Yellow,
        (ArkTxLevel::Medium, StakesLevel::Moderate, _) => CIStatus::Yellow,
        (ArkTxLevel::Low, StakesLevel::Safe, EcosystemDepth::Deep) => CIStatus::Yellow,
        (ArkTxLevel::Low, StakesLevel::Moderate, _) => CIStatus::Yellow,
        (ArkTxLevel::None, StakesLevel::Safe, _) => CIStatus::Yellow,
        _ => CIStatus::Red,
    }
}

fn evaluate_stale(tx: ArkTxLevel, stakes: StakesLevel, anomalous: bool, eco: EcosystemDepth) -> CIStatus {
    if anomalous { return CIStatus::Red; }
    match (tx, stakes, eco) {
        (ArkTxLevel::High, StakesLevel::Safe, EcosystemDepth::Deep) => CIStatus::Green,
        (ArkTxLevel::High, StakesLevel::Safe, _) => CIStatus::Yellow,
        (ArkTxLevel::High, StakesLevel::Moderate, EcosystemDepth::Deep) => CIStatus::Yellow,
        (ArkTxLevel::Medium, StakesLevel::Safe, EcosystemDepth::Deep) => CIStatus::Yellow,
        _ => CIStatus::Red,
    }
}

fn evaluate_cold(tx: ArkTxLevel, stakes: StakesLevel, eco: EcosystemDepth) -> CIStatus {
    match (tx, stakes, eco) {
        (ArkTxLevel::High, StakesLevel::Safe, EcosystemDepth::Deep) => CIStatus::Yellow,
        (ArkTxLevel::High, StakesLevel::Moderate, EcosystemDepth::Deep) => CIStatus::Yellow,
        (ArkTxLevel::Medium, StakesLevel::Safe, EcosystemDepth::Deep) => CIStatus::Yellow,
        _ => CIStatus::Red,
    }
}

/// Sender-health tighten (paper3 v0.18 §6 / YPX-010 reframe). An unhealthy sender
/// Nabla view (`oods_flag.healthy == false` on the presented k=3 receipt)
/// corroborates a deeper outage → ONE conservative step-down of the final score.
/// Monotone by construction: the healthy branch is the identity and the unhealthy
/// branch only lowers, so no input can score HIGHER by carrying `healthy = false` —
/// and the L clamp (an early `return Red` in `evaluate_ci`) is untouchable from
/// here because RED maps to RED. Tighten-only; see the `evaluate_ci` doc-comment
/// for why the flag must never loosen.
fn apply_sender_health_tighten(base: CIStatus, sender_nabla_healthy: bool) -> CIStatus {
    if sender_nabla_healthy {
        return base;
    }
    match base {
        CIStatus::Green => CIStatus::Yellow,
        CIStatus::Yellow => CIStatus::Red,
        CIStatus::Red => CIStatus::Red,
    }
}

fn apply_settlement_modifier(base: CIStatus, ecosystem: EcosystemDepth) -> CIStatus {
    match ecosystem {
        EcosystemDepth::Deep => base,
        EcosystemDepth::Shallow => match base {
            CIStatus::Green => CIStatus::Yellow,
            other => other, // YELLOW stays YELLOW, RED stays RED
        },
        EcosystemDepth::Unknown => match base {
            CIStatus::Green => CIStatus::Yellow, // YELLOW floor
            other => other,
        },
    }
}

// ── Artifact functions (unchanged) ─────────────────────────────────────────

/// Compute the hash of an Ark artifact (for chaining).
pub fn compute_artifact_hash(artifact: &ArkArtifact) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ARK_ARTIFACT_DOMAIN);
    hasher.update(&artifact.last_state_id);
    hasher.update(&artifact.ark_nonce.to_le_bytes());
    hasher.update(&artifact.dmap_attestation_hash);
    hasher.update(&artifact.transaction.consumed_state_id);
    hasher.update(&artifact.transaction.client_pk);
    hasher.update(&artifact.transaction.amount.to_le_bytes());
    hasher.update(artifact.transaction.receiver_wallet_id.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Compute the CI signing message.
pub fn compute_ci_signing_message(ci: &ConfidenceIndex) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CI_DOMAIN);
    hasher.update(&ci.wallet_pk);
    hasher.update(&ci.last_k3_at.to_le_bytes());
    hasher.update(&ci.ark_tx_count_since_k3.to_le_bytes());
    hasher.update(&ci.k3_balance.to_le_bytes());
    hasher.update(&ci.conflict_count.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Verify artifact structure.
pub fn verify_artifact_structure(
    artifact: &ArkArtifact,
    prev_artifact: Option<&ArkArtifact>,
) -> Result<(), ArkError> {
    if artifact.transaction.amount == 0 {
        return Err(ArkError::ZeroAmount);
    }
    if artifact.transaction.consumed_state_id != artifact.last_state_id {
        return Err(ArkError::StateIdMismatch);
    }
    if let Some(prev) = prev_artifact {
        if artifact.ark_nonce <= prev.ark_nonce {
            return Err(ArkError::NonceTooLow);
        }
        let prev_hash = compute_artifact_hash(prev);
        match artifact.prev_artifact_hash {
            Some(ref h) if *h == prev_hash => {}
            Some(_) => return Err(ArkError::ChainHashMismatch),
            None => return Err(ArkError::MissingPrevHash),
        }
    }
    Ok(())
}

/// Verify CI signature using Ed25519.
pub fn verify_ci_signature(ci: &ConfidenceIndex) -> bool {
    let message = compute_ci_signing_message(ci);
    if ci.issuer_validator_pk.len() != 32 || ci.validator_signature.len() != 64 {
        return false;
    }
    let pk_bytes: [u8; 32] = match ci.issuer_validator_pk.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_bytes: [u8; 64] = match ci.validator_signature.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    use ed25519_dalek::{VerifyingKey, Signature, Verifier};
    let pk = match VerifyingKey::from_bytes(&pk_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&sig_bytes);
    pk.verify(&message, &sig).is_ok()
}

/// Ark-specific errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArkError {
    ZeroAmount,
    StateIdMismatch,
    NonceTooLow,
    ChainHashMismatch,
    MissingPrevHash,
}

impl core::fmt::Display for ArkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ZeroAmount => write!(f, "Ark artifact: zero amount"),
            Self::StateIdMismatch => write!(f, "Ark artifact: consumed_state_id != last_state_id"),
            Self::NonceTooLow => write!(f, "Ark artifact: nonce not monotonically increasing"),
            Self::ChainHashMismatch => write!(f, "Ark artifact: chain hash mismatch"),
            Self::MissingPrevHash => write!(f, "Ark artifact: missing prev_artifact_hash"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::string::String;
    use crate::types::{Transaction, FactChain, FactLink, FactWitness};

    // P3.6 §3.4 — the factor reader derives Ark-since-k=3 count, mean amount, distinct
    // validators, and the scar override from a sender's chain; k=3 balance/tick are the
    // caller's current online state.
    #[test]
    fn compute_ci_factors_reads_chain() {
        let link = |required_k: u8, amount: u64, vids: &[u8], resolved: bool| {
            let witnesses = vids.iter().map(|&b| FactWitness {
                validator_id: [b; 32], validator_pk: vec![0u8; 8],
                signature: vec![0u8; 8], vbc_hash: [0u8; 32],
            }).collect();
            FactLink {
                tx_id: [amount as u8; 32], previous_state_id: [0u8; 32], new_state_id: [1u8; 32],
                amount, required_k, tick: 100, witnesses,
                // resolved => a Nabla confirmation (online) makes is_resolved() true.
                nabla_confirmation: if resolved { Some(crate::types::NablaConfirmation {
                    nabla_node_id: [9u8; 32], nabla_signature: vec![0u8; 64],
                    root_hash: [0u8; 32], synced_to_tick: 1, ..Default::default() }) } else { None },
                burn_proof: None, burn_target_tx_id: None,
                sender_anchor: None, is_dev_class: false, recall_proof: None, out_of_order_confirmation: None,
                inherited_scar_txids: vec![], inherited_scar_resolutions: vec![],
                receiver_witness: None,
            }
        };
        // history: a k=3 settled link (validators 1,2,3), then two k=0 offline links.
        let chain = FactChain {
            checkpoint: None,
            links: vec![
                link(3, 1_000, &[1, 2, 3], true),  // last k=3
                link(0, 400, &[], false),          // k=0 offline (unresolved scar)
                link(0, 600, &[], false),          // k=0 offline
            ],
        };
        let ci = compute_ci_factors(&chain, &[7u8; 32], 50_000, 999);

        assert_eq!(ci.last_k3_at, 999, "last_k3_at = the current k=3 tick");
        assert_eq!(ci.k3_balance, 50_000);
        assert_eq!(ci.ark_tx_count_since_k3, 2, "two k=0 links after the last k=3");
        assert_eq!(ci.ark_tx_mean_amount, 500, "(400+600)/2");
        assert_eq!(ci.ark_validator_count, 3, "validators 1,2,3 distinct");
        assert!(ci.has_any_k3);
        // §10.4.1 scoping (BUILD §3.4): unresolved k=0 links are the NORMAL
        // state of unsettled offline trades — they feed Factor 2 (counted
        // above), NOT the scar override. Only a k≥3 scar disqualifies.
        assert!(!ci.has_fact_scar, "unresolved k=0 links must NOT trip the scar override");
        assert_eq!(ci.conflict_count, 0);
        assert!(ci.validator_signature.is_empty(), "Core-stamped CI is receipt-signed, not credential-signed");

        // An unresolved k≥3 link IS the scar override.
        let scarred = FactChain {
            checkpoint: None,
            links: vec![
                link(3, 1_000, &[1, 2, 3], false), // k=3, UNRESOLVED → scar
                link(0, 400, &[], false),
            ],
        };
        let ci2 = compute_ci_factors(&scarred, &[7u8; 32], 50_000, 999);
        assert!(ci2.has_fact_scar, "an unresolved k≥3 link is the §3 scar override");
    }

    fn make_test_ci(last_k3_at: u64) -> ConfidenceIndex {
        ConfidenceIndex {
            wallet_pk: vec![1u8; 32],
            last_k3_at,
            ark_tx_count_since_k3: 20,
            k3_balance: 1_000_000,
            ark_tx_mean_amount: 10_000,
            ark_validator_count: 3,
            has_fact_scar: false,
            has_any_k3: true,
            conflict_count: 0,
            validator_signature: vec![],
            issuer_validator_pk: vec![],
        }
    }

    fn make_test_tx() -> Transaction {
        Transaction {
            consumed_state_id: [7u8; 32],
            client_pk: vec![1u8; 32],
            sender_wallet_id: String::new(),
            client_sig: vec![0u8; 64],
            wallet_seq: 1,
            receiver_wallet_id: "test@test.com/a1b2c3d4".to_string(),
            receiver_address: None,
            amount: 100_000,
            reference: "ark test".to_string(),
            nonce: 42,
            epoch: 1,
            scar_passcode: None,
            burn_target_tx_id: None,
            recall_target_tx_id: None,
            required_k: 0,
            proof_type: 0,
            oracle_claim: None,
            core_version: String::new(),
            core_id: [0u8; 32],
            kind: TxKind::Normal,
        }
    }

    fn make_test_artifact(nonce: u64, prev_hash: Option<[u8; 32]>) -> ArkArtifact {
        ArkArtifact {
            transaction: make_test_tx(),
            last_state_id: [7u8; 32],
            ark_nonce: nonce,
            dmap_attestation_hash: [42u8; 32],
            prev_artifact_hash: prev_hash,
            confidence_index: make_test_ci(1000000),
            created_at_secs: 1000000,
        }
    }

    // ── Factor computation tests ───────────────────────────────────────

    #[test]
    fn test_staleness_fresh() {
        assert_eq!(compute_staleness(1000, 1500), Staleness::Fresh); // 500s = 8min
    }

    #[test]
    fn test_staleness_warm() {
        assert_eq!(compute_staleness(1000, 5000), Staleness::Warm); // 4000s = 66min
    }

    #[test]
    fn test_staleness_stale() {
        assert_eq!(compute_staleness(1000, 25000), Staleness::Stale); // 24000s = 400min
    }

    #[test]
    fn test_staleness_cold() {
        assert_eq!(compute_staleness(1000, 100000), Staleness::Cold); // 99000s = 27h
    }

    #[test]
    fn test_stakes_safe() {
        assert_eq!(compute_stakes_level(1_000_000, 10_000), StakesLevel::Safe); // 100x
    }

    #[test]
    fn test_stakes_moderate() {
        assert_eq!(compute_stakes_level(50_000, 10_000), StakesLevel::Moderate); // 5x
    }

    #[test]
    fn test_stakes_thin() {
        assert_eq!(compute_stakes_level(15_000, 10_000), StakesLevel::Thin); // 1.5x
    }

    #[test]
    fn test_stakes_underwater() {
        assert_eq!(compute_stakes_level(5_000, 10_000), StakesLevel::Underwater); // 0.5x
    }

    #[test]
    fn test_anomalous_amount() {
        assert!(is_amount_anomalous(50_000, 10_000)); // 5x > 3x threshold
        assert!(!is_amount_anomalous(20_000, 10_000)); // 2x < 3x threshold
    }

    // ── Override tests ─────────────────────────────────────────────────

    #[test]
    fn test_override_fact_scar() {
        let mut ci = make_test_ci(1000000);
        ci.has_fact_scar = true;
        assert_eq!(evaluate_ci(&ci, 1000100, 10_000, None, true), CIStatus::Red);
    }

    #[test]
    fn test_override_no_k3() {
        let mut ci = make_test_ci(1000000);
        ci.has_any_k3 = false;
        assert_eq!(evaluate_ci(&ci, 1000100, 10_000, None, true), CIStatus::Red);
    }

    #[test]
    fn test_override_conflicts() {
        let mut ci = make_test_ci(1000000);
        ci.conflict_count = 1;
        assert_eq!(evaluate_ci(&ci, 1000100, 10_000, None, true), CIStatus::Red);
    }

    #[test]
    fn test_override_underwater() {
        let mut ci = make_test_ci(1000000);
        ci.k3_balance = 5_000; // less than ark_amount
        assert_eq!(evaluate_ci(&ci, 1000100, 10_000, None, true), CIStatus::Red);
    }

    // ── Matrix tests — FRESH ───────────────────────────────────────────

    #[test]
    fn test_fresh_safe_deep_green() {
        let ci = make_test_ci(1000000);
        // Fresh (100s ago), Safe (100x), Deep (3 validators)
        assert_eq!(evaluate_ci(&ci, 1000100, 10_000, None, true), CIStatus::Green);
    }

    #[test]
    fn test_fresh_thin_yellow() {
        let mut ci = make_test_ci(1000000);
        ci.k3_balance = 15_000; // Thin (1.5x)
        assert_eq!(evaluate_ci(&ci, 1000100, 10_000, None, true), CIStatus::Yellow);
    }

    // ── Matrix tests — WARM ────────────────────────────────────────────

    #[test]
    fn test_warm_high_safe_deep_green() {
        let ci = make_test_ci(1000000);
        // Warm (3600s = 1h), High (20 TXs), Safe (100x), Deep (3)
        assert_eq!(evaluate_ci(&ci, 1003600, 10_000, None, true), CIStatus::Green);
    }

    #[test]
    fn test_warm_none_thin_red() {
        let mut ci = make_test_ci(1000000);
        ci.ark_tx_count_since_k3 = 0;
        ci.k3_balance = 15_000; // Thin
        assert_eq!(evaluate_ci(&ci, 1003600, 10_000, None, true), CIStatus::Red);
    }

    #[test]
    fn test_warm_anomalous_red() {
        let ci = make_test_ci(1000000);
        // Warm, but amount is 10x mean (anomalous)
        assert_eq!(evaluate_ci(&ci, 1003600, 100_000, None, true), CIStatus::Red);
    }

    // ── Matrix tests — STALE ───────────────────────────────────────────

    #[test]
    fn test_stale_high_safe_deep_green() {
        let ci = make_test_ci(1000000);
        // Stale (30000s = 8.3h), High (20), Safe (100x), Deep (3)
        assert_eq!(evaluate_ci(&ci, 1030000, 10_000, None, true), CIStatus::Green);
    }

    #[test]
    fn test_stale_low_any_red() {
        let mut ci = make_test_ci(1000000);
        ci.ark_tx_count_since_k3 = 2; // Low
        assert_eq!(evaluate_ci(&ci, 1030000, 10_000, None, true), CIStatus::Red);
    }

    // ── Matrix tests — COLD ────────────────────────────────────────────

    #[test]
    fn test_cold_high_safe_deep_yellow() {
        let ci = make_test_ci(1000000);
        // Cold (100000s = 27h), High (20), Safe (100x), Deep (3) → YELLOW (not GREEN)
        assert_eq!(evaluate_ci(&ci, 1100000, 10_000, None, true), CIStatus::Yellow);
    }

    #[test]
    fn test_cold_medium_moderate_red() {
        let mut ci = make_test_ci(1000000);
        ci.ark_tx_count_since_k3 = 10; // Medium
        ci.k3_balance = 50_000; // Moderate (5x)
        assert_eq!(evaluate_ci(&ci, 1100000, 10_000, None, true), CIStatus::Red);
    }

    // ── Settlement modifier tests ──────────────────────────────────────

    #[test]
    fn test_shallow_downgrades_green_to_yellow() {
        let mut ci = make_test_ci(1000000);
        ci.ark_validator_count = 2; // Shallow
        // Would be GREEN (Fresh + Safe), but Shallow downgrades
        assert_eq!(evaluate_ci(&ci, 1000100, 10_000, None, true), CIStatus::Yellow);
    }

    #[test]
    fn test_unknown_ecosystem_yellow_floor() {
        let mut ci = make_test_ci(1000000);
        ci.ark_validator_count = 0; // Unknown
        // Fresh + Safe would be GREEN, but Unknown → YELLOW floor
        // BUT: Unknown + significant amount → RED override
        // Use small amount to avoid override
        ci.ark_tx_mean_amount = 100_000;
        assert_eq!(evaluate_ci(&ci, 1000100, 10_000, None, true), CIStatus::Yellow);
    }

    // ── Artifact tests ─────────────────────────────────────────────────

    #[test]
    fn test_artifact_hash_deterministic() {
        let a = make_test_artifact(1, None);
        assert_eq!(compute_artifact_hash(&a), compute_artifact_hash(&a));
    }

    #[test]
    fn test_artifact_hash_differs_on_nonce() {
        let a1 = make_test_artifact(1, None);
        let a2 = make_test_artifact(2, None);
        assert_ne!(compute_artifact_hash(&a1), compute_artifact_hash(&a2));
    }

    #[test]
    fn test_verify_artifact_valid() {
        let a = make_test_artifact(1, None);
        assert!(verify_artifact_structure(&a, None).is_ok());
    }

    #[test]
    fn test_verify_artifact_zero_amount() {
        let mut a = make_test_artifact(1, None);
        a.transaction.amount = 0;
        assert_eq!(verify_artifact_structure(&a, None), Err(ArkError::ZeroAmount));
    }

    #[test]
    fn test_verify_artifact_chain() {
        let a1 = make_test_artifact(1, None);
        let h = compute_artifact_hash(&a1);
        let a2 = make_test_artifact(2, Some(h));
        assert!(verify_artifact_structure(&a2, Some(&a1)).is_ok());
    }

    #[test]
    fn test_verify_artifact_nonce_too_low() {
        let a1 = make_test_artifact(5, None);
        let h = compute_artifact_hash(&a1);
        let a2 = make_test_artifact(3, Some(h));
        assert_eq!(verify_artifact_structure(&a2, Some(&a1)), Err(ArkError::NonceTooLow));
    }

    /// Exhaustive enumeration over the FULL `evaluate_ci` input grid — the
    /// "catch everything" check for a pure decision function (more complete
    /// than a model check: every reachable state is actually evaluated).
    /// Locked invariants (paper3 v0.18 §6 / YPX-010):
    ///   (i)   scar / no-k=3-ever / underwater stakes  ⇒ RED, always
    ///   (ii)  receiver-live ∧ sender-stale (> Δ)      ⇒ RED, always (the L clamp)
    ///   (iii) `sender_nabla_healthy = false` never scores HIGHER than the
    ///         identical inputs with `true` (monotone tighten-only)
    ///   (iv)  `sender_nabla_healthy = false`          ⇒ never GREEN
    #[test]
    fn evaluate_ci_exhaustive_grid_invariants() {
        const AMOUNT: u64 = 10_000;
        const LAST_K3: u64 = 1_000_000;
        fn rank(s: CIStatus) -> u8 {
            match s { CIStatus::Green => 0, CIStatus::Yellow => 1, CIStatus::Red => 2 }
        }

        // One representative elapsed per staleness band (0 = Fresh; each
        // band constant is the inclusive lower edge of the next band).
        let elapsed_grid = [0, STALENESS_FRESH_SECS, STALENESS_WARM_SECS, STALENESS_STALE_SECS];
        // One balance per stakes level vs AMOUNT: 20x / 5x / 1.5x / 0.5x.
        let balance_grid = [200_000u64, 50_000, 15_000, 5_000];
        let tx_count_grid = [0u64, 2, 10, 20];          // None / Low / Medium / High
        let ecosystem_grid = [0u8, 1, 3];               // Unknown / Shallow / Deep
        let mean_grid = [0u64, 3_000, 10_000];          // no-history / anomalous / typical

        let mut states = 0u64;
        for &elapsed in &elapsed_grid {
            let now = LAST_K3 + elapsed;
            for &k3_balance in &balance_grid {
                for &tx_count in &tx_count_grid {
                    for &eco in &ecosystem_grid {
                        for &mean in &mean_grid {
                            for &scar in &[false, true] {
                                for &any_k3 in &[false, true] {
                                    for &conflicts in &[0u64, 1] {
                                        for &live in &[None, Some(now)] {
                                            let ci = ConfidenceIndex {
                                                wallet_pk: vec![1u8; 32],
                                                last_k3_at: LAST_K3,
                                                ark_tx_count_since_k3: tx_count,
                                                k3_balance,
                                                ark_tx_mean_amount: mean,
                                                ark_validator_count: eco,
                                                has_fact_scar: scar,
                                                has_any_k3: any_k3,
                                                conflict_count: conflicts,
                                                validator_signature: vec![],
                                                issuer_validator_pk: vec![],
                                            };
                                            let healthy = evaluate_ci(&ci, now, AMOUNT, live, true);
                                            let unhealthy = evaluate_ci(&ci, now, AMOUNT, live, false);
                                            states += 2;

                                            // (i) unconditional overrides ⇒ RED regardless of health
                                            let underwater = compute_stakes_level(k3_balance, AMOUNT)
                                                == StakesLevel::Underwater;
                                            if scar || !any_k3 || underwater {
                                                assert_eq!(healthy, CIStatus::Red,
                                                    "override must be RED: scar={scar} any_k3={any_k3} underwater={underwater}");
                                                assert_eq!(unhealthy, CIStatus::Red);
                                            }

                                            // (ii) the L clamp: receiver-live ∧ stale ⇒ RED,
                                            // for BOTH health values (health never rescues L)
                                            if let Some(t) = live {
                                                if t - LAST_K3 > L_DELTA_SECS {
                                                    assert_eq!(healthy, CIStatus::Red,
                                                        "L clamp must fire: elapsed={elapsed}");
                                                    assert_eq!(unhealthy, CIStatus::Red,
                                                        "unhealthy sender must not rescue the L clamp");
                                                }
                                            }

                                            // (iii) monotone tighten-only
                                            assert!(rank(unhealthy) >= rank(healthy),
                                                "unhealthy scored HIGHER: {unhealthy:?} < {healthy:?} \
                                                 (elapsed={elapsed} bal={k3_balance} tx={tx_count} eco={eco} \
                                                  mean={mean} scar={scar} k3={any_k3} conf={conflicts} live={live:?})");

                                            // (iv) unhealthy sender is never GREEN
                                            assert_ne!(unhealthy, CIStatus::Green,
                                                "unhealthy sender must never score GREEN");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // 4·4·4·3·3·2·2·2·2 grid × 2 health values = 18,432 evaluated states.
        assert_eq!(states, 18_432, "grid changed — update the expected state count");
    }
}
