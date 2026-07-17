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

// ── CI evaluation (YPX-010 §3-4) ──────────────────────────────────────────

/// Evaluate the full 5-factor Confidence Index from a CI struct.
///
/// This is the core evaluation function. The receiver computes the CI from
/// the sender's FACT chain, then calls this to get GREEN/YELLOW/RED.
///
/// Core is the law — this function is the sole authority on CI status.
pub fn evaluate_ci(ci: &ConfidenceIndex, current_time: u64, ark_amount: u64) -> CIStatus {
    // === Unconditional overrides (YPX-010 §3) ===

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
    apply_settlement_modifier(base_ci, ecosystem)
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
    use crate::types::Transaction;

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
        assert_eq!(evaluate_ci(&ci, 1000100, 10_000), CIStatus::Red);
    }

    #[test]
    fn test_override_no_k3() {
        let mut ci = make_test_ci(1000000);
        ci.has_any_k3 = false;
        assert_eq!(evaluate_ci(&ci, 1000100, 10_000), CIStatus::Red);
    }

    #[test]
    fn test_override_conflicts() {
        let mut ci = make_test_ci(1000000);
        ci.conflict_count = 1;
        assert_eq!(evaluate_ci(&ci, 1000100, 10_000), CIStatus::Red);
    }

    #[test]
    fn test_override_underwater() {
        let mut ci = make_test_ci(1000000);
        ci.k3_balance = 5_000; // less than ark_amount
        assert_eq!(evaluate_ci(&ci, 1000100, 10_000), CIStatus::Red);
    }

    // ── Matrix tests — FRESH ───────────────────────────────────────────

    #[test]
    fn test_fresh_safe_deep_green() {
        let ci = make_test_ci(1000000);
        // Fresh (100s ago), Safe (100x), Deep (3 validators)
        assert_eq!(evaluate_ci(&ci, 1000100, 10_000), CIStatus::Green);
    }

    #[test]
    fn test_fresh_thin_yellow() {
        let mut ci = make_test_ci(1000000);
        ci.k3_balance = 15_000; // Thin (1.5x)
        assert_eq!(evaluate_ci(&ci, 1000100, 10_000), CIStatus::Yellow);
    }

    // ── Matrix tests — WARM ────────────────────────────────────────────

    #[test]
    fn test_warm_high_safe_deep_green() {
        let ci = make_test_ci(1000000);
        // Warm (3600s = 1h), High (20 TXs), Safe (100x), Deep (3)
        assert_eq!(evaluate_ci(&ci, 1003600, 10_000), CIStatus::Green);
    }

    #[test]
    fn test_warm_none_thin_red() {
        let mut ci = make_test_ci(1000000);
        ci.ark_tx_count_since_k3 = 0;
        ci.k3_balance = 15_000; // Thin
        assert_eq!(evaluate_ci(&ci, 1003600, 10_000), CIStatus::Red);
    }

    #[test]
    fn test_warm_anomalous_red() {
        let ci = make_test_ci(1000000);
        // Warm, but amount is 10x mean (anomalous)
        assert_eq!(evaluate_ci(&ci, 1003600, 100_000), CIStatus::Red);
    }

    // ── Matrix tests — STALE ───────────────────────────────────────────

    #[test]
    fn test_stale_high_safe_deep_green() {
        let ci = make_test_ci(1000000);
        // Stale (30000s = 8.3h), High (20), Safe (100x), Deep (3)
        assert_eq!(evaluate_ci(&ci, 1030000, 10_000), CIStatus::Green);
    }

    #[test]
    fn test_stale_low_any_red() {
        let mut ci = make_test_ci(1000000);
        ci.ark_tx_count_since_k3 = 2; // Low
        assert_eq!(evaluate_ci(&ci, 1030000, 10_000), CIStatus::Red);
    }

    // ── Matrix tests — COLD ────────────────────────────────────────────

    #[test]
    fn test_cold_high_safe_deep_yellow() {
        let ci = make_test_ci(1000000);
        // Cold (100000s = 27h), High (20), Safe (100x), Deep (3) → YELLOW (not GREEN)
        assert_eq!(evaluate_ci(&ci, 1100000, 10_000), CIStatus::Yellow);
    }

    #[test]
    fn test_cold_medium_moderate_red() {
        let mut ci = make_test_ci(1000000);
        ci.ark_tx_count_since_k3 = 10; // Medium
        ci.k3_balance = 50_000; // Moderate (5x)
        assert_eq!(evaluate_ci(&ci, 1100000, 10_000), CIStatus::Red);
    }

    // ── Settlement modifier tests ──────────────────────────────────────

    #[test]
    fn test_shallow_downgrades_green_to_yellow() {
        let mut ci = make_test_ci(1000000);
        ci.ark_validator_count = 2; // Shallow
        // Would be GREEN (Fresh + Safe), but Shallow downgrades
        assert_eq!(evaluate_ci(&ci, 1000100, 10_000), CIStatus::Yellow);
    }

    #[test]
    fn test_unknown_ecosystem_yellow_floor() {
        let mut ci = make_test_ci(1000000);
        ci.ark_validator_count = 0; // Unknown
        // Fresh + Safe would be GREEN, but Unknown → YELLOW floor
        // BUT: Unknown + significant amount → RED override
        // Use small amount to avoid override
        ci.ark_tx_mean_amount = 100_000;
        assert_eq!(evaluate_ci(&ci, 1000100, 10_000), CIStatus::Yellow);
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
}
