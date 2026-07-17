// AXIOM Core — Oracle Distribution System
// Reference: AXIOM_GUIDE_Nabla.md Section 11, Phase 7
//
// Oracle distribution is how AXIOM's Market Reserve Pool of 88,000,000 AXC
// enters circulation. Contributors earn AXC by doing verified citizen
// science work on 11 whitelisted platforms.
//
// Oracle claims flow through the standard CL1-CL5 TX pipeline with k=5
// witnesses. Platform identity is verified via the Living Signature
// mechanism (AXM_<hex16> in username). No ZK-TLS is used.
//
// ZK-TLS integration is deferred. See docs/ORACLE_FUTURE_ZKTLS.md for
// the rationale and integration path when a suitable library is available.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

// ── Constants ──

/// Total AXC in the oracle reserve (= Market Allocation from White Paper §2.10).
/// When exhausted, oracle stops permanently.
pub const TOTAL_RESERVE: u64 = 88_000_000;

/// Daily emission across all platforms (AXC/day).
/// 88,000,000 / 3,650 days = 24,109 AXC/day (~10 year drain).
pub const DAILY_EMISSION: u64 = 24_109;

/// Minimum interval between claims per user per platform (in ticks).
/// 24 hours at 5-second ticks = 17,280 ticks.
pub const CLAIM_INTERVAL_TICKS: u64 = crate::validation::protocol_gen::CLAIM_INTERVAL_TICKS;

/// Number of whitelisted platforms.
pub const PLATFORM_COUNT: usize = 11;

// ── Task 53: Platform Whitelist ──

/// Platform category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformType {
    /// BOINC credits, F@H points — CPU/GPU hours.
    Compute,
    /// Zooniverse, iNaturalist — human classifications.
    Classification,
    /// OSM edits, Wikipedia edits — human knowledge work.
    Mapping,
}

/// A whitelisted citizen science platform.
#[derive(Debug, Clone)]
pub struct WhitelistEntry {
    /// Canonical project URL (must match exactly).
    pub project_url: &'static str,
    /// Weight percentage (integer, all sum to 100).
    pub weight_pct: u8,
        /// Platform units per 1 AXC.
    /// Rates are protocol constants baked into the Core ELF — deterministic and
    /// stateless. Core enforces both rates AND the 5 AXC/claim cap. Lambda uses
    /// its own configurable rates for display/payout computation, but Core's
    /// rates are authoritative. See YPX-012 §6.3.
    pub conversion_rate: u64,
    /// Platform category.
    pub platform_type: PlatformType,
}

/// The hardcoded whitelist. Immutable. Changing requires Yellow Paper upgrade.
pub const WHITELIST: [WhitelistEntry; PLATFORM_COUNT] = [
    // Compute platforms (64% total)
    WhitelistEntry { project_url: "https://foldingathome.org",          weight_pct: 10, conversion_rate: 10_000, platform_type: PlatformType::Compute },
    WhitelistEntry { project_url: "https://einstein.phys.uwm.edu",     weight_pct: 10, conversion_rate: 8_000,  platform_type: PlatformType::Compute },
    WhitelistEntry { project_url: "https://boinc.bakerlab.org",        weight_pct: 10, conversion_rate: 8_000,  platform_type: PlatformType::Compute },  // Rosetta@home
    WhitelistEntry { project_url: "https://lhcathome.cern.ch",         weight_pct: 9,  conversion_rate: 8_000,  platform_type: PlatformType::Compute },
    WhitelistEntry { project_url: "https://milkyway.cs.rpi.edu",       weight_pct: 9,  conversion_rate: 8_000,  platform_type: PlatformType::Compute },
    WhitelistEntry { project_url: "https://universeathome.pl",         weight_pct: 9,  conversion_rate: 8_000,  platform_type: PlatformType::Compute },
    WhitelistEntry { project_url: "https://www.worldcommunitygrid.org", weight_pct: 7, conversion_rate: 8_000,  platform_type: PlatformType::Compute },

    // Human classification platforms (18% total)
    WhitelistEntry { project_url: "https://www.zooniverse.org",        weight_pct: 9,  conversion_rate: 2,      platform_type: PlatformType::Classification },
    WhitelistEntry { project_url: "https://www.inaturalist.org",       weight_pct: 9,  conversion_rate: 20,     platform_type: PlatformType::Classification },

    // Mapping and knowledge platforms (18% total)
    WhitelistEntry { project_url: "https://www.openstreetmap.org",     weight_pct: 10, conversion_rate: 3,      platform_type: PlatformType::Mapping },
    WhitelistEntry { project_url: "https://www.wikipedia.org",         weight_pct: 8,  conversion_rate: 5,      platform_type: PlatformType::Mapping },
];

/// Look up a platform by URL. Returns (index, entry) or None.
pub fn whitelist_lookup(url: &str) -> Option<(usize, &'static WhitelistEntry)> {
    WHITELIST.iter().enumerate().find(|(_, e)| e.project_url == url)
}

// ── Task 52: OracleClaim Transaction Type ──

/// An oracle claim transaction. Submitted by a contributor, processed by Core.
#[derive(Debug, Clone)]
pub struct OracleClaim {
    /// Must match a whitelist entry exactly.
    pub project_url: String,
    /// Platform's immutable numeric user ID.
    pub user_id: u64,
    /// Platform username — must contain Living Signature (AXM_Base32(address)).
    pub username: String,
    /// Current total credits/points from platform.
    pub credit_total: u64,
    /// New work since last claim (credit_total - last_claimed_balance).
    pub credit_delta: u64,
    /// ZK-TLS proof blob.
    pub proof: Vec<u8>,
    /// Claimer's AXIOM wallet address.
    pub claimer_address: [u8; 32],
    /// Claimer's wallet_id (e.g., "alice@axiom.local/a3f7b232").
    /// Used for Living Signature verification.
    pub wallet_id: String,
    /// Tick at which this claim was submitted.
    pub claim_tick: u64,
}

// ── Task 55: Living Signature ──

/// Compute a Living Signature from a wallet_id.
/// Format: AXM_ + BLAKE3("AXIOM_LIVING_SIG" || wallet_id)[0..8].hex()
///
/// The contributor must set their platform username to contain this string.
/// This proves ownership of the wallet — only the wallet owner knows their
/// wallet_id (which includes email + salt + MASTER_PK in the checksum).
/// The BLAKE3 hash is not reversible — the wallet_id cannot be derived from it.
///
/// At claim time, Core recomputes: BLAKE3("AXIOM_LIVING_SIG" || sender_wallet_id)
/// and checks the username contains the result. Since sender_wallet_id is
/// authenticated by the TX signature, only the wallet owner can produce this.
pub fn living_signature(wallet_id: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_LIVING_SIG");
    hasher.update(wallet_id.as_bytes());
    let hash = hasher.finalize();
    let hex: String = hash.as_bytes()[..8].iter().map(|b| format!("{:02x}", b)).collect();
    format!("AXM_{}", hex)
}

/// Check if a username contains the Living Signature for the given wallet_id.
pub fn verify_living_signature(username: &str, wallet_id: &str) -> bool {
    let sig = living_signature(wallet_id);
    username.contains(&*sig)
}

// ── Task 56: Oracle Binding ──

/// Permanent binding between a platform identity and an AXIOM address.
/// Created on first claim. Immutable forever after.
#[derive(Debug, Clone)]
pub struct OracleBinding {
    /// Platform URL.
    pub project_url: String,
    /// Platform's immutable numeric user ID.
    pub user_id: u64,
    /// Bound AXIOM wallet address.
    pub axiom_address: [u8; 32],
    /// Tick when binding was created.
    pub first_claim_tick: u64,
    /// Credit total at last successful claim (Task 58).
    pub last_claimed_balance: u64,
    /// Tick of last successful claim (Task 63: 24-hour enforcement).
    pub last_claim_tick: u64,
}

/// Binding key: (project_url, user_id) — uniquely identifies a binding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BindingKey {
    pub project_url: String,
    pub user_id: u64,
}

impl BindingKey {
    pub fn new(project_url: &str, user_id: u64) -> Self {
        Self {
            project_url: String::from(project_url),
            user_id,
        }
    }
}

// ── Task 56-57: Binding Table ──

/// The binding table. Stores all (project_url + user_id) → axiom_address bindings.
pub struct BindingTable {
    bindings: BTreeMap<BindingKey, OracleBinding>,
}

impl Default for BindingTable {
    fn default() -> Self {
        Self::new()
    }
}

impl BindingTable {
    pub fn new() -> Self {
        Self {
            bindings: BTreeMap::new(),
        }
    }

    /// Look up an existing binding.
    pub fn get(&self, key: &BindingKey) -> Option<&OracleBinding> {
        self.bindings.get(key)
    }

    /// Look up a mutable binding (for updating last_claimed_balance).
    pub fn get_mut(&mut self, key: &BindingKey) -> Option<&mut OracleBinding> {
        self.bindings.get_mut(key)
    }

    /// Create a new binding. Fails if one already exists (immutability).
    pub fn create(
        &mut self,
        project_url: &str,
        user_id: u64,
        axiom_address: [u8; 32],
        tick: u64,
    ) -> Result<(), OracleError> {
        let key = BindingKey::new(project_url, user_id);
        if self.bindings.contains_key(&key) {
            return Err(OracleError::BindingAlreadyExists);
        }
        self.bindings.insert(
            key,
            OracleBinding {
                project_url: String::from(project_url),
                user_id,
                axiom_address,
                first_claim_tick: tick,
                last_claimed_balance: 0,
                last_claim_tick: 0,
            },
        );
        Ok(())
    }

    /// Number of bindings.
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }
}

// ── Task 60: Daily Pool State ──

/// Daily pool state per platform.
#[derive(Debug, Clone)]
pub struct DailyPoolState {
    /// Current UTC date string ("2027-03-15").
    pub date: String,
    /// Remaining AXC per platform today (indexed by whitelist position).
    pub pools: [u64; PLATFORM_COUNT],
    /// Total AXC remaining in reserve.
    pub reserve_left: u64,
    /// Number of claims processed today.
    pub claims_today: u64,
    /// TARDIS tick of last midnight reset.
    pub last_reset_tick: u64,
}

impl DailyPoolState {
    /// Initialize with full daily allocation.
    pub fn new(date: &str, reserve_left: u64, tick: u64) -> Self {
        let mut pools = [0u64; PLATFORM_COUNT];
        for (i, entry) in WHITELIST.iter().enumerate() {
            pools[i] = DAILY_EMISSION * entry.weight_pct as u64 / 100;
        }
        Self {
            date: String::from(date),
            pools,
            reserve_left,
            claims_today: 0,
            last_reset_tick: tick,
        }
    }

    /// Remaining AXC in a specific platform's pool today.
    pub fn platform_remaining(&self, platform_index: usize) -> u64 {
        if platform_index < PLATFORM_COUNT {
            self.pools[platform_index]
        } else {
            0
        }
    }

    /// Deduct AXC from a platform's daily pool.
    /// Returns the actual amount deducted (may be less if pool nearly empty).
    pub fn deduct(&mut self, platform_index: usize, amount: u64) -> u64 {
        if platform_index >= PLATFORM_COUNT {
            return 0;
        }
        let available = self.pools[platform_index];
        let actual = amount.min(available);
        self.pools[platform_index] -= actual;
        self.reserve_left = self.reserve_left.saturating_sub(actual);
        self.claims_today += 1;
        actual
    }

    /// Total remaining across all platforms today.
    pub fn total_remaining_today(&self) -> u64 {
        self.pools.iter().sum()
    }

    /// Reset for a new day. Refills all platform pools from daily emission.
    /// Does NOT reset reserve_left (only daily pools reset).
    pub fn reset_day(&mut self, new_date: &str, tick: u64) {
        self.date = String::from(new_date);
        for (i, entry) in WHITELIST.iter().enumerate() {
            self.pools[i] = DAILY_EMISSION * entry.weight_pct as u64 / 100;
        }
        self.claims_today = 0;
        self.last_reset_tick = tick;
    }
}

// ── Task 62: Reserve Counter ──

/// Reserve counter — tracks total AXC distributed from the oracle reserve.
/// When total_distributed reaches TOTAL_RESERVE, oracle stops permanently.
#[derive(Debug, Clone)]
pub struct ReserveCounter {
    /// Total AXC distributed from reserve since genesis.
    pub total_distributed: u64,
}

impl Default for ReserveCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl ReserveCounter {
    pub fn new() -> Self {
        Self {
            total_distributed: 0,
        }
    }

    /// Remaining AXC in reserve.
    pub fn remaining(&self) -> u64 {
        TOTAL_RESERVE.saturating_sub(self.total_distributed)
    }

    /// Is the reserve exhausted?
    pub fn is_exhausted(&self) -> bool {
        self.total_distributed >= TOTAL_RESERVE
    }

    /// Record a distribution. Returns error if reserve would be exceeded.
    pub fn distribute(&mut self, amount: u64) -> Result<(), OracleError> {
        if self.total_distributed + amount > TOTAL_RESERVE {
            return Err(OracleError::ReserveExhausted);
        }
        self.total_distributed += amount;
        Ok(())
    }
}

// ── Errors ──

/// Oracle distribution errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleError {
    /// Project URL not in whitelist.
    PlatformNotWhitelisted,
    /// ZK-TLS proof verification failed (legacy single-step flow).
    InvalidProof,
    /// Username does not contain Living Signature.
    LivingSignatureMismatch,
    /// (url + user_id) already bound to a different address.
    BindingMismatch,
    /// Attempted to create a binding that already exists.
    BindingAlreadyExists,
    /// credit_delta is zero (no new work).
    ZeroDelta,
    /// credit_delta doesn't match (credit_total - last_claimed_balance).
    DeltaMismatch,
    /// Platform's daily pool has no remaining AXC.
    DailyPoolExhausted,
    /// Total reserve is exhausted. Oracle is permanently stopped.
    ReserveExhausted,
    /// 24-hour interval not elapsed since last claim.
    ClaimTooSoon,
    /// Oracle TX sender must equal receiver (self-payout only).
    OracleSenderReceiverMismatch,
    /// Oracle TX requires k=5 witnesses with >= 1M AXC stake each.
    OracleInsufficientWitnesses,
    /// Oracle cheque maturity not reached (48h).
    OracleMaturityNotReached,
    /// Oracle re-verification failed (credits don't match at redeem time).
    OracleReverifyFailed,
}

// ── LEGACY: ZK-TLS Verification (NOT USED IN PRODUCTION) ──
//
// This function is from the original oracle design where ZK-TLS would verify
// ZK-TLS verification has been removed. Oracle uses the CL1-CL5 TX pipeline
// with Living Signature verification. See docs/ORACLE_FUTURE_ZKTLS.md.

// ── Task 59: Credit Delta Computation ──

/// Compute AXC payout from credit delta and conversion rate.
/// AXC = credit_delta / conversion_rate (integer division, floor).
pub fn compute_axc_payout(credit_delta: u64, conversion_rate: u64) -> u64 {
    if conversion_rate == 0 {
        return 0;
    }
    credit_delta / conversion_rate
}

// ════════════════════════════════════════════════════════════════════════
// Oracle as Transaction — CL1-CL5 Pipeline
//
// Oracle claims flow through the SAME pipeline as regular transactions:
//   - k=5 witnesses (not k=3) — higher stake requirement
//   - Each witness must have >= 1M AXC stake (NablaStakeProof)
//   - Each witness independently queries the platform API
//   - Witness produces a cheque (same as any TX)
//   - Client redeems cheques after 48h maturity
//   - Redeeming validator re-queries platform to verify credits
//
// Security: same as every TX — validators stake their own AXC.
// 5M AXC at risk for max 5 AXC/claim. Attack is economically irrational.
//
// Core enforces:
//   - sender == receiver (self-payout only, like Ark Rule 1)
//   - k=5 minimum (via receiver address YPX-007 tier)
//   - 48h cheque maturity (checked at CL5 redeem)
//   - Payout cap: 5 AXC per claim (ORACLE_MAX_PAYOUT_PER_CLAIM)
//   - 24h claim interval per binding
// ════════════════════════════════════════════════════════════════════════

/// Oracle requires k=5 witnesses (higher than standard k=3).
pub const ORACLE_K: usize = 5;

/// Minimum stake for oracle witnesses (1M AXC).
pub const ORACLE_MIN_STAKE: u64 = 1_000_000;

/// Oracle cheque maturity — 48h in 5-second ticks (must wait before redeem).
pub const ORACLE_MATURITY_TICKS: u64 = crate::validation::protocol_gen::ORACLE_MATURITY_TICKS;

/// Recommended VBC renewal interval for oracle validators — 24 hours in ticks.
/// Operators enabling oracle processing should configure Lambda to auto-renew
/// their VBC via CL8 on this schedule. This is an operator responsibility,
/// not a Core-enforced rule — see protocol_core.toml [oracle] section.
/// 17_280 ticks × 5 sec/tick = 86_400 sec = 24 hours.
/// Reference: YPX-012 §2.5, Yellow Paper §25.5.4
pub const ORACLE_VBC_RENEWAL_TICKS: u64 = crate::validation::protocol_gen::ORACLE_VBC_RENEWAL_TICKS;

/// Max AXC payout per claim.
/// SECURITY-ORACLE: Oracle payout cap — hard ceiling prevents oracle drain attacks.
/// Both rates and cap are Core protocol constants (deterministic, stateless).
pub const ORACLE_MAX_PAYOUT_PER_CLAIM: u64 = 5;

/// Validate an oracle claim as a transaction.
/// Called during CL1/CL2 validation when tx_type indicates oracle claim.
/// Checks: sender == receiver, platform whitelisted, living signature valid.
pub fn validate_oracle_tx(
    sender_wallet_id: &str,
    receiver_wallet_id: &str,
    project_url: &str,
    username: &str,
) -> Result<(), OracleError> {
    // Rule: sender must equal receiver (self-payout only)
    if sender_wallet_id != receiver_wallet_id {
        return Err(OracleError::OracleSenderReceiverMismatch);
    }

    // Platform must be whitelisted
    whitelist_lookup(project_url).ok_or(OracleError::PlatformNotWhitelisted)?;

    // Living Signature must be in username (derived from wallet_id, not pk)
    if !verify_living_signature(username, sender_wallet_id) {
        return Err(OracleError::LivingSignatureMismatch);
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════════════
// Legacy business logic — used by process_oracle_claim_inner for
// binding management, pool deduction, and payout computation.
// These functions are reused at CL5 redeem time for oracle cheques.
// ════════════════════════════════════════════════════════════════════════

// ── Business logic (binding, pool, payout) ──

/// Result of a successful oracle claim.
#[derive(Debug, Clone)]
pub struct ClaimResult {
    /// AXC awarded to the claimer.
    pub axc_awarded: u64,
    /// Platform index in whitelist.
    pub platform_index: usize,
    /// Whether a new binding was created.
    pub new_binding: bool,
}

/// Validate and process an OracleClaim transaction.
///
/// Core performs six checks (all must pass):
///   1. ZK-TLS valid?
///   2. URL whitelisted?
///   3. Living Signature match?
///   4. User ID binding valid?
///   5. Credit delta > 0 and matches?
///   6. Daily pool has balance?
///
/// Plus: reserve not exhausted, 24-hour interval respected.
pub fn process_oracle_claim(
    claim: &OracleClaim,
    bindings: &mut BindingTable,
    pool: &mut DailyPoolState,
    reserve: &mut ReserveCounter,
) -> Result<ClaimResult, OracleError> {
    // 0. Reserve check (fail fast)
    if reserve.is_exhausted() {
        return Err(OracleError::ReserveExhausted);
    }

    // ZK-TLS gate removed — oracle uses CL1-CL5 TX pipeline with Living
    // Signature verification. See docs/ORACLE_FUTURE_ZKTLS.md.

    // Steps 2-11: business logic (binding, pool, payout)
    process_oracle_claim_inner(claim, bindings, pool, reserve)
}

/// Internal business logic for oracle claims (steps 2-11).
fn process_oracle_claim_inner(
    claim: &OracleClaim,
    bindings: &mut BindingTable,
    pool: &mut DailyPoolState,
    reserve: &mut ReserveCounter,
) -> Result<ClaimResult, OracleError> {
    // 2. URL whitelisted?
    let (platform_idx, entry) = whitelist_lookup(&claim.project_url)
        .ok_or(OracleError::PlatformNotWhitelisted)?;

    // 3. Living Signature match?
    if !verify_living_signature(&claim.username, &claim.wallet_id) {
        return Err(OracleError::LivingSignatureMismatch);
    }

    // 4. User ID binding
    let key = BindingKey::new(&claim.project_url, claim.user_id);
    let new_binding;
    let last_balance;
    let last_tick;

    match bindings.get(&key) {
        Some(existing) => {
            // Binding exists — must match claimer's address
            if existing.axiom_address != claim.claimer_address {
                return Err(OracleError::BindingMismatch);
            }
            last_balance = existing.last_claimed_balance;
            last_tick = existing.last_claim_tick;
            new_binding = false;
        }
        None => {
            // First claim — create binding
            bindings.create(
                &claim.project_url,
                claim.user_id,
                claim.claimer_address,
                claim.claim_tick,
            )?;
            last_balance = 0;
            last_tick = 0;
            new_binding = true;
        }
    }

    // 5a. Credit delta > 0?
    if claim.credit_delta == 0 {
        return Err(OracleError::ZeroDelta);
    }

    // 5b. Credit delta matches?
    let expected_delta = claim.credit_total.saturating_sub(last_balance);
    if claim.credit_delta != expected_delta {
        return Err(OracleError::DeltaMismatch);
    }

    // 6. 24-hour interval (Task 63)
    // Skip for first claim (last_tick == 0)
    if last_tick > 0 && claim.claim_tick < last_tick + CLAIM_INTERVAL_TICKS {
        return Err(OracleError::ClaimTooSoon);
    }

    // 7. Compute AXC payout
    let axc_amount = compute_axc_payout(claim.credit_delta, entry.conversion_rate);
    if axc_amount == 0 {
        return Err(OracleError::ZeroDelta);
    }

    // 8. Daily pool check (Task 61)
    let pool_remaining = pool.platform_remaining(platform_idx);
    if pool_remaining == 0 {
        return Err(OracleError::DailyPoolExhausted);
    }

    // Cap payout at pool remaining
    let actual_payout = axc_amount.min(pool_remaining);

    // 9. Reserve check
    reserve.distribute(actual_payout)?;

    // 10. Deduct from daily pool
    pool.deduct(platform_idx, actual_payout);

    // 11. Update binding
    if let Some(binding) = bindings.get_mut(&key) {
        binding.last_claimed_balance = claim.credit_total;
        binding.last_claim_tick = claim.claim_tick;
    }

    Ok(ClaimResult {
        axc_awarded: actual_payout,
        platform_index: platform_idx,
        new_binding,
    })
}

// ══════════════════════════════════════════════════════════════════════
// Tests — Task 64
// ══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn test_wallet_id(b: u8) -> String {
        format!("user{}@test.com/{:02x}{:02x}{:02x}{:02x}", b, b, b, b, b)
    }

    fn make_claim(
        url: &str,
        user_id: u64,
        address: [u8; 32],
        credit_total: u64,
        credit_delta: u64,
        tick: u64,
    ) -> OracleClaim {
        let wid = test_wallet_id(address[0]);
        let sig = living_signature(&wid);
        OracleClaim {
            project_url: String::from(url),
            user_id,
            username: format!("user_{}", sig),
            credit_total,
            credit_delta,
            proof: vec![0x01],
            claimer_address: address,
            wallet_id: wid,
            claim_tick: tick,
        }
    }

    fn fresh_state() -> (BindingTable, DailyPoolState, ReserveCounter) {
        let bindings = BindingTable::new();
        let pool = DailyPoolState::new("2027-03-15", TOTAL_RESERVE, 0);
        let reserve = ReserveCounter::new();
        (bindings, pool, reserve)
    }

    // ── Whitelist Tests ──

    #[test]
    fn whitelist_weights_sum_to_100() {
        let total: u8 = WHITELIST.iter().map(|e| e.weight_pct).sum();
        assert_eq!(total, 100);
    }

    #[test]
    fn whitelist_lookup_valid() {
        let result = whitelist_lookup("https://foldingathome.org");
        assert!(result.is_some());
        let (idx, entry) = result.unwrap();
        assert_eq!(idx, 0);
        assert_eq!(entry.weight_pct, 10);
    }

    #[test]
    fn whitelist_lookup_invalid() {
        assert!(whitelist_lookup("https://notaplatform.com").is_none());
    }

    #[test]
    fn whitelist_has_11_entries() {
        assert_eq!(WHITELIST.len(), 11);
    }

    // ── Living Signature Tests ──

    #[test]
    fn living_signature_format() {
        let wid = "alice@axiom.local/a3f7b232";
        let sig = living_signature(wid);
        assert!(sig.starts_with("AXM_"));
        assert_eq!(sig.len(), 4 + 16); // AXM_ + 16 hex chars
    }

    #[test]
    fn living_signature_deterministic() {
        let wid = "bob@test.com/12345678";
        assert_eq!(living_signature(wid), living_signature(wid));
    }

    #[test]
    fn living_signature_different_wallets_differ() {
        let sig_a = living_signature("alice@test.com/aabbccdd");
        let sig_b = living_signature("bob@test.com/11223344");
        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn living_signature_verify_pass() {
        let wid = "alice@axiom.local/a3f7b232";
        let sig = living_signature(wid);
        let username = format!("my_science_account_{}", sig);
        assert!(verify_living_signature(&username, wid));
    }

    #[test]
    fn living_signature_verify_fail() {
        let wid_a = "alice@test.com/aabbccdd";
        let wid_b = "bob@test.com/11223344";
        let sig = living_signature(wid_a);
        let username = format!("user_{}", sig);
        // Username has Alice's signature, but we check against Bob's wallet
        assert!(!verify_living_signature(&username, wid_b));
    }

    // ── Daily Pool Tests ──

    #[test]
    fn daily_pool_initial_allocation() {
        let pool = DailyPoolState::new("2027-03-15", TOTAL_RESERVE, 0);
        // Folding@home: 10% of 24,109 = 2,410
        assert_eq!(pool.pools[0], 2410);
        // Total should approximate DAILY_EMISSION (rounding from integer division)
        let total: u64 = pool.pools.iter().sum();
        assert!(total <= DAILY_EMISSION);
        assert!(total >= DAILY_EMISSION - PLATFORM_COUNT as u64);
    }

    #[test]
    fn daily_pool_deduct() {
        let mut pool = DailyPoolState::new("2027-03-15", TOTAL_RESERVE, 0);
        let before = pool.pools[0];
        let deducted = pool.deduct(0, 100);
        assert_eq!(deducted, 100);
        assert_eq!(pool.pools[0], before - 100);
        assert_eq!(pool.claims_today, 1);
    }

    #[test]
    fn daily_pool_deduct_capped() {
        let mut pool = DailyPoolState::new("2027-03-15", TOTAL_RESERVE, 0);
        let available = pool.pools[0];
        let deducted = pool.deduct(0, available + 1000);
        assert_eq!(deducted, available);
        assert_eq!(pool.pools[0], 0);
    }

    #[test]
    fn daily_pool_reset() {
        let mut pool = DailyPoolState::new("2027-03-15", TOTAL_RESERVE, 0);
        pool.deduct(0, 1000);
        pool.deduct(1, 500);
        assert_eq!(pool.claims_today, 2);

        let reserve_after = pool.reserve_left;
        pool.reset_day("2027-03-16", 17280);

        assert_eq!(&pool.date, "2027-03-16");
        assert_eq!(pool.claims_today, 0);
        assert_eq!(pool.pools[0], 2410);
        assert_eq!(pool.reserve_left, reserve_after);
    }

    // ── Reserve Counter Tests ──

    #[test]
    fn reserve_initial() {
        let reserve = ReserveCounter::new();
        assert_eq!(reserve.remaining(), TOTAL_RESERVE);
        assert!(!reserve.is_exhausted());
    }

    #[test]
    fn reserve_distribute() {
        let mut reserve = ReserveCounter::new();
        reserve.distribute(1000).unwrap();
        assert_eq!(reserve.total_distributed, 1000);
        assert_eq!(reserve.remaining(), TOTAL_RESERVE - 1000);
    }

    #[test]
    fn reserve_exhaustion() {
        let mut reserve = ReserveCounter::new();
        reserve.distribute(TOTAL_RESERVE).unwrap();
        assert!(reserve.is_exhausted());
        assert_eq!(reserve.distribute(1), Err(OracleError::ReserveExhausted));
    }

    // ── Credit Delta Tests ──

    #[test]
    fn compute_payout_basic() {
        assert_eq!(compute_axc_payout(10_000, 10_000), 1);
        assert_eq!(compute_axc_payout(50_000, 10_000), 5);
        assert_eq!(compute_axc_payout(3, 2), 1);
    }

    #[test]
    fn compute_payout_floor() {
        assert_eq!(compute_axc_payout(9_999, 10_000), 0);
    }

    #[test]
    fn compute_payout_zero_rate() {
        assert_eq!(compute_axc_payout(1000, 0), 0);
    }

    // ── Binding Tests ──

    #[test]
    fn binding_create_and_lookup() {
        let mut table = BindingTable::new();
        let addr = test_address(0xAA);
        table.create("https://foldingathome.org", 12345, addr, 100).unwrap();

        let key = BindingKey::new("https://foldingathome.org", 12345);
        let binding = table.get(&key).unwrap();
        assert_eq!(binding.axiom_address, addr);
        assert_eq!(binding.first_claim_tick, 100);
        assert_eq!(binding.last_claimed_balance, 0);
    }

    #[test]
    fn binding_immutable() {
        let mut table = BindingTable::new();
        let addr_a = test_address(0xAA);
        let addr_b = test_address(0xBB);
        table.create("https://foldingathome.org", 12345, addr_a, 100).unwrap();

        let result = table.create("https://foldingathome.org", 12345, addr_b, 200);
        assert_eq!(result, Err(OracleError::BindingAlreadyExists));
    }

    // ── Full Claim Validation Tests (Task 64) ──

    #[test]
    fn valid_first_claim() {
        let (mut bindings, mut pool, mut reserve) = fresh_state();
        let addr = test_address(0xAA);
        let claim = make_claim("https://foldingathome.org", 1, addr, 50_000, 50_000, 100);

        let result = process_oracle_claim_inner(&claim, &mut bindings, &mut pool, &mut reserve).unwrap();
        assert_eq!(result.axc_awarded, 5);
        assert_eq!(result.platform_index, 0);
        assert!(result.new_binding);
    }

    #[test]
    fn valid_second_claim() {
        let (mut bindings, mut pool, mut reserve) = fresh_state();
        let addr = test_address(0xAA);

        let c1 = make_claim("https://foldingathome.org", 1, addr, 50_000, 50_000, 100);
        process_oracle_claim_inner(&c1, &mut bindings, &mut pool, &mut reserve).unwrap();

        let c2 = make_claim("https://foldingathome.org", 1, addr, 100_000, 50_000, 100 + CLAIM_INTERVAL_TICKS);
        let result = process_oracle_claim_inner(&c2, &mut bindings, &mut pool, &mut reserve).unwrap();
        assert_eq!(result.axc_awarded, 5);
        assert!(!result.new_binding);
    }

    #[test]
    fn duplicate_claim_too_soon() {
        let (mut bindings, mut pool, mut reserve) = fresh_state();
        let addr = test_address(0xAA);

        let c1 = make_claim("https://foldingathome.org", 1, addr, 50_000, 50_000, 100);
        process_oracle_claim_inner(&c1, &mut bindings, &mut pool, &mut reserve).unwrap();

        let c2 = make_claim("https://foldingathome.org", 1, addr, 100_000, 50_000, 101);
        let result = process_oracle_claim_inner(&c2, &mut bindings, &mut pool, &mut reserve);
        assert_eq!(result.unwrap_err(), OracleError::ClaimTooSoon);
    }

    #[test]
    fn wrong_binding_different_address() {
        let (mut bindings, mut pool, mut reserve) = fresh_state();
        let alice = test_address(0xAA);
        let bob = test_address(0xBB);

        let c1 = make_claim("https://foldingathome.org", 1, alice, 50_000, 50_000, 100);
        process_oracle_claim_inner(&c1, &mut bindings, &mut pool, &mut reserve).unwrap();

        let c2 = make_claim("https://foldingathome.org", 1, bob, 100_000, 100_000, 200);
        let result = process_oracle_claim_inner(&c2, &mut bindings, &mut pool, &mut reserve);
        assert_eq!(result.unwrap_err(), OracleError::BindingMismatch);
    }

    #[test]
    fn pool_exhausted() {
        let (mut bindings, mut pool, mut reserve) = fresh_state();
        pool.pools[0] = 0;

        let addr = test_address(0xAA);
        let claim = make_claim("https://foldingathome.org", 1, addr, 50_000, 50_000, 100);
        let result = process_oracle_claim_inner(&claim, &mut bindings, &mut pool, &mut reserve);
        assert_eq!(result.unwrap_err(), OracleError::DailyPoolExhausted);
    }

    #[test]
    fn reserve_exhausted_claim() {
        let (mut bindings, mut pool, mut reserve) = fresh_state();
        reserve.total_distributed = TOTAL_RESERVE;

        let addr = test_address(0xAA);
        let claim = make_claim("https://foldingathome.org", 1, addr, 50_000, 50_000, 100);
        let result = process_oracle_claim_inner(&claim, &mut bindings, &mut pool, &mut reserve);
        assert_eq!(result.unwrap_err(), OracleError::ReserveExhausted);
    }

    #[test]
    fn living_signature_mismatch_claim() {
        let (mut bindings, mut pool, mut reserve) = fresh_state();
        let addr = test_address(0xAA);

        let mut claim = make_claim("https://foldingathome.org", 1, addr, 50_000, 50_000, 100);
        claim.username = String::from("wrong_username_no_sig");

        let result = process_oracle_claim_inner(&claim, &mut bindings, &mut pool, &mut reserve);
        assert_eq!(result.unwrap_err(), OracleError::LivingSignatureMismatch);
    }

    #[test]
    fn fake_url_not_whitelisted() {
        let (mut bindings, mut pool, mut reserve) = fresh_state();
        let addr = test_address(0xAA);

        let claim = make_claim("https://fakescience.com", 1, addr, 50_000, 50_000, 100);
        let result = process_oracle_claim_inner(&claim, &mut bindings, &mut pool, &mut reserve);
        assert_eq!(result.unwrap_err(), OracleError::PlatformNotWhitelisted);
    }

    #[test]
    fn delta_zero_rejected() {
        let (mut bindings, mut pool, mut reserve) = fresh_state();
        let addr = test_address(0xAA);

        let claim = make_claim("https://foldingathome.org", 1, addr, 0, 0, 100);
        let result = process_oracle_claim_inner(&claim, &mut bindings, &mut pool, &mut reserve);
        assert_eq!(result.unwrap_err(), OracleError::ZeroDelta);
    }

    #[test]
    fn delta_mismatch_rejected() {
        let (mut bindings, mut pool, mut reserve) = fresh_state();
        let addr = test_address(0xAA);

        let c1 = make_claim("https://foldingathome.org", 1, addr, 50_000, 50_000, 100);
        process_oracle_claim_inner(&c1, &mut bindings, &mut pool, &mut reserve).unwrap();

        let c2 = make_claim("https://foldingathome.org", 1, addr, 100_000, 30_000, 100 + CLAIM_INTERVAL_TICKS);
        let result = process_oracle_claim_inner(&c2, &mut bindings, &mut pool, &mut reserve);
        assert_eq!(result.unwrap_err(), OracleError::DeltaMismatch);
    }

    // invalid_proof_rejected test REMOVED — ZK-TLS proof gate removed in v2.11.13.
    // Oracle uses CL1 TX pipeline with Living Signature. See docs/ORACLE_FUTURE_ZKTLS.md.
    // Oracle claim rejection with enabled=false is tested in Lambda (test_oracle_disabled_rejects_claim).

    #[test]
    fn multi_platform_same_day() {
        let (mut bindings, mut pool, mut reserve) = fresh_state();
        let addr = test_address(0xAA);

        let c1 = make_claim("https://foldingathome.org", 1, addr, 50_000, 50_000, 100);
        let r1 = process_oracle_claim_inner(&c1, &mut bindings, &mut pool, &mut reserve).unwrap();
        assert_eq!(r1.platform_index, 0);

        let c2 = make_claim("https://www.zooniverse.org", 99, addr, 10, 10, 101);
        let r2 = process_oracle_claim_inner(&c2, &mut bindings, &mut pool, &mut reserve).unwrap();
        assert_eq!(r2.platform_index, 7);
        assert_eq!(r2.axc_awarded, 5);
    }

    #[test]
    fn payout_capped_at_pool_remaining() {
        let (mut bindings, mut pool, mut reserve) = fresh_state();
        let addr = test_address(0xAA);

        pool.pools[0] = 2;

        let claim = make_claim("https://foldingathome.org", 1, addr, 50_000, 50_000, 100);
        let result = process_oracle_claim_inner(&claim, &mut bindings, &mut pool, &mut reserve).unwrap();
        assert_eq!(result.axc_awarded, 2);
    }

    #[test]
    fn different_users_same_platform() {
        let (mut bindings, mut pool, mut reserve) = fresh_state();
        let alice = test_address(0xAA);
        let bob = test_address(0xBB);

        let c1 = make_claim("https://foldingathome.org", 1, alice, 50_000, 50_000, 100);
        process_oracle_claim_inner(&c1, &mut bindings, &mut pool, &mut reserve).unwrap();

        let c2 = make_claim("https://foldingathome.org", 2, bob, 30_000, 30_000, 101);
        let result = process_oracle_claim_inner(&c2, &mut bindings, &mut pool, &mut reserve).unwrap();
        assert_eq!(result.axc_awarded, 3);
        assert!(result.new_binding);
    }

    // ── Days Until Reserve Drains ──

    #[test]
    fn reserve_lifetime() {
        // 88,000,000 / 24,109 = 3,650 days (~10.0 years)
        let days = TOTAL_RESERVE / DAILY_EMISSION;
        assert!(days >= 3640, "Reserve should last at least ~9.97 years");
        assert!(days <= 3660, "Reserve should drain within ~10.03 years");
    }

    // ════════════════════════════════════════════════════════════════
    // Oracle TX Validation Tests
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn oracle_tx_sender_must_equal_receiver() {
        let wid = "alice@test.com/aabbccdd";
        let sig = living_signature(wid);
        // Same sender and receiver — passes
        assert!(validate_oracle_tx(
            wid, wid, "https://foldingathome.org",
            &format!("user_{}", sig),
        ).is_ok());

        // Different sender and receiver — rejected
        assert_eq!(
            validate_oracle_tx(
                "alice@test.com/aabbccdd", "bob@test.com/11223344",
                "https://foldingathome.org",
                &format!("user_{}", sig),
            ).unwrap_err(),
            OracleError::OracleSenderReceiverMismatch,
        );
    }

    #[test]
    fn oracle_tx_requires_whitelisted_platform() {
        let wid = "alice@test.com/aabbccdd";
        let sig = living_signature(wid);
        assert_eq!(
            validate_oracle_tx(wid, wid, "https://notaplatform.com",
                &format!("user_{}", sig),
            ).unwrap_err(),
            OracleError::PlatformNotWhitelisted,
        );
    }

    #[test]
    fn oracle_tx_requires_living_signature() {
        let wid = "alice@test.com/aabbccdd";
        assert_eq!(
            validate_oracle_tx(wid, wid, "https://foldingathome.org",
                "user_without_signature",
            ).unwrap_err(),
            OracleError::LivingSignatureMismatch,
        );
    }

    #[test]
    fn oracle_constants_are_sane() {
        assert_eq!(ORACLE_K, 5);
        assert_eq!(ORACLE_MIN_STAKE, 1_000_000);
        assert_eq!(ORACLE_MATURITY_TICKS, 34_560); // 48h at 5s/tick
        assert_eq!(ORACLE_MAX_PAYOUT_PER_CLAIM, 5);
        assert_eq!(ORACLE_VBC_RENEWAL_TICKS, 17_280); // 24h at 5s/tick
    }

}
