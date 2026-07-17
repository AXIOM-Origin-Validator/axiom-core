//! Core data types for AXIOM
//!
//! All types use `#[derive(Serialize, Deserialize)]` for Canonical JSON encoding.

use alloc::boxed::Box;
use alloc::string::String;
// `vec!` macro for the no_std build of the AVM-guest ELF. Used by
// `Transaction::to_canonical_cbor_value` (introduced 9a106c1). Without
// this import the ELF rebuild fails with "cannot find macro `vec` in
// this scope" — the `Vec` type import above doesn't bring the macro
// in, the macro lives in `alloc::vec` (the module).
use alloc::vec;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Burn address — money sent here is permanently destroyed (YPX-001 §1.5.4).
/// Used to resolve scarred FACT links by burning the tainted amount.
pub const BURN_ADDRESS: &str = "BURN/00000000";

/// Deed address — receives the 10-atom Nabla registration payment.
/// Protocol-mandated amount bypasses the dust limit.
///
/// Build-time configurable: set `AXIOM_DEED_ADDRESS` env var before compiling
/// to use a real genesis-derived wallet ID (e.g. from `compute_deed_wallet_id()`).
/// Default `"DEED/00000000"` is the dev/test placeholder.
pub const DEED_ADDRESS: &str = match option_env!("AXIOM_DEED_ADDRESS") {
    Some(addr) => addr,
    None => "DEED/00000000",
};

// Compile-time safety: DEED_ADDRESS must start with "DEED/" to prevent
// build-env hijack redirecting registration fees to an attacker wallet.
const _: () = {
    let b = DEED_ADDRESS.as_bytes();
    assert!(
        b.len() >= 5
            && b[0] == b'D'
            && b[1] == b'E'
            && b[2] == b'E'
            && b[3] == b'D'
            && b[4] == b'/',
        "DEED_ADDRESS must start with 'DEED/'"
    );
};

/// Fee address — receives protocol fee transactions.
/// Protocol-mandated amount bypasses the dust limit.
pub const FEE_ADDRESS: &str = "FEE/00000000";

/// Per-validator fee cap, in basis points of the transaction amount.
/// 30 bps = 0.30%. Bounds any single validator's slot in `Receipt.fee_breakdown`.
/// YP §19.6 amendment — aligns with EU Regulation 2015/751 per-service ceiling.
pub const MAX_VALIDATOR_FEE_BPS: u32 = 30;

/// Aggregate fee cap across all validators on a single transaction, in basis
/// points of the amount. 90 bps = 0.90%. Bounds the sum of `Receipt.fee_breakdown`.
/// YP §19.6 amendment.
pub const MAX_TOTAL_TX_FEE_BPS: u32 = 90;

/// Divisor used to interpret basis points (`bps / 10_000 = fraction`).
pub const FEE_BPS_DIVISOR: u64 = 10_000;

/// Fraction of every TX's total validator fees that goes to the DEED
/// infrastructure-funding pool, in basis points. 1000 bps = 10%.
/// Applied to `sum(fee_breakdown[i].amount)` per receipt; the remaining
/// 90% is split proportionally across the witnessing validators. See
/// `docs/AXIOM_DESIGN_DeedDistribution.md` and `compute_deed_split`.
pub const DEED_BPS: u32 = 1_000;

/// How long the DEED pool collects, in seconds. Compared against
/// `tick - GENESIS_NEWS_ANCHOR` at every register. Past the cutoff,
/// validators keep the full slot and the DEED pool size freezes.
/// 10 calendar years, no leap-day adjustment — lands ~2.5 days short
/// of the 10-year calendar anniversary.
pub const DEED_COLLECTION_DURATION_SECS: u64 = 10 * 365 * 24 * 60 * 60;

/// Protocol version tag included in every signing message.
/// Prevents cross-network and cross-version signature replay attacks.
pub const AXIOM_PROTOCOL_VERSION: &str = "AXIOM/2.11";

/// DWP group wallet address prefix — JFP vote TXs (1 atom) bypass dust limit.
/// Group wallets are created by the DWP query flow and already exist when votes arrive.
/// See Yellow Paper §8.4.
pub const DWP_ADDRESS_PREFIX: &str = "DWP/";

/// Genesis claim amount — 1 AXC credited to new wallets from the Airdrop Pool.
/// 1 AXC = 10^10 atoms (Yellow Paper §17.11, White Paper §2.10.2).
/// Core uses this as the effective amount for produced_state_id and commitment
/// computation when `is_genesis_claim == true` (tx.amount is 0).
pub const GENESIS_CLAIM_AMOUNT: u64 = axiom_denomination::axc(1);

/// YPX-012: Oracle claim data embedded in a transaction.
/// Presence of this field marks the TX as an oracle claim.
/// Core validates: sender == receiver, k >= 5, platform whitelisted, living signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleClaimData {
    /// Must match a whitelist entry exactly (e.g., "https://foldingathome.org").
    pub platform_url: String,
    /// Platform's immutable numeric user ID.
    pub user_id: u64,
    /// Platform username — must contain Living Signature (AXM_<hex16>).
    pub username: String,
    /// Current total credits/points observed by the witnessing validators.
    pub credit_total: u64,
    /// Credit delta since last claim (credit_total - last_claimed_balance).
    pub credit_delta: u64,
    /// AXC payout computed by Lambda from credit_delta and config conversion rate.
    /// Core validates: payout_amount <= ORACLE_MAX_PAYOUT_PER_CLAIM AND platform whitelisted.
    /// Core does NOT recompute from credit_delta — Lambda owns the rate.
    #[serde(default)]
    pub payout_amount: u64,
    /// ZK-TLS proof blob (optional). When present, Lambda verifies via
    /// oracle_zktls::verify_zktls_proof before passing to Core.
    /// See docs/ORACLE_FUTURE_ZKTLS.md for integration plan.
    #[serde(default)]
    pub zktls_proof: Option<Vec<u8>>,
}

/// Core Logic Mode - determines which validation path to execute
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum CoreLogicMode {
    /// CL1: Client Core Out - validate outgoing transaction
    CL1,
    /// CL2: Validator Core In - verify incoming proof, validate transaction
    CL2,
    /// CL3: Validator Core Out - verify Lambda's work, produce witness proof
    CL3,
    /// CL4: Client Core In — verify incoming receipt.
    ///
    /// RESERVED FUTURE GATE (2026-07-05, KI#36). Intentionally NOT wired: today
    /// a receiver never moves value on a raw receipt — value advances only at
    /// CL5 (redeem), which is Core-verified twice (the receiver's own local
    /// `run_cl5` on the incoming cheque + the k-witness CL5 round), so a
    /// standalone CL4 pass would be pure redundancy. The slot is kept (not
    /// deleted) as the natural home for a *future* client-side receipt gate —
    /// if we ever need the receiver to get Core's verdict on an incoming
    /// receipt BEFORE redeem (e.g. a display-trust or forwarding guard), place
    /// it here. Until then it's DEFERRED in scripts/check_mode_coverage.py and
    /// the balance-advance invariant (Q1-A) is the live defense-in-depth. See
    /// AXIOM_REPORT_KnownIssues.md #36.
    CL4,
    /// CL5: Validator Redeem - validate cheque redemption (balance increase)
    CL5,
    // CL6 (standalone VBC verification) removed 2026-07-05: it was dead code —
    // VBC verification happens inside CL2/CL3/CL5 (validate_witnesses + the
    // S-ABR full-VBC check) and NBCs use CL7. Numeric slot 6 is now retired.
    /// CL7: NBC Verification (Nabla) — verify NBC bundle via Core IPC (k=1, NABLA_ROOT_AUTHORITY_PKS)
    CL7,
    /// CL8: NBC Issuance Signing — Core signs NBC with issuer's SPHINCS+ key (Nabla)
    CL8,
    /// CL9: Scar Heal Signing — Core signs scar heal commitment with validator's Dilithium key
    CL9,
    /// CL10: Fan-Out Verification — verify diffusion message (§18.8)
    CL10,
    /// CL11: Console Validation — verify Console Certificate chain + election (YPX-013)
    CL11,
    /// CL12: Send Proof Verification — offline, third-party verification of a
    /// retained Send Proof (transaction + finalized receipt). Beyond the k
    /// witness signatures, Core verifies every witness's VBC chains to
    /// `ROOT_AUTHORITY_PKS`, so a proof forged with throwaway validator keys is
    /// REJECTED. The verdict is Core's, reproducible via DMAP-VM or attestable
    /// via the zkVM. Carries the proof in `transaction` + `prev_receipts[0]`.
    CL12,
    /// CL13: Validator-withdrawal mint (YP §20.10, fee ledger Step 9B).
    ///
    /// Mints `validator_withdrawal_proof.earnings_attestation.total_amount
    /// × 90/100` atoms into `pool_linkage.linked_wallet_id`. Re-runs the
    /// 7-step verification chain (`verify_validator_withdrawal`) against
    /// the embedded proof before producing a mint receipt. Each chosen
    /// witness Lambda runs this independently — no trust placed in the
    /// originating Lambda.
    ///
    /// Step 9B.1 wires the dispatch surface; Step 9B.2 lands the
    /// verification logic. Until then `execute_validator_withdrawal_mint`
    /// returns `Reject(ValidatorWithdrawalMintNotImplemented)`.
    CL13,
    /// CL2_PREFILTER: ANTIE gateway pre-execution.
    ///
    /// State-INDEPENDENT subset of CL2. Runs every check that can be made
    /// from the request alone (signatures, dust, Ark rules, oracle rules,
    /// genesis lockup, reference length, frozen wallets, sender_wallet_id
    /// shape, version, fact-chain integrity, burn target). Skips every
    /// check that requires Lambda's stored wallet state (balance, wallet_seq
    /// chain, state_id chain, owner_proof against stored auth_hash, S-ABR
    /// overlap math, VBC expiry of forwarded prev_receipts, CLARA rewrite).
    ///
    /// Used by ANTIE so its Core pre-execution can run with
    /// `current_state = None` — no fabricated WalletState, no false claim
    /// about Lambda's storage. Lambda's own CL2 pass owns the authoritative
    /// stateful checks against real stored state.
    ///
    /// CLAUDE.md §8 ("Layer roles are strict") — ANTIE never synthesizes
    /// what Lambda should verify. CL2_PREFILTER is the architectural fix
    /// that lets ANTIE honor that rule without losing its early-reject
    /// gating. See YPX-018 §2.1.2.
    CL2_PREFILTER,
}

/// Validation result from Core.bin
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationResult {
    Accept,
    Reject,
    /// FATAL: Validator configuration is broken — Lambda MUST shut down.
    /// This is returned when Core's OWN VBC fails verification (root key mismatch,
    /// expired, invalid chain). The validator cannot produce honest results.
    /// "Can crash, must not lie."
    Fatal,
}

/// A transaction in AXIOM
/// 
/// SECURITY: Uses deny_unknown_fields to prevent field aliasing attacks (C2)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    /// State ID being consumed by this transaction
    pub consumed_state_id: [u8; 32],
    
    /// Client's public key (Ed25519 or Dilithium)
    pub client_pk: Vec<u8>,

    /// Sender's wallet_id — identifies which tier address the sender is using.
    /// Core enforces identity binding: sender_wallet_id must match WalletState.wallet_id
    /// once established (prevents lockup bypass and Ark policy spoofing).
    /// Used for Ark tier enforcement (§11.9), genesis lockup, and oracle policy.
    #[serde(default)]
    pub sender_wallet_id: String,

    /// Wallet sequence number (must be prev + 1)
    pub wallet_seq: u64,
    
    /// Receiver's wallet_id (REQUIRED) - the actual wallet identity
    /// Format: "email/hex8" e.g. "bob@example.com/a3f7b232"
    /// The hex8 = checksum(6) + salt(2) for anti-typo protection
    /// checksum = BLAKE3(email || master_pk || salt)[0:6]
    pub receiver_wallet_id: String,
    
    /// Receiver's email override (OPTIONAL)
    /// If Some, send cheque to this email instead of wallet_id's email
    /// If None, extract email from receiver_wallet_id
    pub receiver_address: Option<String>,
    
    /// Amount in atoms (smallest unit)
    /// MUST be > 0 (zero amount transactions are rejected)
    pub amount: u64,
    
    /// Payment reference (max 256 chars)
    pub reference: String,
    
    /// Nonce for replay protection (epoch-scoped)
    pub nonce: u64,
    
    /// Epoch derived from consumed_state_id
    pub epoch: u64,
    
    /// Client's signature over the transaction
    pub client_sig: Vec<u8>,
    
    /// Owner authentication proof (optional — required when wallet has auth_hash)
    /// Zero-knowledge Ed25519 signature proving knowledge of owner_secret.
    /// auth_hash stores the Ed25519 public key derived from owner_secret.
    /// owner_proof = Ed25519_sign(derived_key, BLAKE3("AXIOM_OWNER_SIG" || signing_message))
    /// Validators see only the signature (64 bytes), never the secret.
    pub owner_proof: Option<Vec<u8>>,
    
    /// FACT scar passcode (YPX-001 §1.5)
    /// 6-digit code generated by overlapped validator when sender's money is scarred.
    /// Core strips this (like balance) for S-ABR — Lambda refills from stored record.
    /// Presence indicates receiver has consented to receive scarred money.
    /// None = no scar (normal TX) or first attempt (validator will pause and notify).
    pub scar_passcode: Option<u32>,

    /// Burn target TX ID (YPX-001 §1.5.4)
    /// When set, this TX is a burn: money sent to BURN_ADDRESS to resolve a scarred
    /// FACT link. The target is the tx_id of the scarred link being burned.
    /// Requires receiver_wallet_id == BURN_ADDRESS.
    pub burn_target_tx_id: Option<[u8; 32]>,

    /// YPX-022 RECALL — the failed (sub-quorum) send this recall reclaims.
    /// Audit reference only: the AUTHORITATIVE target + pre-send state rides
    /// the Nabla recall attestation (§2.1/§2.2). This documents the recalled
    /// txid on the RECALL tx (mirrors `burn_target_tx_id`).
    pub recall_target_tx_id: Option<[u8; 32]>,

    /// YPX-012: Oracle claim data (optional). When present, this TX is an oracle claim.
    /// Core enforces: sender == receiver, k >= 5, platform whitelisted, living signature.
    /// Validators independently verify platform credits before witnessing.
    #[serde(default)]
    pub oracle_claim: Option<OracleClaimData>,

    /// YPX-007: Required number of validators (0, 3, 4, or 5).
    /// Core-filled from wallet_id extraction — sender MUST NOT set this.
    /// Persisted for S-ABR overlap on the next transaction.
    #[serde(default)]
    pub required_k: u8,

    /// YPX-007: Proof type (0=zkvm, 1=dmap, 2=ark).
    /// Core-filled from wallet_id extraction — sender MUST NOT set this.
    #[serde(default)]
    pub proof_type: u8,

    /// Core version tag (e.g. "Kyoto/1.1/GENESIS").
    /// Checked at the very beginning of validate_transaction().
    /// Can be faked — real verification is the ELF hash (DMAP CoreID / ZKP IMAGE_ID).
    /// This is a cheap pre-filter to reject incompatible transactions early.
    #[serde(default)]
    pub core_version: String,

    /// BLAKE3 of the Core ELF the sender ran when building this TX.
    /// This is the **authoritative** version gate — `core_version` is the
    /// human label, `core_id` is the machine check. Step -1.5 of CL2:
    /// if non-zero and != `PublicInputs.local_core_id`, fast-reject with
    /// `ValidationError::CoreIdMismatch` before any DMAP / signature work.
    ///
    /// Empty (all-zero) is accepted for backward compat with TXs built
    /// before this field existed.
    ///
    /// Sender (SDK) reads this from `axiom_sdk::runtime().local_core_id`
    /// (which is `BLAKE3(elf_bytes)` computed at `setup()` time).
    /// Validators read theirs from compile-time `CANONICAL_CORE_ID`
    /// (release builds) or the same runtime hash (dev builds).
    #[serde(default)]
    pub core_id: [u8; 32],

    /// Discriminant for the protocol-level operation this transaction
    /// performs. Replaces the v2.x bool sprawl (`is_heal`,
    /// `is_genesis_claim`) so future ops add a `TxKind` variant instead
    /// of a new flag. Type-system enforces mutual exclusion: a TX can
    /// be exactly one of these.
    ///
    /// Helpers `tx.is_heal()`, `tx.is_genesis_claim()`,
    /// `tx.is_validator_withdrawal_mint()` exist for ergonomic reads
    /// at call sites that don't need exhaustive matching.
    #[serde(default)]
    pub kind: TxKind,
}

/// What kind of operation a `Transaction` performs. Mutually exclusive
/// by construction.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxKind {
    /// Default — a normal value-transfer transaction (Alice → Bob).
    #[default]
    Normal,

    /// YPX-018 Phase 5f — TX_HEAL self-send marker.
    ///
    /// CLARA wallet-recovery self-send: the wallet sends to itself to
    /// produce a real ChequeBundle for `POST /clara`. Relaxes the
    /// §11.9.4 self-send rejection (normally only Ark wallets can
    /// self-send). Otherwise goes through normal CL1 validation, k=3
    /// witnessing, FACT chain, scar handling, etc. Does NOT bypass any
    /// security check — only gates the self-send rejection rule.
    ///
    /// Reference: YPX-018 §2.4, Yellow Paper §17.10.14.
    Heal,

    /// New-wallet airdrop claim. Relaxes S-ABR (no prev_receipts) and
    /// self-send rejection. Core validates `wallet_seq == 1`, `prev_seq
    /// == 0`, `amount == 0`. Validators issue `GENESIS_CLAIM_AMOUNT`
    /// cheque; Nabla controls the pool balance.
    ///
    /// Reference: Yellow Paper §17.11.
    GenesisClaim,

    /// YP §20.10 / fee ledger Step 9B — validator-withdrawal mint.
    ///
    /// Mints `validator_withdrawal_proof.earnings_attestation
    /// .total_amount × 90/100` atoms into
    /// `pool_linkage.linked_wallet_id`. Source is the synthetic
    /// validator pool; atom-conservation is enforced at Nabla. Each
    /// `chosen_witness` Lambda re-runs the 7-step verification chain
    /// (`verify_validator_withdrawal`) before signing.
    ///
    /// Reference: YP §20.10, `docs/AXIOM_DESIGN_ValidatorFeeLedger.md`.
    ValidatorWithdrawalMint,

    /// YPX-020 HAL — dead-overlap re-anchor self-send.
    ///
    /// A wallet whose prior witnesses have vanished cannot assemble the
    /// `k-1` S-ABR overlap and is stuck. A HAL re-anchor `X → X'` is
    /// witnessed by FRESH validators and **relaxes the overlap check**
    /// (modes.rs CL2). It does NOT relax the double-spend gate: that role
    /// moves to Nabla, which (1) rejects the re-anchor register until the
    /// convergence wait has elapsed (so a concurrent spend converges first)
    /// and (2) rejects it if `old_state` is in the monotonic consumed-state
    /// bloom (replay of an already-spent state). Core's relaxation MUST NOT
    /// deploy without that Nabla wait+bloom — they are one safety unit.
    ///
    /// Reference: YPX-020 §2/§6.
    ///
    /// YPX-020 §2 (2026-06-23): there is NO `HalComplete` kind. Completion is the
    /// REDEEM of the re-anchor's distress cheque (a self-send), which clears the
    /// hibernation lock on its produced state (see `modes.rs::execute_cl5`). The
    /// separate completion self-send was removed.
    HalReanchor,

    /// YPX-022 — RECALL self-send: reclaim a *failed* (sub-quorum, < k) send whose
    /// cheque the receiver can never redeem. Like `HalReanchor` it re-anchors with
    /// fresh witnesses and rides the binary hibernation lock, but its overlap
    /// substitute is the `< k` + window gate — the same `cheques.len() < required_k`
    /// predicate CL5 uses to reject a redeem (`modes.rs`) — and it consumes the
    /// target cheque at Nabla so the receiver's later redeem dies. Discriminator
    /// only for now; the gate + wire flag land in later steps (build plan
    /// `docs/AXIOM_BUILD_RECALL_OODS_v1.md`).
    Recall,
}

/// YPX-020 — HIBERNATION window: epochs a wallet is held "out of work" after a
/// HAL re-anchor, so a concurrent spend converges (fork→ban) before the
/// re-anchored funds become spendable again. Enforced at Core CL2 + Nabla.
/// Production = ~the 25 h convergence wait. Dev-mode shortens it to 50 ticks
/// (50 × TICK_INTERVAL_SECS = ~250s, ~4 min) so the soak can drive a full
/// re-anchor → hibernate → unhibernate cycle quickly while still OUTLASTING the
/// ~30–50s witness round — the window is stamped at the re-anchor's TX epoch
/// (round start), so a too-short value (the old 10 = 50s) elapses before
/// hal_reanchor even returns and the UI countdown reads as a dead timer.
/// NB: this is baked into the ELF, so the dev CoreID ≠ the prod CoreID (expected).
/// Single source: protocol_core.toml `[timing]` (2026-07-07 consolidation) —
/// dev/prod selected by the build.rs `_dev`-pair codegen. See the toml key
/// docs; the prod/dev values are unchanged (18000 / 50).
pub use crate::validation::HIBERNATION_WINDOW;

/// YPX-022 RECALL maturity window — the ONE time mechanism RECALL has, and it is the
/// SAME mechanism HAL uses: the wallet carries `produced_hibernation_until` in its
/// k-witnessed state (via `hibernation_until_for`), Core binary-gates it, Nabla enforces
/// the tick-wait on completion. HAL and RECALL differ ONLY in this duration constant.
/// Tick count, projected exactly like `HIBERNATION_WINDOW`. Baked into the ELF →
/// dev CoreID ≠ prod CoreID (expected). Prod value tuned against TARDIS cadence.
/// Single source: protocol_core.toml `[timing]` (720 / 20 dev, unchanged).
pub use crate::validation::RECALL_HIBERNATION_WINDOW;
/// Dev-WALLET (`@axiom.internal`) short windows — see `hibernation_until_for`.
pub use crate::validation::{DEV_WALLET_HIBERNATION_WINDOW, DEV_WALLET_RECALL_HIBERNATION_WINDOW};
/// YPX-022 §2.1 recall initiation window — protocol_core.toml `[timing]`
/// ([18000, 50000] prod / [10, 100000] dev, unchanged). Exposed HERE (the
/// ELF-bound protocol surface) so Nabla and the Mac FFI read the SAME
/// constant instead of hand-mirroring it (Mac's drift ask, 2026-07-07).
pub use crate::validation::{RECALL_INIT_WINDOW_LOW, RECALL_INIT_WINDOW_HIGH};

/// Seconds per tick — the protocol's maximum inter-tick interval (a TARDIS tick
/// is generated from unix time with an `age <= 5s` freshness bound; it can be
/// faster but never slower). `epoch`/`tick` values are unix-second stamps, so a
/// window expressed in TICKS is projected onto a stamp by multiplying by this
/// bound: real ticks arrive faster, so the projected stamp is an upper bound the
/// actual tick never passes — the window holds for AT LEAST that many ticks.
/// Mirrors `axiom_nabla::constants::TICK_INTERVAL_SECS`.
pub const TICK_INTERVAL_SECS: u64 = crate::validation::protocol_gen::TICK_INTERVAL_SECS;

/// THE single tick-count → unix-second projection. Every window expressed in
/// TICKS (recall init window, hibernation windows, cheque maturity) projects onto
/// the unix-second `tick`/`epoch` scale through THIS one function — never an
/// inline `* TICK_INTERVAL_SECS` (which is where the copies drifted, and where one
/// silently went wrong: see [`TickCount`]). Real ticks arrive at most
/// `TICK_INTERVAL_SECS` apart, so the projected stamp is an upper bound the actual
/// tick never passes — the window holds for AT LEAST `ticks` ticks.
pub const fn ticks_to_secs(ticks: u64) -> u64 {
    ticks.saturating_mul(TICK_INTERVAL_SECS)
}

/// A COUNT of TARDIS ticks — NOT a tick VALUE (a unix-second stamp) and NOT a
/// duration in seconds. It exists as a COMPILE-TIME GUARD against the
/// tick-count-vs-tick-value confusion that has now bitten three times: most
/// recently the RECALL init window compared a seconds-difference
/// (`current_tick - completion_tick`, both unix-second stamps) directly against a
/// raw tick COUNT, so the window opened ~5× early (`TICK_INTERVAL_SECS`×) and
/// shortened the receiver's guaranteed no-recall protection.
///
/// The ONLY way to get a comparable unix-second quantity out of a `TickCount` is
/// [`TickCount::to_secs`], which routes through [`ticks_to_secs`]. Because the
/// window constants are `TickCount`, a raw `age_secs < RECALL_INIT_WINDOW_LOW` no
/// longer type-checks — the author is forced to write
/// `age_secs < RECALL_INIT_WINDOW_LOW.to_secs()`, and the mistake cannot recur.
///
/// Core-owned: this is the ELF-bound protocol surface. Nabla and the FFI import
/// the window constants AND this projection from here, so the eligibility math is
/// defined ONCE, by Core, and every enforcer agrees on the exact window.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TickCount(pub u64);

impl TickCount {
    /// Project this tick COUNT onto the unix-second scale that `tick`/`epoch`
    /// stamps live on. THE ONLY projection — delegates to [`ticks_to_secs`].
    /// Compare a tick-VALUE difference (an age in seconds) against THIS, never
    /// against [`TickCount::ticks`].
    pub const fn to_secs(self) -> u64 {
        ticks_to_secs(self.0)
    }

    /// The raw tick count, for arithmetic that legitimately stays in tick-count
    /// space (e.g. selecting a hibernation window before it is projected). Does
    /// NOT project — never compare the result against a tick-VALUE difference.
    pub const fn ticks(self) -> u64 {
        self.0
    }
}

/// The SINGLE hibernation-deadline projection, shared by Core (`produced_hibernation_until`),
/// Nabla (the re-anchor register stamp), and the SDK (§15 local set). Returns
/// `base_tick + window_ticks·TICK_INTERVAL_SECS`, or `0` (not hibernating) when `window == 0`.
/// HAL and RECALL both go through this; they differ ONLY in the window value passed in — the
/// projection logic exists in one place, not per-layer/per-kind.
/// THE SINGLE SOURCE OF HIBERNATION TRUTH — kind → window → deadline, all in one function.
/// The re-anchor hibernation deadline stamped on `base_tick`: HAL and RECALL both go through
/// this and differ ONLY in the window constant selected; any other kind → 0 (not hibernating).
/// Core (`produced_hibernation_until` / the §15 state binding), Nabla (the register stamp),
/// and the SDK (the §15 local mirror) ALL call this one function — a hibernation bug is fixed
/// in exactly one place. `WINDOW` is a TICK count projected onto the unix-sec `base_tick` via
/// the `<= TICK_INTERVAL_SECS`/tick bound, so the lock holds for at least `WINDOW` ticks.
pub fn hibernation_until_for(
    base_tick: u64,
    is_hal_reanchor: bool,
    is_recall: bool,
    is_dev_class: bool,
) -> u64 {
    // The dev-WALLET short window applies ONLY when `is_dev_class` is set — the k-signed
    // flag Core computes as `is_dev_wallet(sender)` and binds into `receipt_commitment`.
    // A PUBLIC wallet (is_dev_class=false) ALWAYS gets the full window below; a forged
    // is_dev_class=true is caught by Core's k-signed receipt verification. So this can
    // NEVER shorten a real (public) wallet's hibernation — it cannot touch real money.
    // All THREE callers supply the SAME authoritative flag (Core = is_dev_wallet(sender),
    // Nabla = reg.receipt.is_dev_class, SDK = wallet.is_dev_class()), keeping the §15
    // Core↔Nabla↔SDK lock-step exact.
    let window_ticks = if is_hal_reanchor {
        if is_dev_class { DEV_WALLET_HIBERNATION_WINDOW } else { HIBERNATION_WINDOW }
    } else if is_recall {
        if is_dev_class { DEV_WALLET_RECALL_HIBERNATION_WINDOW } else { RECALL_HIBERNATION_WINDOW }
    } else {
        return 0;
    };
    base_tick.saturating_add(window_ticks.saturating_mul(TICK_INTERVAL_SECS))
}

impl Transaction {
    /// YPX-020: the hibernation deadline a HAL re-anchor stamps on its produced
    /// state. `HIBERNATION_WINDOW` is a TICK count; we project it onto the
    /// `epoch` unix-second stamp via `TICK_INTERVAL_SECS` (the <=5s/tick bound),
    /// so the lock holds for at least `HIBERNATION_WINDOW` ticks. `0` for any
    /// non-re-anchor tx. SINGLE SOURCE for both the state-hash binding
    /// (`compute_new_state_hash`) and `PublicOutputs.hibernation_until` — keeping
    /// these two in lock-step is load-bearing for the §15 anchor check.
    pub fn produced_hibernation_until(&self) -> u64 {
        // YPX-022 RECALL hibernates like HAL — the maturity window for the recall's
        // consume-once to converge across the mesh before the SDK's fail-closed re-verify.
        // SAME function + SAME projection for both — only the window value differs by kind
        // (HAL vs recall). No non-re-anchor tx hibernates.
        hibernation_until_for(
            self.epoch,
            self.is_hal_reanchor(),
            self.is_recall(),
            // Core's authoritative dev-class determination — the SAME check that gates
            // FACT class isolation and stamps the k-signed Receipt.is_dev_class.
            crate::wallet_id::is_dev_wallet(&self.sender_wallet_id),
        )
    }
}

impl Transaction {
    /// True if this TX is a CLARA wallet-recovery self-send. Pre-9B.1
    /// callers read `tx.is_heal()` (a bool field); this is the type-safe
    /// replacement that keeps call sites short.
    #[inline]
    pub fn is_heal(&self) -> bool {
        matches!(self.kind, TxKind::Heal)
    }

    /// True if this TX is a new-wallet airdrop claim. Pre-9B.1 callers
    /// read `tx.is_genesis_claim()` (a bool field); this is the type-safe
    /// replacement.
    #[inline]
    pub fn is_genesis_claim(&self) -> bool {
        matches!(self.kind, TxKind::GenesisClaim)
    }

    /// True if this TX is a validator-withdrawal mint (Step 9B+).
    #[inline]
    pub fn is_validator_withdrawal_mint(&self) -> bool {
        matches!(self.kind, TxKind::ValidatorWithdrawalMint)
    }

    /// True if this TX is a YPX-020 HAL dead-overlap re-anchor. Relaxes the
    /// S-ABR overlap (modes.rs CL2) ONLY — the double-spend gate moves to the
    /// Nabla wait + consumed-state bloom (must deploy together).
    #[inline]
    pub fn is_hal_reanchor(&self) -> bool {
        matches!(self.kind, TxKind::HalReanchor)
    }

    /// YPX-022 — RECALL discriminator. Not yet consulted on the consensus path
    /// (the `< k` + window gate and the wire flag land in later build-plan steps).
    #[inline]
    pub fn is_recall(&self) -> bool {
        matches!(self.kind, TxKind::Recall)
    }

}

impl Transaction {
    /// Canonical CBOR encoding used on the SDK ↔ validator wire.
    ///
    /// Two things make this NOT serde's default `Serialize` for `Transaction`:
    ///
    /// 1. **Byte arrays as `[u8, u8, …]` not as CBOR byte strings.** The wire
    ///    format predates the canonical `Transaction` struct; switching to
    ///    serde's default byte-string emission would break every downstream
    ///    consumer (validators, Lambda, Python harness, webclient). The
    ///    decoders all accept both — but the encoder direction has to keep
    ///    emitting arrays-of-int.
    ///
    /// 2. **Field order matches the historical hand-built encoder.** CBOR
    ///    maps are keyed (so decode is order-independent), but the bytes are
    ///    what `client_sig` is computed over. Changing field order would
    ///    invalidate the signing-message hash. We preserve the existing
    ///    18-field order to keep on-the-wire signatures stable.
    ///
    /// **Drift-prevention pattern** (mirrors the receipt-builder
    /// consolidation, see `axiom_core_logic::receipt::build_send_receipt`):
    /// this is the *only* function in the workspace that produces canonical
    /// `Transaction` CBOR. The SDK's `build_tx_cbor` and `build_tx_cbor_heal`
    /// are thin wrappers that construct a `Transaction { … }` and call this.
    /// Adding a field to `Transaction` therefore forces a decision here
    /// (emit it or leave it out, both explicit); see `INTENTIONALLY_UNEMITTED`
    /// for the current skip list.
    ///
    /// **Fields intentionally not on the wire today:** `oracle_claim`,
    /// `is_genesis_claim`. Both default to None/false and are accepted by
    /// Core's decoder when missing (`#[serde(default)]`). Extending the
    /// emitted set is a wire-format change that requires soak validation.
    pub fn to_canonical_cbor_value(&self) -> ciborium::Value {
        use ciborium::Value;

        fn bytes_as_int_array(bytes: &[u8]) -> Value {
            Value::Array(bytes.iter().map(|&b| Value::Integer(b.into())).collect())
        }
        fn opt_text(opt: &Option<String>) -> Value {
            match opt {
                Some(s) if !s.is_empty() => Value::Text(s.clone()),
                _ => Value::Null,
            }
        }
        fn opt_u32(opt: Option<u32>) -> Value {
            match opt {
                Some(n) => Value::Integer(n.into()),
                None => Value::Null,
            }
        }
        fn opt_bytes_as_int_array(opt: &Option<[u8; 32]>) -> Value {
            match opt {
                Some(b) => bytes_as_int_array(b),
                None => Value::Null,
            }
        }

        Value::Map(vec![
            (Value::Text("consumed_state_id".into()),
             bytes_as_int_array(&self.consumed_state_id)),
            (Value::Text("client_pk".into()),
             bytes_as_int_array(&self.client_pk)),
            (Value::Text("wallet_seq".into()),
             Value::Integer(self.wallet_seq.into())),
            (Value::Text("sender_wallet_id".into()),
             Value::Text(self.sender_wallet_id.clone())),
            (Value::Text("receiver_wallet_id".into()),
             Value::Text(self.receiver_wallet_id.clone())),
            (Value::Text("receiver_address".into()),
             opt_text(&self.receiver_address)),
            (Value::Text("amount".into()),
             Value::Integer(self.amount.into())),
            (Value::Text("reference".into()),
             Value::Text(self.reference.clone())),
            (Value::Text("nonce".into()),
             Value::Integer(self.nonce.into())),
            (Value::Text("epoch".into()),
             Value::Integer(self.epoch.into())),
            (Value::Text("client_sig".into()),
             bytes_as_int_array(&self.client_sig)),
            (Value::Text("owner_proof".into()),
             // Historical: emit as an array even when absent. Some(empty)
             // and None both serialize to an empty array — the wire shape
             // never distinguished.
             bytes_as_int_array(self.owner_proof.as_deref().unwrap_or(&[]))),
            (Value::Text("scar_passcode".into()),
             opt_u32(self.scar_passcode)),
            (Value::Text("burn_target_tx_id".into()),
             opt_bytes_as_int_array(&self.burn_target_tx_id)),
            (Value::Text("recall_target_tx_id".into()),
             opt_bytes_as_int_array(&self.recall_target_tx_id)),
            (Value::Text("required_k".into()),
             Value::Integer(self.required_k.into())),
            (Value::Text("proof_type".into()),
             Value::Integer(self.proof_type.into())),
            (Value::Text("core_version".into()),
             Value::Text(self.core_version.clone())),
            (Value::Text("core_id".into()),
             bytes_as_int_array(&self.core_id)),
            // 9B.1 C+B refactor: emit `is_heal` derived from `kind` so the
            // canonical CBOR bytes (and therefore the receipt commitment)
            // stay byte-identical for Normal/Heal/GenesisClaim TXs.
            // GenesisClaim is intentionally unemitted (same as v2.x — see
            // INTENTIONALLY_UNEMITTED). ValidatorWithdrawalMint is a new
            // kind with no pre-9B receipts to preserve; it gets its own
            // discriminant slot below.
            (Value::Text("is_heal".into()),
             Value::Bool(self.is_heal())),
            (Value::Text("is_validator_withdrawal_mint".into()),
             Value::Bool(self.is_validator_withdrawal_mint())),
            // YPX-020 HAL: HalReanchor is a new kind with no pre-9B receipts
            // to preserve, so it gets its own discriminant bool (like the
            // mint above). WITHOUT this emit the kind silently degrades to
            // Normal on the canonical wire and the validator rejects the
            // re-anchor with SABRInsufficientOverlap instead of relaxing
            // overlap — the whole HAL primitive is unreachable. The ANTIE
            // gateway decoder reconstructs `kind` from this bool.
            (Value::Text("is_hal_reanchor".into()),
             Value::Bool(self.is_hal_reanchor())),
            // YPX-022 RECALL: same pattern as HAL — a new kind's own discriminant
            // bool so `kind` survives the canonical wire (else it degrades to Normal
            // and the <k gate is unreachable). The gateway decoder reconstructs it.
            (Value::Text("is_recall".into()),
             Value::Bool(self.is_recall())),
        ])
    }

    /// CBOR-encoded bytes via the canonical encoder. Used by the SDK's
    /// `build_tx_cbor` callers that need a `Vec<u8>` rather than a
    /// `ciborium::Value`.
    pub fn to_canonical_cbor_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&self.to_canonical_cbor_value(), &mut buf)
            .expect("Transaction canonical CBOR encode (in-memory writer cannot fail)");
        buf
    }

    /// Fields on the struct that the canonical encoder intentionally
    /// does NOT emit on the wire. Used by the test below to assert
    /// that every newly-added field is either emitted or explicitly
    /// listed here — closing the §13 drift class mechanically.
    #[cfg(test)]
    const INTENTIONALLY_UNEMITTED: &'static [&'static str] = &[
        "oracle_claim",
        // `kind` is decomposed into per-discriminant bools by the
        // canonical encoder (`is_heal`, `is_validator_withdrawal_mint`).
        // `TxKind::GenesisClaim` is intentionally not committed (was
        // `is_genesis_claim` pre-9B.1 and behaves the same).
        "kind",
    ];
}

/// A single validator's slot in `Receipt.fee_breakdown`.
///
/// Receiver-pays-only fee model (post v2.11.6): each entry attributes a fee
/// amount to one of the receiver's witnessing validators. The aggregate sum is
/// the total fee the receiver pays out of `amount`. Empty `fee_breakdown` means
/// no fee (heal, genesis claim, or operator-zero-rate paths).
///
/// Bound into `receipt_commitment` via `compute_receipt_commitment` so a
/// post-hoc edit of any slot invalidates the k witnessing Ed25519 signatures.
/// Each Lambda verifies its own slot before signing (`fee_breakdown[i].amount
/// == fee_config.rate_bps * amount / 10_000`); the cap rules
/// (`validate_fee_breakdown`) are enforced independently by Core CL5 and Nabla
/// at `/register` so a colluding k-set cannot mint over-cap fees.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct FeeShare {
    /// Validator's stable identifier: `blake3(sphincs_pk)`. Same value
    /// `WitnessSig.validator_id` carries and the same key `Nabla.validator_earnings`
    /// indexes by.
    pub validator_id: [u8; 32],
    /// Fee amount in atoms allocated to this validator.
    pub amount: u64,
}

/// OODS health flag (YPX-021 §8.2) — the network-view health annotation a
/// witnessing round stamps onto the wallet's receipt. Carries forward with
/// the wallet's state so the NEXT validator knows whether the previous step
/// happened under a healthy view of the network.
///
/// `tick` — when it was stamped; `oods_size` — the (rounded) network size
/// the attesting Nabla saw; `healthy` — `true` iff `oods_size` is in range
/// of the Nabla's NBC baseline (§7; see `validation::oods_healthy`).
///
/// Set by Core (`modes::execute_cl3` / `execute_cl5`) from a verified
/// `NablaOodsAttestation` and bound into `receipt_commitment`, so an
/// eclipsed Nabla cannot forge `healthy = true` post-hoc. `healthy = false`
/// on the previous state blocks FACT-chain compression on the next TX
/// (the §8 wash-out gate) — NOT a scar, an orthogonal health annotation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct OodsFlag {
    /// TARDIS tick at stamp time.
    pub tick: u64,
    /// Rounded OODS network-size estimate the attesting Nabla held.
    pub oods_size: u32,
    /// `oods_size` within range of the Nabla's NBC baseline (§7/§9).
    pub healthy: bool,
}

/// A receipt proving a transaction was processed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// Transaction ID (BLAKE3 hash of CB_core)
    pub txid: [u8; 32],
    
    /// State hash after transaction (SHA3-256)
    pub state_hash: [u8; 32],
    
    /// Produced state ID
    pub produced_state_id: [u8; 32],
    
    /// New wallet sequence number
    pub new_wallet_seq: u64,
    
    /// Commitment hash that validators signed
    /// BLAKE3("AXIOM_WITNESS_V2" || consumed_state_id || client_pk || ...)
    /// Core verifies: each witness_sig.signature is valid over this hash
    /// Note: serde(default) for backward compat — production receipts MUST have this
    #[serde(default)]
    pub commitment_hash: [u8; 32],
    
    /// Settlement Domain ID — identifies which worldline this receipt belongs to.
    /// BLAKE3("AXIOM_SDID" || genesis_hash). Prevents cross-worldline receipt replay.
    /// See Yellow Paper §23.9.2, §23.11.2.
    #[serde(default)]
    pub sdid: [u8; 32],
    
    /// Lineage hash — BLAKE3 chain of core upgrades from genesis.
    /// Must be an ancestor of the verifier's current lineage.
    /// See Yellow Paper §23.11.2.
    #[serde(default)]
    pub lineage_hash: [u8; 32],
    
    /// Core version that produced this receipt (e.g., "2.5.0").
    /// Must be from the verifier's known upgrade path.
    /// See Yellow Paper §23.11.2.
    #[serde(default)]
    pub core_version: String,

    /// BLAKE3 of the Core ELF that produced this receipt. Companion to
    /// `Transaction.core_id`: when a future TX references this receipt
    /// in `prev_receipts`, Lambda's chain walk can fast-reject if the
    /// receipt's core_id doesn't match the current local core_id —
    /// without re-running DMAP verify on the embedded execution proofs
    /// (which would fail anyway with WrongCore).
    ///
    /// Covered by `receipt_commitment`, so the witnessing validators
    /// are cryptographically attesting "we verified under THIS core_id."
    /// Empty (all-zero) accepted for backward compat with receipts
    /// built before this field existed.
    #[serde(default)]
    pub core_id: [u8; 32],

    /// Witness signatures (k=3 minimum)
    pub witness_sigs: Vec<WitnessSig>,
    
    /// Epoch when processed
    pub epoch: u64,
    
    /// FACT proof: zkVM execution receipt proving Core accepted this transaction.
    /// None in dev mode (no zkVM). MANDATORY in production mode.
    /// Per Yellow Paper Section 26.17: "No proof, no money."
    pub fact_proof: Option<FactProof>,

    /// k required by the original TX's receiver tier (3/4/5).
    /// Used by validate_witnesses to compute sabr_overlap for heal floor:
    /// a heal's prev_receipts may have as few as sabr_overlap(required_k)
    /// sigs (the partial-commit shape). Normal sends still require >=3.
    /// Defaults to 3 for receipts built before this field existed.
    #[serde(default = "default_receipt_required_k")]
    pub required_k: u8,

    /// Receipt commitment — BLAKE3("AXIOM_RECEIPT_v1" || txid || state_hash
    /// || produced_state_id || new_wallet_seq || commitment_hash || epoch
    /// || fee_breakdown_bytes).
    /// Binds ALL receipt fields including fee_breakdown into a single hash
    /// that k validators sign. Core verifies: recompute from fields, check k
    /// signatures match. Prevents receipt fabrication by clients or colluding
    /// validators (forged or post-hoc-edited fee_breakdown invalidates the sigs).
    #[serde(default)]
    pub receipt_commitment: [u8; 32],

    /// Receiver-pays-only fee allocation. Each entry attributes a fee amount
    /// to one of the receiver's witnessing validators (post v2.11.6 cashier's
    /// cheque model). Empty on heal / genesis-claim / zero-rate paths.
    ///
    /// Bound into `receipt_commitment`. Cap-enforced by `validate_fee_breakdown`
    /// at Core CL5 and again at Nabla `/register`.
    pub fee_breakdown: Vec<FeeShare>,

    /// Dev-class flag (`AXIOM_DESIGN_FactClassIsolation.md`).
    ///
    /// `true` when this TX's `sender_wallet_id` matches the
    /// `@axiom.internal` domain (per `is_dev_wallet`). Receiver class
    /// is identical by Rule R1 (`check_domain_isolation`), so the
    /// flag captures the class of BOTH ends of the TX.
    ///
    /// Core attests this at every CL that validates the TX (CL1
    /// client self-check, CL2 validator pre-sign, CL3 Lambda
    /// re-validation, CL5 redeem). Bound into `receipt_commitment`
    /// so the k=3 witness sigs cryptographically cover it — a
    /// forged or post-hoc-edited flag invalidates the sigs.
    ///
    /// Routing consequence (Nabla `/register`): when `true`, fees +
    /// DEED are credited to the dev-side pools (`DevDeedPool`,
    /// `ValidatorDevNetLedger`) instead of the public pools. The
    /// validator-withdrawal mint path reads the source-pool flag to
    /// gate the mint type, so dev fees can ONLY mint dev-AXC.
    /// Multi-layer defense: Core enforces the flag is recomputable
    /// from `sender_wallet_id`; Nabla routes by it; the mint path
    /// gates by it. Any one layer alone closes the leak; the three
    /// together make a leak structurally impossible.
    #[serde(default)]
    pub is_dev_class: bool,

    /// OODS health flag (YPX-021 §8.2). `Some` when the witnessing round
    /// carried a verified `NablaOodsAttestation`; `None` on paths with no
    /// Nabla reading (heal, genesis claim — Phase 1; Phase 2 makes the
    /// attestation mandatory on send/redeem). Bound into
    /// `receipt_commitment` (presence AND values), so it cannot be added,
    /// removed, or edited after the k witnesses sign.
    ///
    /// NO `serde(default)` — deliberate hard format break per CLAUDE.md
    /// §13; pre-flag receipts do not load.
    pub oods_flag: Option<OodsFlag>,
}

fn default_receipt_required_k() -> u8 { 3 }


/// FACT proof — cryptographic evidence that Core verified this state transition.
/// Contains the zkVM receipt (STARK proof) that Core.bin executed and accepted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactProof {
    /// RISC Zero receipt bytes (STARK proof)
    pub zkvm_receipt: Vec<u8>,
    
    /// Program digest of Core.bin that produced this proof
    pub core_digest: [u8; 32],
    
    /// Hash of the public inputs fed to Core
    pub public_inputs_hash: [u8; 32],
    
    /// Hash of the public outputs Core produced
    pub public_outputs_hash: [u8; 32],
}

// ============================================================================
// FACT CHAIN — Money Provenance (YPX-001)
// ============================================================================
//
// Every wallet carries a FACT chain proving its money traces back to genesis.
// Same trust model as VBC: genesis validators are the root of trust.
//
// Compression triggers at 8 links (MAX_FACT_DEPTH), 5 retained after compression (FACT_KEEP).
// Scarred links (no Nabla confirmation) block compression until healed or burned.

/// Default required_k for deserialization of old FACT links without the field.
fn default_required_k() -> u8 { 3 }

/// A single FACT link — proves one state transition happened, witnessed by k validators.
/// Like VBC links prove validator legitimacy, FACT links prove money legitimacy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactLink {
    /// Transaction ID (BLAKE3 of commitment)
    pub tx_id: [u8; 32],
    
    /// Sender's state before this transaction
    pub previous_state_id: [u8; 32],
    
    /// Sender's state after this transaction (= produced_state_id)
    pub new_state_id: [u8; 32],
    
    /// Amount transferred in this link
    pub amount: u64,
    
    /// TARDIS tick when TX occurred (0 if TARDIS not yet active)
    #[serde(default)]
    pub tick: u64,
    
    /// Required k for this TX — how many witnesses were needed for full commit.
    /// Extracted from receiver_wallet_id at TX time. Used for scar detection:
    /// witnesses.len() < required_k = partial commit = real scar.
    /// NOT for S-ABR overlap (that uses PREVIOUS TX's k).
    #[serde(default = "default_required_k")]
    pub required_k: u8,

    /// Compact witness references (validator_id + signature)
    /// Full VBC verification happens at witness time; FACT carries the proof
    /// that k=3 real validators (VBC-verified) signed this transition.
    pub witnesses: Vec<FactWitness>,
    
    /// Nabla confirmation (None = SCAR — blocks checkpoint compression)
    /// Can be healed later if Nabla confirmation obtained.
    /// Can be burned if owner chooses to destroy the tainted amount.
    pub nabla_confirmation: Option<NablaConfirmation>,
    
    /// Receiver's contact for scar healing propagation (YPX-001 §1.5.3).
    /// Contains wallet_id + email so healing proofs can be:
    ///   1. Delivered via email (validator or client app sends)
    ///   2. Verified by receiver's validator (wallet_id for lookup)
    ///      Format: "wallet_id|email" e.g. "bob@example.com/a3f7b232|bob@example.com"
    ///      Either validator or client app may deliver — proof is self-verifying.
    pub receiver_contact: Option<ReceiverContact>,

    /// Burn proof (YPX-001 §1.5.4) — proves a scarred link was resolved by burning.
    /// When present, this link is considered resolved (like nabla_confirmation)
    /// and becomes eligible for checkpoint compression.
    ///
    /// The proof is ONLY meaningful together with `burn_target_tx_id` on the
    /// burn TX's own link — see that field. `BurnProof.validator_sigs` is a
    /// clone of the burn link's own witnesses and binds nothing by itself.
    pub burn_proof: Option<BurnProof>,

    /// YPX-001 §1.5.4 — set ONLY on a BURN TX's own link: the tx_id of the
    /// scarred link this burn destroyed (mirrors `Transaction.burn_target_tx_id`,
    /// which Core already validates via `validate_burn_target`).
    ///
    /// **Bound into `compute_fact_commitment`**, so the k=3 witnesses attest the
    /// linkage and the sender cannot re-point a burn at a different scar without
    /// invalidating every Dilithium `fact_signature`. `verify_fact_link` then
    /// requires a burned link's `burn_proof.burn_tx_id` to name a link in the
    /// same chain that (a) targets it and (b) destroyed its exact amount.
    ///
    /// Closes the burn-proof COPY forge (2026-07-17): `BurnProof.validator_sigs`
    /// is only a clone of the burn link's own witnesses (`build_fact_link`), and
    /// `compute_burn_commitment` — the binding the BurnProof doc-comment claimed —
    /// was never called in production. So a proof lifted off a genuinely-burned
    /// 1-atom link and pasted onto a 1000-atom scar passed every check and read
    /// `is_resolved() == true`. Proven by
    /// `fact::tests::burn_proof_copied_from_another_link_rejected`.
    pub burn_target_tx_id: Option<[u8; 32]>,

    /// YPX-022 RECALL (2026-07-06 forward redesign) — resolves a scarred link whose
    /// sub-quorum send was RECALLED. When present + valid (Nabla-signed attestation
    /// whose `txid == this link's tx_id`), the link counts as resolved, exactly like
    /// `burn_proof`/`nabla_confirmation`: the send never moved value (it was reclaimed),
    /// so its scar no longer blocks compression. Lambda attaches it to the failed link
    /// when finalizing the recall self-send. NOT in `compute_fact_commitment` (a
    /// post-round resolution, like the other two), so the link's witness sigs stay valid.
    #[serde(default)]
    pub recall_proof: Option<RecallAttestation>,

    /// YPX-001 §1.5.1a SCAR INHERITANCE (CORE RULE, 2026-07-12). Tx_ids of
    /// the SENDER-chain links that were unresolved when this CROSS-WALLET
    /// redeem link was built — transitively including the sender's own
    /// unresolved inherited txids, so taint survives any number of hops.
    /// Sorted ascending (BTreeSet order): every one of the k signers
    /// derives the identical set from the same client-carried chain.
    /// BOUND into `compute_fact_commitment` — stripping the taint
    /// invalidates every witness Dilithium signature. Empty on send /
    /// heal / burn / self-redeem links and clean-provenance redeems.
    /// Consent (scar_passcode) is NOT cleansing: the receiver agreed to
    /// inherit, and the next hop's receiver consents in turn until the
    /// ORIGIN txid resolves.
    pub inherited_scar_txids: Vec<[u8; 32]>,

    /// Client-carried resolutions for the inherited set: one valid
    /// `NablaTxidAttestation` per source txid above. ANY validly-signed,
    /// NBC-anchored attestation resolves its txid — existence in Nabla's
    /// record means the origin transition re-registered (§1.5.2 heal), and
    /// status "BURNED" means the origin destroyed the tainted amount
    /// (§1.5.4). Post-round attachments — NOT in the commitment (witness
    /// sigs stay valid; recall_proof precedent) — but verified HARD by
    /// `verify_fact_link`: an invalid attestation rejects the chain. The
    /// link counts as SCARRED (gate fires, compression blocked) until
    /// every source txid has a resolution.
    #[serde(default)]
    pub inherited_scar_resolutions: Vec<NablaTxidAttestation>,

    /// Sender's chain-tip state_id at send time, populated on REDEEM links.
    /// Lets the receiver's chain anchor to the sender's verified provenance
    /// without needing a separate "bridge" link. Replaces the pre-A2
    /// double-link-per-redeem pattern.
    ///
    /// Required on every redeem link; CL5 verifies it equals
    /// `cheque.sender_fact_chain.tip().new_state_id`. None on send / heal /
    /// burn links. Bound into the FACT commitment (see AXIOM_FACT_v2).
    pub sender_anchor: Option<[u8; 32]>,

    /// Sticky class lock — `true` iff this wallet's first AXC came from
    /// `DevTreasuryPool` (i.e. `@axiom.internal`). Set ONCE at genesis
    /// and inherited unchanged on every subsequent link.
    ///
    /// Bound into `compute_fact_commitment` so k validators' Dilithium
    /// `fact_signature`s cryptographically attest to the value — a
    /// tampered flag invalidates every witness signature.
    /// `verify_fact_link` enforces TWO invariants:
    ///   (1) Sticky chain:  link[i].is_dev_class == link[i-1].is_dev_class
    ///   (2) Chain-vs-TX:   link.is_dev_class == is_dev_wallet(tx.sender_wallet_id)
    ///
    /// Used by Nabla `/register` for credit routing (replaces the
    /// SDK-tamperable `K3Receipt.is_dev_class` read) and by Lambda's
    /// `validator_earned` ledger for the dev-vs-public sum (replaces
    /// the per-TX `redeem_proof.outputs.is_dev_class` read).
    ///
    /// See `AXIOM_DESIGN_FactChainClassLock.md`.
    #[serde(default)]
    pub is_dev_class: bool,
}

impl FactLink {
    /// Number of inherited source txids still lacking a resolution
    /// attestation (presence check — signature validity is enforced by
    /// `verify_fact_link`, which hard-rejects invalid attachments, so a
    /// present entry here is verified-or-rejected upstream).
    pub fn inherited_unresolved(&self) -> usize {
        self.inherited_scar_txids.iter()
            .filter(|t| !self.inherited_scar_resolutions.iter().any(|r| &r.txid == *t))
            .count()
    }

}

impl FactLink {
    /// Whether this link is resolved (not a scar).
    ///
    /// Two resolution paths, and they treat inherited taint differently
    /// (YPX-001 §1.5.1a + §1.5.4):
    ///
    /// - **Burn** (`burn_proof` present) resolves the link UNCONDITIONALLY,
    ///   including any inherited taint. Burning destroys the link's exact
    ///   amount (the §1.5.4 binding, verified in `verify_fact_chain` before any
    ///   link is trusted here), so the tainted value no longer exists to
    ///   launder. This is the holder's escape hatch when the ORIGIN of an
    ///   inherited scar (typically a banned double-spender) will never resolve
    ///   it: the holder burns the tainted money, takes the loss, and un-sticks
    ///   their wallet. It is NOT a laundering path — clearing inherited taint
    ///   costs the full tainted amount, so an accomplice who burns to "get
    ///   healthy" ends up with zero, not clean money.
    ///
    /// - **Nabla confirmation** resolves only the link's OWN transition, so it
    ///   still requires every inherited scar to carry a resolution attestation
    ///   (the ORIGIN txid re-registered or burned). A confirmed-but-tainted
    ///   link stays scarred — the §1.5.1a wash-out defence in depth: consent is
    ///   not cleansing, only destruction-of-value or origin-resolution is.
    ///
    /// Scars are never healed by time.
    pub fn is_resolved(&self) -> bool {
        if self.burn_proof.is_some() {
            return true;
        }
        self.nabla_confirmation.is_some() && self.inherited_unresolved() == 0
    }
}

/// Proof that a scarred FACT link was resolved by burning the tainted amount.
/// The burn TX sends the exact scarred amount to BURN_ADDRESS.
/// k=3 validators sign the burn commitment to attest the burn is legitimate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnProof {
    /// TX ID of the burn transaction (sent to BURN_ADDRESS)
    pub burn_tx_id: [u8; 32],

    /// k=3 validator signatures over the burn commitment
    /// Signs: BLAKE3("AXIOM_BURN" || scarred_tx_id || wallet_pk || amount)
    pub validator_sigs: Vec<FactWitness>,
}

/// Contact information for scar healing propagation.
/// Both fields required: wallet_id for validator lookup, email for delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiverContact {
    /// Receiver's wallet ID (for validator to find the wallet and match FACT chain)
    pub wallet_id: String,
    
    /// Receiver's email (for delivering the ScarRecoveryProof)
    pub email: String,
}

/// Compact witness proof within a FACT link.
/// We don't carry full VBC bundles in every link (too large).
/// Instead: validator_id (derived from VBC) + signature over the transition.
/// The VBC was verified at witness time — this is the receipt of that verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactWitness {
    /// Validator ID = BLAKE3(sphincs_pk) — ties to VBC
    pub validator_id: [u8; 32],
    
    /// Validator's Dilithium (ML-DSA-65) public key (1,952 bytes)
    /// FACT uses Dilithium (not SPHINCS+) because FACT is operational:
    /// signed every transaction, needs speed (~1ms vs ~100ms).
    /// Still quantum-resistant. VBC keeps SPHINCS+ for ceremonial signing.
    pub validator_pk: Vec<u8>,
    
    /// Dilithium signature over BLAKE3("AXIOM_FACT" || tx_id || previous_state_id || new_state_id || amount)
    /// 3,309 bytes (ML-DSA-65)
    pub signature: Vec<u8>,

    /// L5: VBC genesis anchor — chain of SPHINCS+ PKs from this validator's
    /// VBC back to ROOT_AUTHORITY_PKS. Proves the validator traces to genesis.
    /// None during bootstrap / dev mode. Populated by CL3 from VBC chain.
    #[serde(default)]
    pub vbc_genesis_anchor: Option<Vec<[u8; 32]>>,
}

/// Nabla confirmation stub — full definition in YPX-002.
/// Proves this transaction was registered and verified by the Nabla network.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NablaConfirmation {
    /// Nabla node that confirmed this transaction.
    ///
    /// This is the Nabla node's Ed25519 public key — the same key
    /// used to verify `nabla_signature`. Despite the field name "id"
    /// (kept for wire-format stability), it is a public key.
    #[serde(with = "conf_bytes32")]
    pub nabla_node_id: [u8; 32],

    /// Nabla node's signature over the confirmation
    #[serde(with = "conf_bytes")]
    pub nabla_signature: Vec<u8>,

    /// Merkle root at time of confirmation
    #[serde(with = "conf_bytes32")]
    pub root_hash: [u8; 32],

    /// TARDIS tick at confirmation time
    pub synced_to_tick: u64,

    /// Nabla TARDIS tick at the moment the writer's SMT committed
    /// `new_state_id` for this wallet.  Signed by the writer as part
    /// of `nabla_signature` (the signing payload is V2 — see
    /// `nabla/src/crypto.rs::fact_confirm_payload` / Core's matching
    /// recompute in `fact.rs::verify_fact_link`).
    ///
    /// **Used by CL5 redeem:** the redeem of any cheque whose sender
    /// FACT-chain tip carries a `NablaConfirmation` MUST satisfy
    /// `current_tick > committed_at_tick` (≥ 1 tick gap).  This
    /// closes the same-tick "commit-and-immediately-redeem" race
    /// where a receiver could redeem before the sender's commit
    /// had propagated through Nabla's mesh.  See YP §17.10.5.3.
    ///
    /// Scarred links (no Nabla confirmation at all) carry no such
    /// field — the check doesn't apply and Ark-mode operation
    /// continues unchanged.
    #[serde(default)]
    pub committed_at_tick: u64,

    // ── NBC trust-anchor (KI#8 strengthening, 2026-05-15) ──
    //
    // Three fields that bind `nabla_node_id` to a `NABLA_ROOT_AUTHORITY_PKS`
    // issuer via a SPHINCS+ NBC signature. Mirrors the pattern used by
    // `NablaTxidAttestation`, `ChequeClaimProof`, and `ClaraAttestation`
    // (see `validation.rs::verify_nbc_for_*`). Without these, Core's
    // `verify_fact_link` can only check the math on the Ed25519 sig but
    // NOT that the signer is an authorized Nabla node — a compromised
    // SDK could synthesize confs from arbitrary keypairs and pass.
    //
    // **Pre-mainnet:** `#[serde(default)]` keeps legacy wallet.cbor files
    // loading (empty bytes default). `verify_fact_link` treats all-empty
    // NBC fields as "out-of-band trust" (the conf came from a real
    // Nabla TCP session via register_with_nabla; SDK never synthesizes)
    // and proceeds. **Mainnet:** flip the hard-reject on NBC absence —
    // tracked in `AXIOM_REPORT_KnownIssues.md` KI#8.
    /// SPHINCS+ public key of the root authority that issued the NBC.
    /// MUST be in `NABLA_ROOT_AUTHORITY_PKS` when NBC verification fires.
    #[serde(default, with = "conf_bytes", skip_serializing_if = "Vec::is_empty")]
    pub nbc_issuer_pk: Vec<u8>,

    /// SPHINCS+ signature by `nbc_issuer_pk` over `BLAKE3(nbc_commitment)`.
    #[serde(default, with = "conf_bytes", skip_serializing_if = "Vec::is_empty")]
    pub nbc_signature: Vec<u8>,

    /// Canonical pre-image bytes signed by the NBC issuer. The Nabla
    /// node's Ed25519 pubkey (`nabla_node_id` in this struct) MUST
    /// appear as a 32-byte window inside this blob — that binding
    /// catches Ed25519 substitution attacks where the attacker reuses
    /// a legit NBC commitment but swaps the signing key (Phase 5f
    /// fix pattern; see `validation.rs::verify_nbc_for_txid_attestation`).
    #[serde(default, with = "conf_bytes", skip_serializing_if = "Vec::is_empty")]
    pub nbc_commitment: Vec<u8>,
}

// Byte-serde shims for `NablaConfirmation` so ciborium emits canonical CBOR
// byte-strings (major type 2) for the node id / signature / root hash / NBC
// blobs instead of an Array<Integer> (major type 4). Without these, serde's
// default `[u8; 32]` / `Vec<u8>` handling produces a u8 array — bloating the
// FACT chain and forcing every consumer (SDK / Nabla) to hand-coerce.
//
// `NablaConfirmation` is EXCLUDED from every cryptographic hash — it is not in
// `compute_fact_commitment`, nor in the Ed25519 confirm payload — so changing
// only its on-wire byte representation is crypto-transparent (no CoreID-bearing
// commitment moves).
//
// Both shims keep the decode forgiving (accept Bytes OR Array-of-int) so a
// chain serialized by an older binary — or a Nabla response that still emits an
// integer array — round-trips cleanly. Mirrors the bundled `serde_bytes` shim
// in `envelope.rs`.
mod conf_bytes {
    use alloc::vec::Vec;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str("a byte string or array of bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, b: &[u8]) -> Result<Self::Value, E> {
                Ok(b.to_vec())
            }
            fn visit_byte_buf<E: serde::de::Error>(self, b: Vec<u8>) -> Result<Self::Value, E> {
                Ok(b)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(b) = seq.next_element::<u8>()? { out.push(b); }
                Ok(out)
            }
        }
        d.deserialize_byte_buf(V)
    }
}

mod conf_bytes32 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    fn fill32<E: serde::de::Error>(b: &[u8]) -> Result<[u8; 32], E> {
        if b.len() != 32 {
            return Err(E::invalid_length(b.len(), &"exactly 32 bytes"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(b);
        Ok(out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = [u8; 32];
            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str("a 32-byte string or array of 32 bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, b: &[u8]) -> Result<Self::Value, E> {
                fill32(b)
            }
            fn visit_byte_buf<E: serde::de::Error>(self, b: alloc::vec::Vec<u8>) -> Result<Self::Value, E> {
                fill32(&b)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; 32];
                let mut n = 0usize;
                while let Some(b) = seq.next_element::<u8>()? {
                    if n < 32 { out[n] = b; }
                    n += 1;
                }
                if n != 32 {
                    return Err(serde::de::Error::invalid_length(n, &"exactly 32 bytes"));
                }
                Ok(out)
            }
        }
        d.deserialize_byte_buf(V)
    }
}

/// FACT checkpoint — compressed history signed by k=3 validators.
/// Replaces N verified links with a single hash commitment.
/// Scarred links CANNOT be included in a checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactCheckpoint {
    /// Hash of all compressed links: BLAKE3(link_1 || link_2 || ... || link_n)
    pub root_hash: [u8; 32],
    
    /// Number of links compressed into this checkpoint
    pub compressed_count: u64,
    
    /// State ID at the end of the compressed section
    /// (= new_state_id of the last compressed link)
    pub final_state_id: [u8; 32],
    
    /// Genesis state ID (= previous_state_id of the first link ever)
    /// Proves the chain starts at genesis
    pub genesis_state_id: [u8; 32],
    
    /// Total amount that flowed through the compressed links
    /// (for audit: sum of all link amounts)
    pub total_amount: u64,
    
    /// Genesis fact hash (YPX-011): BLAKE3 of FACT #0.
    /// Propagated through every compression — never dropped.
    /// Proves this money traces back to the genesis headlines.
    #[serde(default)]
    pub genesis_fact_hash: [u8; 32],

    /// k=3 validator signatures over the checkpoint commitment
    /// BLAKE3("AXIOM_FACT_CHECKPOINT" || root_hash || compressed_count || final_state_id || genesis_state_id)
    pub validator_sigs: Vec<FactWitness>,

    /// SEC-07 travel-model: number of leading links in `chain.links` that this
    /// checkpoint covers and is still RETAINING (provisional state). While
    /// `pending_links > 0`, the covered links are physically present and the
    /// checkpoint is a proposal accumulating distinct validator co-signatures;
    /// the chain verifies through the real links, not the summary. When the
    /// proposal reaches `CHECKPOINT_SIG_THRESHOLD` distinct sigs, those links are
    /// deleted and `pending_links` becomes 0 (finalized) — only then is the k=5
    /// sig gate enforced. Deliberately NOT folded into `compute_checkpoint_commitment`:
    /// the committed bytes (root_hash, sigs) MUST stay identical across the
    /// provisional→finalized transition. Not forgeable — the committed `root_hash`
    /// pins the covered links, so a lying `pending_links` fails the
    /// `compute_checkpoint_root(links[0..pending_links]) == root_hash` check.
    pub pending_links: u64,
}

/// Complete FACT chain carried by a wallet/cheque.
/// Proves money provenance from genesis to current holder.
///
/// Structure: [checkpoint?] → [link_0] → [link_1] → ... → [link_n]
/// Max 5 uncompressed links. Checkpoint covers everything before.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FactChain {
    /// Compressed history (None for wallets with ≤5 transactions)
    pub checkpoint: Option<FactCheckpoint>,
    
    /// Recent uncompressed links (max 5)
    /// Ordered oldest→newest. Last link = most recent transaction.
    #[serde(default)]
    pub links: Vec<FactLink>,
}

impl FactChain {
    /// Create empty FACT chain (for genesis wallets)
    pub fn new() -> Self {
        Self { checkpoint: None, links: Vec::new() }
    }
    
    /// Current chain depth (uncompressed links only)
    pub fn depth(&self) -> usize {
        self.links.len()
    }
    
    /// Whether this chain has any scarred (unconfirmed and unburned) links
    /// Check for real scars. A link is scarred only if it has no
    /// nabla_confirmation AND fewer witnesses than its required_k.
    /// A link with witnesses.len() >= required_k was fully committed —
    /// the missing confirmation is from chain replacement, not a partial.
    pub fn has_scars(&self) -> bool {
        self.links.iter().any(|l| {
            l.nabla_confirmation.is_none()
                && l.burn_proof.is_none()
                && l.witnesses.len() < l.required_k as usize
        })
    }

    /// Whether compression is needed (depth > 5)
    pub fn needs_compression(&self) -> bool {
        self.links.len() > 5
    }

    /// Count real scars. witnesses.len() < required_k = partial = real scar.
    pub fn scar_count(&self) -> usize {
        self.links.iter().filter(|l| {
            l.nabla_confirmation.is_none()
                && l.burn_proof.is_none()
                && l.recall_proof.is_none()  // YPX-022: a recalled link is resolved
                && l.witnesses.len() < l.required_k as usize
        }).count()
    }
    
    /// The latest state_id in the chain (tip of provenance)
    pub fn tip_state_id(&self) -> Option<[u8; 32]> {
        self.links.last().map(|l| l.new_state_id)
    }
    
    /// The genesis origin state_id
    pub fn genesis_state_id(&self) -> Option<[u8; 32]> {
        if let Some(ref cp) = self.checkpoint {
            Some(cp.genesis_state_id)
        } else {
            self.links.first().map(|l| l.previous_state_id)
        }
    }
}

/// Self-verifying proof that a FACT scar has been healed.
/// Delivered via email by EITHER the validator OR the client app.
/// Receiver's validator verifies independently — doesn't matter who sent it.
///
/// This is like a mini-cheque: it carries enough information for any
/// validator to verify the healing without trusting the messenger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScarRecoveryProof {
    /// The original transaction ID whose FACT link was scarred
    pub original_tx_id: [u8; 32],
    
    /// Nabla confirmation that healed the scar
    pub nabla_confirmation: NablaConfirmation,
    
    /// k=3 validator signatures over the healing
    /// Signs: BLAKE3("AXIOM_SCAR_HEAL" || original_tx_id || nabla_node_id || root_hash)
    /// These validators verified the Nabla confirmation is real
    pub healing_witnesses: Vec<FactWitness>,
    
    /// The receiver's wallet_id (so their validator can find the right wallet)
    pub receiver_wallet_id: String,
    
    /// The FACT link index in the receiver's chain that should be healed
    /// (receiver's validator matches by tx_id, this is a hint)
    pub fact_link_index: Option<u32>,
}

// ============================================================================
// CHEQUE MODEL - Correct 6-validator implementation
// ============================================================================
//
// Flow:
// 1. Sender contacts k validators (V_A, V_B, V_C)
// 2. Each validator sends ONE ValidatorCheque to receiver
// 3. Receiver collects k ValidatorCheques into a ChequeBundle
// 4. Receiver brings ChequeBundle to THEIR k validators (V_X, V_Y, V_Z)
// 5. Receiver's validators verify bundle and sign new state
// 6. Receiver sends ACK + ConfirmationCheque back to sender's validators
// 7. (v3.x): validator fees settle direct-deposit at CL5 redeem; per-validator
//    earnings live on Nabla. See docs/AXIOM_DESIGN_ValidatorFeeLedger.md.
//
// Total: 6 validators involved (k=3 case)
// ============================================================================

/// A single validator's cheque
/// 
/// Each validator who witnesses the sender's transaction creates ONE of these
/// and sends it to the receiver (via ANTIE/email).
/// 
/// The receiver must collect k of these (from k different validators) before
/// they can redeem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorCheque {
    /// Transaction ID this cheque is for
    pub txid: [u8; 32],
    
    /// Validator's unique identifier (derived from VBC)
    pub validator_id: [u8; 32],
    
    /// The validator who issued this cheque
    pub validator_pk: Vec<u8>,
    
    /// Validator's signature over the cheque commitment.
    /// Signs: BLAKE3("AXIOM_CHEQUE" || txid || state_hash || produced_state_id
    ///        || receiver_wallet_id || amount || epoch || rate_bps_le
    ///        || dmap_input_hash || dmap_output_hash || optional ORACLE block).
    ///
    /// `rate_bps` is bound into the commitment so the receiver's Core CL5
    /// can read each cheque's authoritative rate at redeem time and
    /// compute `total_fee` deterministically without trusting any
    /// client-supplied proposal (closes the
    /// `E_RECEIPT_COMMITMENT_MISMATCH` class — see commit landing
    /// 2026-06-05 PM). Pre-mainnet, the cheque commitment has no
    /// version tag; there is exactly one format — CLAUDE.md §13.
    pub signature: Vec<u8>,
    
    /// Execution proof (deterministic or ZKP)
    pub execution_proof: Vec<u8>,
    
    /// Validator Birth Certificate bundle
    #[serde(default)]
    pub vbc_bundle: Option<VBCProofBundle>,
    
    /// Carrier type (how to reach this validator)
    /// e.g., "email", "swift", "https"
    pub carrier_type: String,
    
    /// Carrier address (endpoint for this validator)
    /// e.g., "validator-alpha@axiom.network", "AXIOMVAL1XXX"
    pub carrier_address: String,
    
    /// Sender's wallet_id (for reference)
    pub sender_wallet_id: String,
    
    /// Receiver's wallet_id (who can redeem this)
    pub receiver_wallet_id: String,
    
    /// Amount in atoms
    pub amount: u64,

    /// This validator's receiver-pays fee rate, in basis points.
    /// Capped at `MAX_VALIDATOR_FEE_BPS` (30) by Core CL5 via
    /// `expected_fee_slot_amount`. Bound into the cheque commitment
    /// signature — clients cannot tamper with it post-issuance.
    ///
    /// Core CL5 sums `expected_fee_slot_amount(c.amount, c.rate_bps)`
    /// across the k cheques in a bundle to derive `total_fee` →
    /// `new_balance` → `state_hash` / `produced_state_id` deterministically.
    /// The pre-2026-06-05 design routed the proposal through the
    /// client (`RedeemRequestEnvelope.fee_breakdown`), which let a
    /// stale client `validators.list` create a divergence between
    /// the receipt's NET binding and the validator's signed
    /// slot_amount — closed in this commit.
    pub rate_bps: u32,

    /// Payment reference
    pub reference: String,
    
    /// Transaction epoch
    pub epoch: u64,
    
    /// When this cheque was created
    pub created_at: u64,
    
    /// State hash from validator's witness
    pub state_hash: [u8; 32],
    
    /// Produced state ID (sender's new state)
    pub produced_state_id: [u8; 32],
    
    /// Sender's FACT chain — money provenance (YPX-001 §1.6)
    /// Each validator independently attaches the sender's FACT chain to
    /// the cheque they send to the receiver. All 3 cheques carry the same
    /// chain (redundant for survivability). Receiver can cross-verify that
    /// all 3 copies match as additional client-side security.
    /// Core verifies chain integrity at redeem time (CL5).
    pub sender_fact_chain: Option<FactChain>,

    /// ZKP nonce used during proof generation (for receiver-side replay check)
    #[serde(default)]
    pub zkp_nonce: Option<[u8; 32]>,

    /// Proof type discriminator: 0 = ZKP (STARK), 1 = DMAP (attestation)
    /// Defaults to 0 for backward compatibility with existing cheques.
    #[serde(default)]
    pub proof_type: u8,

    /// DMAP input hash — BLAKE3 of serialized PublicInputs at proof production time.
    /// Used by receiver to verify attestation binds to the correct transaction (GAP-B fix).
    /// Cheque signature covers this field — tampering invalidates the cheque.
    #[serde(default)]
    pub dmap_input_hash: [u8; 32],

    /// DMAP output hash — BLAKE3 of serialized PublicOutputs at proof production time.
    #[serde(default)]
    pub dmap_output_hash: [u8; 32],

    /// YPX-022 RECALL (2026-07-06 forward redesign): `Some(T)` when this cheque is the
    /// recall cheque re-issuing failed send `T`'s amount back to the sender. Lambda
    /// stamps it (from the verified recall) at witness time and it is BOUND into the
    /// cheque commitment (non-zero suffix), so a client cannot forge it. Core CL5 reads
    /// it to exempt the genesis-claim replay guard (a recall cheque of exactly
    /// GENESIS_CLAIM_AMOUNT is NOT an airdrop), and it is the SDK's `is_recall_cheque`
    /// discriminator. `None` for every non-recall cheque → commitment byte-identical.
    #[serde(default)]
    pub recall_target_tx_id: Option<[u8; 32]>,

    /// YPX-012: Oracle claim data (if this cheque is for an oracle TX).
    /// Presence triggers 48h maturity check at CL5 redeem.
    #[serde(default)]
    pub oracle_claim: Option<OracleClaimData>,

    /// Nabla hint — sender's preferred Nabla node for receiver verification (YPX-003 §2.16.5).
    /// Optional performance hint: receiver tries this node first before querying random 3.
    /// Not signed, not verified — purely informational. If node is dead, receiver falls back.
    /// Sender includes this after S-ABR round 1, before final validator witnesses.
    #[serde(default)]
    pub nabla_hint: Option<NablaHint>,

    /// YPX-002 §4.6 — sender's raw Ed25519 wallet public key.
    ///
    /// This is the 32-byte value the sender registered with Nabla (Nabla's SMT
    /// is keyed on it), and it is the `wallet_pk` query parameter the receiver
    /// hands to `/query` when running the §4.6 verification routine. The
    /// existing `sender_wallet_id` field is the email-format identifier used
    /// by Lambda for storage and Ark rule enforcement; it is NOT a valid Nabla
    /// lookup key, so a receiver that has only `sender_wallet_id` cannot run
    /// §4.6 at all. This field closes that gap.
    ///
    /// Pass-through only: Core never validates it and the cheque commitment
    /// signature does not cover it (the same unsigned-advisory contract as
    /// `nabla_hint`). Lambda stamps it from `transaction.client_pk` at witness
    /// issuance. `Option` so pre-§4.6 cheques still deserialize; receivers
    /// MUST fall back to best-effort behaviour when the field is absent.
    #[serde(default)]
    pub sender_wallet_pk: Option<[u8; 32]>,
}

/// Fan-out diffusion message for CL10 verification (§18.8).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FanOutMessage {
    pub diffusion_id: [u8; 32],
    pub content_type: u16,
    pub content: Vec<u8>,
    pub originator_pk: [u8; 32],
    pub originator_sig: Vec<u8>,
    pub timestamp: u64,
    pub ttl_original: u8,
    pub fanout: u8,
    pub ttl_current: u8,
}

/// Signed proof of validator stake for CL8 VBC approval (§25.5.4).
/// Two components: Nabla attestation (state is current) + k=3 receipt (balance at state).
/// Core verifies both independently. No Lambda in the trust chain.
///
/// Nabla txid attestation — proves a txid has NOT been redeemed globally.
///
/// The CLIENT queries Nabla before submitting a redeem request.
/// Nabla responds with a signed attestation: "this txid is not in my index."
/// The client includes this attestation in the redeem request.
/// Lambda VERIFIES the signature (never queries Nabla directly).
///
/// Architecture: Client fetches, validator verifies. Same pattern as NablaStakeProof.
/// Lambda MUST NOT talk to Nabla directly (except TARDIS requests via Core).
///
/// Freshness: the `nabla_tick` field lets Lambda reject stale attestations.
/// A txid could be registered between the attestation and the redeem — but the
/// LOCAL try_mark_cheque_redeemed() catches same-validator replays, and the
/// attestation catches cross-validator replays with bounded staleness.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NablaTxidAttestation {
    /// The txid being attested.
    pub txid: [u8; 32],
    /// Attestation status: "NOT_REDEEMED" or "REDEEMED".
    pub status: String,
    /// If REDEEMED: which wallet registered it. Empty if NOT_REDEEMED.
    #[serde(default)]
    pub registered_by: Vec<u8>,
    /// Nabla node's Ed25519 public key (for signature verification).
    pub nabla_node_pk: [u8; 32],
    /// Nabla node's signature over:
    /// BLAKE3("AXIOM_TXID_ATTEST" || txid || status_bytes || tick_le)
    pub nabla_signature: Vec<u8>,
    /// Nabla tick at attestation time (freshness check).
    pub nabla_tick: u64,
    /// Txid service mode of the attesting node ("bloom" or "hashmap").
    #[serde(default)]
    pub txid_service: String,
    /// NBC issuer SPHINCS+ public key (32 bytes for SLH-DSA-SHA2-128s).
    /// Extracted from the Nabla node's NBC issuer_set[0].
    /// Core checks: is_nabla_root_authority(pk) → must be in NABLA_ROOT_AUTHORITY_PKS.
    #[serde(default)]
    pub nbc_issuer_pk: Vec<u8>,
    /// NBC SPHINCS+ signature over the VBC commitment (7,856 bytes for SLH-DSA-SHA2-128s).
    /// Extracted from the Nabla node's NBC signatures[0].
    /// Core verifies: verify_sphincs(issuer_pk, commitment, signature) → valid.
    #[serde(default)]
    pub nbc_signature: Vec<u8>,
    /// VBC signing payload — 32-byte BLAKE3 hash (pre-computed by Nabla).
    /// Computed by crypto::compute_vbc_signing_payload(&nbc):
    ///   BLAKE3("AXIOM_VBC_V1" || validator_id || sphincs_pk || dilithium_pk
    ///          || ed25519_pk || version || role || chain_depth || issuer_count
    ///          || issued_at || expires_at || max_tx || founding_vbc_hash)
    /// The ed25519_pk is included — this binds the commitment to the attester's key.
    /// If an attacker substitutes a different Ed25519 PK, the commitment won't match.
    #[serde(default)]
    pub nbc_commitment: Vec<u8>,
}

/// Nabla-signed OODS reading (YPX-021 §8.2) — carries the attesting node's
/// CURRENT network-size estimate plus its NBC baseline to Core, which
/// verifies it and stamps the derived `OodsFlag` into the receipt.
///
/// Trust model (Phase 1): the reading is Ed25519-signed by a Nabla whose
/// NBC chains to a `NABLA_ROOT_AUTHORITY_PKS` issuer (same anchor pattern
/// as `NablaTxidAttestation`), and the claimed baseline is bound into that
/// NBC's issuer-signed pre-image (suffix check — see
/// `validation::verify_oods_attestation`). An honestly-eclipsed Nabla
/// therefore cannot report a healthy size; a MALICIOUS Nabla lying about
/// its live estimate is priced by the Phase-2 §5 recomputation (CL14,
/// blocked on Core-mediated tick signing) — Phase 1 closes the wash-out
/// for the honest-but-eclipsed case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NablaOodsAttestation {
    /// Rounded current OODS network-size estimate of the attesting node.
    pub oods_size: u32,
    /// TARDIS tick of the reading.
    pub tick: u64,
    /// The attesting node's NBC baseline (§7). 0 = genesis-exempt cert.
    pub baseline_size: u32,
    /// Tick at which the baseline was stamped by the NBC issuer.
    pub baseline_tick: u64,
    /// Nabla node's Ed25519 public key (verifies `nabla_signature`).
    pub nabla_node_pk: [u8; 32],
    /// Ed25519 signature over `compute_oods_attestation_payload(...)`:
    /// BLAKE3("AXIOM_OODS_ATTEST" || oods_size || tick || baseline_size
    ///        || baseline_tick).
    pub nabla_signature: Vec<u8>,
    /// NBC issuer SPHINCS+ public key — must be in NABLA_ROOT_AUTHORITY_PKS.
    pub nbc_issuer_pk: Vec<u8>,
    /// NBC SPHINCS+ signature over BLAKE3(nbc_commitment).
    pub nbc_signature: Vec<u8>,
    /// The NBC signing-payload PRE-IMAGE bytes
    /// (`compute_vbc_signing_payload_bytes`). Binds `nabla_node_pk` (window
    /// check) and, when `baseline_size != 0`, the baseline (suffix check).
    pub nbc_commitment: Vec<u8>,
}

/// YPX-022 RECALL — Nabla-writer-signed proof that a `register_recall` landed for
/// this txid (the consume-once completed). Core CL2 requires it on a RECALL self-send
/// before restoring the sender's pre-send balance. It proves ONLY "this txid was
/// recalled"; the restore TARGET (the failed send's pre-send state) is bound separately
/// by Core via the txid hash (§2.1), never by this attestation — a hostile Nabla can
/// withhold a recall but can never forge a favourable restore.
///
/// Domain tag: `BLAKE3("AXIOM_RECALL_ATTEST" || txid || recall_tick_le)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecallAttestation {
    /// The recalled txid (the failed sub-quorum send being reclaimed).
    pub txid: [u8; 32],
    /// The pre-send state the recalled send consumed (= its `consumed_state_id`).
    /// Nabla stamps this AFTER verifying `hash(failed_send_tx) == txid` at
    /// `register_recall`, so it is authoritatively bound to the recalled txid (the
    /// sender cannot substitute a higher-balance state — it wouldn't hash to `txid`).
    /// Core CL2 restores the wallet to EXACTLY this state (§2.1), blocking over-reclaim.
    pub presend_state_hash: [u8; 32],
    /// The failed send's amount `A`, Nabla-stamped from `failed_send_tx.amount` at
    /// `register_recall` (after verifying `hash(failed_send_tx) == txid`). Bound into
    /// the attestation signature, so the recall cheque's value cannot be inflated:
    /// Core CL2 pins `tx.amount == att.amount` (2026-07-06 forward redesign, §2).
    pub amount: u64,
    /// TARDIS tick at which Nabla registered the recall (consume-once landed).
    pub recall_tick: u64,
    /// Nabla node's Ed25519 public key (verifies `nabla_signature`).
    pub nabla_node_pk: [u8; 32],
    /// Ed25519 signature over `compute_recall_attestation_payload(txid, recall_tick)`.
    pub nabla_signature: Vec<u8>,
    /// NBC issuer SPHINCS+ public key — must be in `NABLA_ROOT_AUTHORITY_PKS`.
    pub nbc_issuer_pk: Vec<u8>,
    /// NBC SPHINCS+ signature over `BLAKE3(nbc_commitment)`.
    pub nbc_signature: Vec<u8>,
    /// The NBC signing-payload PRE-IMAGE bytes; binds `nabla_node_pk` (window check).
    pub nbc_commitment: Vec<u8>,
}

/// Nabla-writer-signed proof that the receiver successfully registered a
/// `register_cheque_claim` for this cheque.  Closes the concurrent-replay
/// window the older `NablaTxidAttestation` path leaves open:
/// `register_cheque_claim` is enforced single-writer on Nabla, so the
/// second concurrent attempt fails with CONFLICT and never gets a signed
/// proof.  Core CL5 requires this proof on every redeem.
///
/// See `nabla/src/bin/nabla_node.rs::register_cheque_claim_core` and
/// `docs/AXIOM_DESIGN_PublicMailCarriers.md` (Stream B follow-up).
///
/// Domain tag: `BLAKE3("AXIOM_REDEEM_CLAIM" || cheque_id || "CLAIMED" || tick_le)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChequeClaimProof {
    /// The cheque txid being claimed.  Must match the redeem's bundle txid.
    pub cheque_id: [u8; 32],
    /// Ed25519 pubkey of the receiving wallet — bound by the claim
    /// signature.  Must match the redeem's `receiver_pk`.
    pub client_pk: [u8; 32],
    /// TARDIS tick at which the claim was registered (freshness signal).
    pub claim_tick: u64,
    /// Nabla writer node's Ed25519 pubkey.
    pub nabla_node_pk: [u8; 32],
    /// Ed25519 signature over `BLAKE3("AXIOM_REDEEM_CLAIM" || cheque_id ||
    /// "CLAIMED" || tick_le)`.
    pub nabla_signature: Vec<u8>,
    /// NBC issuer SPHINCS+ pubkey (root authority binding).
    #[serde(default)]
    pub nbc_issuer_pk: Vec<u8>,
    /// NBC SPHINCS+ signature over the VBC commitment.
    #[serde(default)]
    pub nbc_signature: Vec<u8>,
    /// VBC signing payload — pre-image bytes binding the Nabla writer's
    /// Ed25519 pubkey to the root authority's SPHINCS+ signature.
    /// Same shape as `NablaTxidAttestation::nbc_commitment` (Phase 5f
    /// wire format).
    #[serde(default)]
    pub nbc_commitment: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NablaStakeProof {
    // ── Nabla attestation (proves state is current) ──
    /// Nabla reader node's Ed25519 PK
    pub nabla_node_pk: [u8; 32],
    /// Nabla sig over: BLAKE3("AXIOM_NABLA_ATTEST" || wallet_pk || state_id || tick_le)
    pub nabla_signature: Vec<u8>,
    /// State_id that Nabla attests as current for this wallet
    pub attested_state_id: [u8; 32],
    /// Nabla tick at attestation time
    pub nabla_tick: u64,
    /// Role: 0 = reader, 1 = writer. Core EXITS if writer.
    pub nabla_role: u8,

    // ── Balance proof (proves balance at that state) ──
    /// Candidate's wallet Ed25519 PK
    pub wallet_pk: [u8; 32],
    /// Balance at the attested state
    pub balance: u64,
    /// k=3 validator signatures over the state transition
    pub receipt_signatures: Vec<WitnessSig>,
    /// produced_state_id from k=3 receipt (must match attested_state_id)
    pub receipt_state_id: [u8; 32],
    /// Number of scarred (unresolved) FACT links on this wallet at attestation time.
    /// Core rejects oracle witnessing if scar_count > 0.
    /// Reference: YPX-012 §1.2, Yellow Paper §34, YPX-001 §1.5
    #[serde(default)]
    pub scar_count: u32,
}

// =====================================================================
// YPX-018 — CLARA & Tiered Bloom Memory (v2.11.15)
// =====================================================================

/// Three-state result of a Nabla txid lookup (YPX-018 §4.6).
///
/// Replaces the original YPX-014 String status. Distinguishes:
/// - `NotRedeemed` — txid is fresh, redeem may proceed
/// - `Redeemed` — txid is in the txid bloom chain, double-redeem rejected
/// - `PhasedOut` — the bloom era containing this txid was retired by Console action,
///   the cheque is irrevocably dead and the lookup is paired with a `phase_out_cert`
///
/// This enum is wire-stable. Encoded as a small integer in CBOR (0/1/2).
/// Phase 1 introduces the type; Phase 4 wires it into modes.rs and the codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TxidStatus {
    NotRedeemed = 0,
    Redeemed = 1,
    PhasedOut = 2,
}

impl TxidStatus {
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::NotRedeemed),
            1 => Some(Self::Redeemed),
            2 => Some(Self::PhasedOut),
            _ => None,
        }
    }
}

/// CLARA — Client-Led Attested Reality Alignment (YPX-018 §2.2).
///
/// Carries a Nabla-signed proof that a wallet has healed past one or more
/// poisoned states. Allows previously poisoned validators to roll their
/// stored state forward and resume normal witness service.
///
/// **Security model:**
/// - The Nabla signature is verified against the embedded NBC trust anchor
///   (SPHINCS+ root authority — same pattern as `NablaTxidAttestation`).
/// - The `wallet_pk` is bound into the signed message — replay across wallets
///   is impossible.
/// - The receiving validator's stored state for the wallet MUST be exactly one
///   of the entries in `garbage_state_ids`. If not, the attestation is rejected
///   with `E_CLARA_STATE_NOT_GARBAGE`. No multi-step provenance walking.
/// - The validator only ever rolls *forward* — never backward.
///
/// Spec: `docs/AXIOM_YPX-018_HEAL_AND_TIERED_MEMORY.md` §2
/// Yellow Paper: §17.10.14
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaraAttestation {
    /// Healing wallet's public key (Ed25519, 32 bytes).
    /// Bound into the signed message — replay across wallets is impossible.
    pub wallet_pk: [u8; 32],

    /// State the wallet is healing FROM (the pre-broken-TX state, last
    /// known-good state shared by the wallet and Nabla).
    pub healed_from_state_id: [u8; 32],

    /// State the wallet is healing TO (the produced_state_id of the heal
    /// cheque). Validators roll their stored state forward to this value.
    pub healed_to_state_id: [u8; 32],

    /// Wallet sequence at heal point. Validators set their stored seq to this.
    pub healed_at_seq: u64,

    /// YPX-018 Phase 5f Finding 4: canonical post-heal balance.
    ///
    /// A previously poisoned validator's stored balance is wrong (lower than
    /// reality) because it processed a partial TX that was never finalized
    /// k=3-wide. Without this field, CLARA roll-forward only moves the
    /// state_id pointer; the validator's balance stays poisoned and the
    /// validator rejects any subsequent TX larger than its (lowered) stored
    /// balance — a liveness degradation per the Phase 5f audit Finding 4.
    ///
    /// **Cryptographic binding:** the heal cheque's `state_hash` field is
    /// `BLAKE3(wallet_pk || healed_balance || healed_at_seq)` — see
    /// `crypto::compute_state_hash`. The cheque is k=3-witnessed, so each
    /// fresh validator has signed `state_hash` over the canonical post-heal
    /// (balance, seq) pair the wallet declared at heal time. Nabla recomputes
    /// the hash from `(wallet_pk, healed_balance, healed_at_seq)` and verifies
    /// it equals `cheque.state_hash`. If they match, `healed_balance` is
    /// trusted (cryptographically committed by the witnessing validators).
    /// Mismatch → reject the registration.
    ///
    /// Validators (Lambda's `clara_roll_forward`) overwrite their stored
    /// balance with this value during roll-forward. The validator only ever
    /// learns a balance that was already attested by k=3 fresh validators —
    /// no new trust assumption.
    #[serde(default)]
    pub healed_balance: u64,

    /// txid of the heal cheque (TX_HEAL self-cheque).
    pub heal_txid: [u8; 32],

    /// Abandoned states declared garbage by this heal.
    /// A poisoned validator's stored state MUST appear here for roll-forward.
    pub garbage_state_ids: Vec<[u8; 32]>,

    /// Bloom era at heal time (for tier resolution).
    pub bloom_era_id: u64,

    /// Bloom-chain commitment at heal time. Allows the validator to verify
    /// the attestation is anchored to a real era (not a forged era_id).
    pub bloom_era_root: [u8; 32],

    /// Nabla TARDIS tick at attestation time (freshness).
    pub nabla_tick: u64,

    /// Attesting Nabla node's Ed25519 public key.
    pub nabla_node_pk: [u8; 32],

    /// Nabla signature over `compute_clara_message(self)`.
    pub nabla_signature: Vec<u8>,

    // === NBC trust anchor (mirrors NablaTxidAttestation, no_std-compatible) ===
    /// NBC issuer SPHINCS+ public key. Must be in `NABLA_ROOT_AUTHORITY_PKS`.
    #[serde(default)]
    pub nbc_issuer_pk: Vec<u8>,
    /// NBC SPHINCS+ signature over the VBC commitment.
    #[serde(default)]
    pub nbc_signature: Vec<u8>,
    /// VBC signing payload binding `nabla_node_pk`.
    #[serde(default)]
    pub nbc_commitment: Vec<u8>,
}

/// Status of a single bloom era in the Bloom Age Index (YPX-018 §3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EraStatus {
    /// Currently accepting writes. Exactly one era is Active at any time.
    Active,
    /// Closed; bloom file is immutable. Can be queried but not modified.
    Frozen,
    /// Console-approved phase-out scheduled. Queries return real answers
    /// during the grace period, tagged with a phase-out warning.
    ScheduledPhaseOut {
        effective_tick: u64,
        console_cert_hash: [u8; 32],
    },
    /// Phase-out has taken effect. Archive nodes are FREE to drop the era's
    /// full hash records. The age-index entry remains forever for auditability.
    PhasedOut {
        effective_tick: u64,
        console_cert_hash: [u8; 32],
    },
}

/// One era in the bloom chain (YPX-018 §3.3).
///
/// Each era covers a TARDIS tick range (default 90 days = quarterly).
/// Both the txid bloom and the garbage state bloom share the same era
/// metadata, so an era is the unit of phase-out for both chains.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloomEra {
    /// Monotonic era id. Increments when an era closes and the next opens.
    pub era_id: u64,

    /// First TARDIS tick in this era's range (inclusive).
    pub start_tick: u64,

    /// First TARDIS tick of the *next* era (exclusive).
    /// `end_tick - start_tick == ERA_DURATION_TICKS` for all eras.
    pub end_tick: u64,

    /// BLAKE3 root of the txid bloom file at era close (zero if Active).
    pub txid_bloom_root: [u8; 32],

    /// BLAKE3 root of the garbage state bloom file at era close (zero if Active).
    pub garbage_bloom_root: [u8; 32],

    /// Exact entry counts at era close (for FPR computation by light nodes).
    pub txid_count: u64,
    pub garbage_count: u64,

    /// Era status — drives query semantics and Console phase-out lifecycle.
    pub status: EraStatus,

    /// Optional list of archive node IDs known to hold this era's full
    /// hash records. Used as a routing hint when bloom hits need archive
    /// resolution. Not authoritative — any node may volunteer to archive.
    #[serde(default)]
    pub archive_nodes: Vec<[u8; 32]>,
}

/// Console proposal payload for a `BLOOM_PHASE_OUT` action (YPX-018 §4.2,
/// YPX-013 §5.5).
///
/// Validated by Core CL11 against the constitutional limits in
/// `console::MIN_PHASE_OUT_AGE_TICKS` and `console::MIN_PHASE_OUT_GRACE_TICKS`.
/// The Console cannot override those limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleProposalBloomPhaseOut {
    /// Bloom eras scheduled for phase-out. Each must satisfy the
    /// constitutional minimum age check in CL11 §6.2.3.
    pub era_ids: Vec<u64>,

    /// TARDIS tick at which phase-out becomes effective.
    /// Must be at least `MIN_PHASE_OUT_GRACE_TICKS` after proposal approval.
    pub effective_tick: u64,

    /// Human-readable rationale (storage pressure, archive coverage, etc.).
    /// Not validated by Core; surfaced in Console UI.
    pub rationale: String,
}

// === Fan-Out Protocol Constants (§18.8) ===

pub const FANOUT_MAX_TTL: u8 = 10;
pub const FANOUT_MAX_FANOUT: u8 = 3;
pub const FANOUT_MAX_CONTENT_BYTES: usize = 65536;
pub const FANOUT_MAX_AGE_SECS: u64 = 86400;
pub const FANOUT_FUTURE_TOLERANCE_SECS: u64 = 60;

// Fan-out content type constants (§18.8)
pub const FANOUT_JFP_FREEZE_REQUEST: u16 = 0x0001;
pub const FANOUT_JFP_VOTE: u16 = 0x0002;
pub const FANOUT_JFP_RESULT: u16 = 0x0003;
pub const FANOUT_DWP_QUERY: u16 = 0x0010;
pub const FANOUT_DWP_RESPONSE: u16 = 0x0011;
pub const FANOUT_DWP_STAMP: u16 = 0x0012;
pub const FANOUT_CONSOLE_APPOINTMENT: u16 = 0x0100;
pub const FANOUT_CONSOLE_RESIGNATION: u16 = 0x0101;
/// YPX-013: Console election announcement — "Election open, submit nominations"
pub const FANOUT_CONSOLE_ELECTION: u16 = 0x0102;
/// YPX-013: Console election result — new ConsoleCertificate or dissolution
pub const FANOUT_CONSOLE_RESULT: u16 = 0x0103;
/// C1: Canonical Reality Attestation — 2-of-3 Genesis Root Authority declares canonical chain.
pub const FANOUT_REALITY_ATTESTATION: u16 = 0x0200;

/// C1: Reality Attestation — resolves mirror worldline forks.
/// Signed by Root Authority SPHINCS+ keys (same keys that signed genesis VBCs).
/// 2-of-3 attestations constitute consensus on which genesis chain is canonical.
/// Broadcast via CL10 Fan-Out. Validators verify against ROOT_AUTHORITY_PKS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealityAttestation {
    /// BLAKE3 hash of the canonical FACT #0 (proves which genesis is real).
    pub canonical_genesis_hash: [u8; 32],
    /// Root Authority index (0, 1, or 2) — which of the 3 root keys signed this.
    pub root_authority_index: u8,
    /// Root Authority SPHINCS+ public key (32 bytes, must match ROOT_AUTHORITY_PKS).
    pub root_authority_pk: Vec<u8>,
    /// SPHINCS+ signature over BLAKE3("AXIOM_CANONICAL" || canonical_genesis_hash || tick).
    pub signature: Vec<u8>,
    /// TARDIS tick when attestation was produced.
    pub tick: u64,
}

// H4: VBC renewal cartel is not a real problem at scale. If a validator is rejected
// by some validators, they try others from their hint table or discover new ones
// via VSP. Hundreds of validators exist. No genesis special authority needed.
pub const FANOUT_VALIDATOR_GOSSIP: u16 = 0x0201;
pub const FANOUT_VBC_ANNOUNCEMENT: u16 = 0x0202; // AUDIT-FIX: was 0x0201 (collision with VALIDATOR_GOSSIP)

// ── Validator Stake Tier Constants (§10, §25.5) ──
/// Tier 1 (Genesis) validators must hold 1,000,000 AXC
pub const TIER1_MIN_STAKE: u64 = 1_000_000;
/// Tier 2 (Foundation) requires 500,000 AXC — only approved by Genesis
pub const TIER2_MIN_STAKE: u64 = 500_000;
/// Tier 3 (Community) requires 500 AXC — standard onboarding
pub const TIER3_MIN_STAKE: u64 = 500;

/// Check whether a content type is a known fan-out content type.
pub fn is_known_fanout_content_type(ct: u16) -> bool {
    matches!(ct, 0x0001..=0x0003 | 0x0010..=0x0012 | 0x0100..=0x0103 | 0x0200..=0x0202)
}

/// Sender's preferred Nabla node hint for receiver cheque verification.
/// Contains both IP:port (fast, works across partitions) and node name
/// (permanent NBC identity, fallback when IP changes — citizen nodes have dynamic IPs).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NablaHint {
    /// Node name from NBC (permanent identity, e.g. "nabla-tokyo-42")
    pub node_name: String,
    /// Current IP:port at registration time (e.g. "85.123.45.67:6225")
    pub address: String,
}

/// A bundle of k ValidatorCheques
/// 
/// Receiver collects these from sender's validators, then brings the
/// entire bundle to their own validators for redemption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChequeBundle {
    /// The k cheques (one from each of sender's validators)
    /// All must have same: txid, receiver_wallet_id, amount, epoch
    pub cheques: Vec<ValidatorCheque>,
    
    /// Sender's FACT chain — money provenance (YPX-001)
    /// 
    /// AUTHORITATIVE SOURCE: Each ValidatorCheque.sender_fact_chain carries
    /// the sender's FACT chain independently (redundant for survivability).
    /// This field is a CONVENIENCE copy extracted by the receiver when
    /// assembling the bundle. Core CL5 uses this field for verification.
    /// 
    /// Client-side security note: Receivers MAY cross-verify that all 3
    /// ValidatorCheque.sender_fact_chain copies are identical. Mismatch
    /// indicates validator corruption. (Not protocol-enforced — future
    /// client implementation.)
    pub fact_chain: Option<FactChain>,
}

impl ChequeBundle {
    /// Verify bundle consistency (all cheques match AND from distinct validators)
    pub fn verify_consistency(&self) -> bool {
        if self.cheques.is_empty() {
            return false;
        }

        let first = &self.cheques[0];

        // Check all cheques have matching fields.
        //
        // YPX-018 Phase 5f Finding 5: also check sender_wallet_id consistency.
        // The cheque commitment binds `receiver_wallet_id` but not
        // `sender_wallet_id`. Without this consistency check, an attacker
        // could splice cheques from different senders into the same bundle
        // (the per-cheque signatures still verify; only the cross-cheque
        // consistency catches it). For CLARA specifically, the authoritative
        // tx-binding (compute_txid match) closes the exploit, but adding the
        // consistency check here is defense-in-depth and harmless to all
        // existing flows (every legitimate bundle already has matching
        // sender_wallet_id across cheques). If the cheque commitment is
        // ever extended to include `sender_wallet_id`, this consistency
        // check becomes redundant; until then, keep it.
        let fields_match = self.cheques.iter().all(|c| {
            c.txid == first.txid
                && c.sender_wallet_id == first.sender_wallet_id
                && c.receiver_wallet_id == first.receiver_wallet_id
                && c.amount == first.amount
                && c.epoch == first.epoch
        });

        if !fields_match {
            return false;
        }

        // Check all cheques are from DISTINCT validators
        // This prevents replay attacks where same validator's cheque is duplicated
        self.has_distinct_validators()
    }
    
    /// Check that all cheques are from distinct validators
    /// Uses validator_id (derived from VBC) for uniqueness
    pub fn has_distinct_validators(&self) -> bool {
        use alloc::collections::BTreeSet;
        
        let mut seen_validators: BTreeSet<[u8; 32]> = BTreeSet::new();
        
        for cheque in &self.cheques {
            // If we've seen this validator_id before, not distinct
            if !seen_validators.insert(cheque.validator_id) {
                return false;
            }
        }
        
        true
    }
    
    /// Get the common txid
    pub fn txid(&self) -> Option<[u8; 32]> {
        self.cheques.first().map(|c| c.txid)
    }
    
    /// Get the receiver wallet_id
    pub fn receiver_wallet_id(&self) -> Option<&str> {
        self.cheques.first().map(|c| c.receiver_wallet_id.as_str())
    }
    
    /// Get the amount
    pub fn amount(&self) -> Option<u64> {
        self.cheques.first().map(|c| c.amount)
    }
    
    /// Check if we have k cheques
    pub fn has_k_cheques(&self, k: usize) -> bool {
        self.cheques.len() >= k
    }
}

/// Request to redeem a cheque bundle
/// 
/// Receiver submits this to THEIR validators (not sender's validators)
/// to update their wallet state with the received funds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedeemRequest {
    /// The bundle of k cheques from sender's validators
    pub cheque_bundle: ChequeBundle,
    
    /// Receiver's public key (must match cheques' receiver_wallet_id)
    pub receiver_pk: Vec<u8>,
    
    /// Receiver's current wallet state (balance before redemption)
    pub current_state: Option<WalletState>,
    
    /// Signature proving ownership of receiver_pk
    /// Signs: BLAKE3("AXIOM_REDEEM" || txid || receiver_pk)
    pub receiver_sig: Vec<u8>,
    
    /// Request ID for correlation
    pub request_id: String,
}

/// ACK envelope (sent by sender to their validators).
///
/// v3.x (YP §20.8): no per-TX fee promise — validator fees settle at CL5
/// via fee_breakdown direct-deposit, not at sender ACK time. The ACK
/// remains as the trigger for state finalization (PENDING → CONFIRMED,
/// mark consumed_state_id, prune superseded S-ABR records). The struct
/// name retains "WithFee" only to avoid wire-type churn; the field is gone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckWithFee {
    /// Transaction ID being acknowledged
    pub txid: [u8; 32],

    /// Which validator this ACK is for
    pub validator_pk: Vec<u8>,

    /// Sender's signature authorizing finalization
    /// Signs: BLAKE3("AXIOM_ACK_v3" || txid || validator_pk)
    pub sender_sig: Vec<u8>,
}

/// Confirmation cheque (sent by receiver to sender's validators)
/// 
/// After receiver successfully redeems, they send this to sender's validators
/// to confirm receipt of payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmationCheque {
    /// Original transaction ID
    pub txid: [u8; 32],
    
    /// Which validator this confirmation is for
    pub validator_pk: Vec<u8>,
    
    /// Receiver's signature confirming receipt
    /// Signs: BLAKE3("AXIOM_CONFIRM" || txid || validator_pk || receiver_pk)
    pub receiver_sig: Vec<u8>,
    
    /// Receiver's public key
    pub receiver_pk: Vec<u8>,
}

// ============================================================================
// FEE CHEQUE MODEL
// 
// Validators collect fees through the same cheque system as normal payments.
// Each validator receives TWO cheques per witnessed transaction:
// 1. Fee cheque (issued when witnessing sender's TX) - contains the fee amount
// 2. Confirmation cheque (issued when receiver redeems) - proves TX completed
// 
// Validator must have BOTH cheques to redeem their fee.
// Fee redemption requires k=3 witnesses (who were NOT original TX witnesses).
// ============================================================================


/// Calculate DEED allocation from validator fee
/// 
/// # Rules
/// - DEED receives 10% of validator fee
/// - Minimum 1 atom (if fee > 0)
/// - Only during DEED period (first 10 years from genesis)
/// 
/// # Parameters
/// - `validator_fee`: The gross fee amount
/// - `years_since_genesis`: Years elapsed since network genesis
/// 
/// # Returns
/// DEED allocation in atoms
pub fn calculate_deed_allocation(validator_fee: u64, years_since_genesis: u64) -> u64 {
    const DEED_PERIOD_YEARS: u64 = 10;
    const DEED_PERCENTAGE: u64 = 10;  // 10%
    
    if years_since_genesis >= DEED_PERIOD_YEARS {
        return 0;  // DEED period expired
    }
    
    if validator_fee == 0 {
        return 0;
    }
    
    // AUDIT-FIX v2.11.14: Use checked/saturating math to prevent overflow
    // when validator_fee is near u64::MAX. Division by 100 always brings
    // the result back into range, so saturating_mul is safe here.
    let deed_amount = validator_fee.saturating_mul(DEED_PERCENTAGE) / 100;
    
    // Minimum 1 atom if any fee exists
    if deed_amount == 0 {
        1
    } else {
        deed_amount
    }
}

/// Calculate receiver amount after fee deduction
/// 
/// # Formula
/// receiver_amount = sender_amount - (k × fee_per_validator)
/// 
/// # Returns
/// Ok(receiver_amount) or Err if insufficient funds for fees
pub fn calculate_receiver_amount(
    sender_amount: u64,
    k: u8,
    fee_per_validator: u64,
) -> Result<u64, ValidationError> {
    let total_fees = (k as u64).checked_mul(fee_per_validator)
        .ok_or(ValidationError::InternalError)?;
    
    sender_amount.checked_sub(total_fees)
        .ok_or(ValidationError::InsufficientBalance)
}

/// Default fee per validator in atoms
pub const DEFAULT_FEE_PER_VALIDATOR: u64 = 10;

/// Current core version string for lineage binding
pub const CORE_VERSION: &str = "2.12.0";

/// Genesis SDID — Settlement Domain ID for the primary AXIOM worldline.
/// BLAKE3("AXIOM_SDID_GENESIS_V1"). Fixed at genesis, never changes.
/// See Yellow Paper §23.9.2.
pub fn genesis_sdid() -> [u8; 32] {
    *blake3::hash(b"AXIOM_SDID_GENESIS_V1").as_bytes()
}

/// Genesis lineage hash — starting point for the lineage chain.
/// BLAKE3("AXIOM_LINEAGE_GENESIS_V1"). Evolves with each core upgrade.
/// See Yellow Paper §23.11.2.
pub fn genesis_lineage_hash() -> [u8; 32] {
    *blake3::hash(b"AXIOM_LINEAGE_GENESIS_V1").as_bytes()
}

/// A witness signature from a validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessSig {
    /// Validator's unique identifier (derived from VBC)
    pub validator_id: [u8; 32],
    
    /// Validator's public key
    pub validator_pk: Vec<u8>,
    
    /// Validator Birth Certificate bundle
    /// Full VBC chain proof — Core verifies back to genesis root keys.
    #[serde(default)]
    pub vbc_bundle: Option<VBCProofBundle>,
    
    /// Carrier type (how to reach this validator)
    /// e.g., "email", "swift", "https"
    pub carrier_type: String,
    
    /// Carrier address (endpoint for this validator)
    /// e.g., "validator-alpha@axiom.network", "AXIOMVAL1XXX"
    pub carrier_address: String,
    
    /// Signature over commitment_hash
    pub signature: Vec<u8>,
    
    /// Execution proof bytes (ZKP STARK receipt or DMAP attestation)
    pub execution_proof: Vec<u8>,

    /// Proof type discriminator: 0 = ZKP (STARK), 1 = DMAP (attestation)
    /// Default 0 (ZKP) for backward compatibility with existing wire format.
    #[serde(default)]
    pub proof_type: u8,

    /// Availability attestation (optional)
    pub availability_attestation: Option<AvailabilityAttestation>,
    
    /// Validator hints for organic discovery (MANDATORY: 1-3 hints)
    /// Per Yellow Paper Section 27.5: Validators MUST include hints in replies
    /// Core enforces: 1 <= hints.len() <= 3
    pub validator_hints: Vec<ValidatorHint>,
    
    /// FACT commitment signature (YPX-001)
    /// Signs: BLAKE3("AXIOM_FACT" || tx_id || previous_state_id || new_state_id || amount)
    /// Used to build FACT links with k=3 witnesses for money provenance.
    /// Each validator signs the FACT commitment alongside the witness commitment.
    /// Client/overlapped validator collects k=3 and assembles the FactLink.
    pub fact_signature: Option<Vec<u8>>,

    /// SEC-07 checkpoint endorsement: this validator's Dilithium signature
    /// (carried as a `FactWitness` so it ships its own validator_id + pk)
    /// over the DETERMINISTIC FACT checkpoint commitment for THIS round.
    ///
    /// Present only when this TX's `sender_fact_chain` crosses the FACT
    /// compression trigger — every witness in that round signs the identical
    /// checkpoint (the compressed set is deterministic given the same input
    /// chain), and the finalizer merges the k endorsements into the
    /// checkpoint's `validator_sigs` (see `fact::merge_checkpoint_endorsements`).
    /// This is the carrier that lets a checkpoint carry k=3 DISTINCT sigs
    /// minted in the one round that created it — no validator-to-validator
    /// talk, no over-rounds accumulation. `None` when no compression triggers.
    /// See `docs/security_review_20260612/SEC-07_RESOLUTION.md`.
    pub checkpoint_sig: Option<FactWitness>,

    /// Nabla register receipt signature.
    ///
    /// Each validator signs `wallet_id || consumed_state_id ||
    /// produced_state_id || tick_le` with their Ed25519 key. Nabla's
    /// `/register` TCP path verifies k=3 of these signatures (see
    /// nabla/src/registration.rs:120 and nabla/src/crypto.rs::receipt_sign_payload).
    /// The SDK forwards this byte string verbatim into the Nabla
    /// `K3Receipt.signatures[].signature` field — the SDK has no
    /// validator key and cannot re-sign.
    ///
    /// This is a SEPARATE signature from `signature` (which is over
    /// the Core commitment_hash for witness consensus) and
    /// `fact_signature` (Dilithium over the FACT commitment for
    /// receiver-side audit). All three pin the same TX from
    /// different oracle perspectives. Always present — serde(default)
    /// removed so any wire that omits this field decodes as an error
    /// rather than silently producing an unsigned receipt.
    pub receipt_signature: Option<Vec<u8>>,

    /// Receipt commitment signature — Ed25519 over BLAKE3("AXIOM_RECEIPT_v1"
    /// || txid || state_hash || produced_state_id || new_wallet_seq ||
    /// commitment_hash || epoch || rate_bps || slot_amount). Each validator
    /// signs this to prove k validators agreed on the SAME receipt fields.
    /// Core verifies on next TX: recompute commitment from receipt fields,
    /// check k sigs. Prevents receipt fabrication by clients or malicious-
    /// validator collusion (honest validators sign different commitment →
    /// mismatch).
    ///
    /// The rate_bps + slot_amount additions (2026-06-03) bind the
    /// validator's signature to its OWN fee claim — without them, the
    /// SDK could swap slot amounts post-witness without breaking the sig.
    #[serde(default)]
    pub receipt_commitment_sig: Option<Vec<u8>>,

    // ── v3.x fee-self-attestation (2026-06-03) ─────────────────────
    // Move the fee-slot authority OUT of the SDK and INTO each
    // validator's own Core. Every WitnessSig now carries the
    // validator's rate AND the slot it produced; both are signed
    // over by `signature` and `receipt_commitment_sig` above. Any
    // Core that processes this WitnessSig — Lambda witness-time
    // pre-sign check, client CL1 redeem-build, receiver CL5 — runs
    // `validation::verify_slot_math(amount, rate_bps, slot_amount)`
    // and rejects on mismatch. This removes the SDK from the fee
    // trust chain: it can't propose a slot, can't lie about a
    // validator's rate, and can't swap one slot for another after
    // the fact.

    /// The validator's advertised fee rate in basis points (1 bps =
    /// 0.01%) at witness time, from its own `lambda.toml [fees]
    /// rate_bps` (capped at `MAX_VALIDATOR_FEE_BPS = 30`). Signed by
    /// `signature` and `receipt_commitment_sig`. 0 is a valid value
    /// for zero-fee validators.
    #[serde(default)]
    pub rate_bps: u32,

    /// The slot atoms this validator earns from this TX, computed by
    /// its own Core as `min(rate_bps, MAX_VALIDATOR_FEE_BPS) × amount
    /// / FEE_BPS_DIVISOR` and signed before returning. Every
    /// downstream Core re-derives the value and rejects if it
    /// doesn't match. Receipt `fee_breakdown[i].amount` MUST equal
    /// `witness_sigs[i].slot_amount`.
    #[serde(default)]
    pub slot_amount: u64,
}

/// Validator hint for organic network discovery
/// Per Yellow Paper Section 27.5
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValidatorHint {
    /// Validator's stable identifier: `blake3(sphincs_pk)` — the same
    /// 32-byte ID `crypto::compute_validator_id` produces. CBOR-encoded
    /// as a 32-byte bytestring; JSON-facing surfaces (admin endpoints)
    /// hex-encode for display. Pre-2026-05-24 this was `String` and
    /// some Lambda code paths populated it with
    /// `"alpha@axiom/abcd1234"`-shape labels — those literals are now
    /// a type error.
    pub validator_id: [u8; 32],
    
    /// Human-friendly display name (e.g., "axiom-first-penguin-alpha")
    pub name: String,
    
    /// Carrier URIs — one or more ways to reach this validator
    /// e.g., ["email:alpha@axiom.local", "uncle:192.168.1.100:9001"]
    /// A validator MAY be reachable via multiple carrier types (ANTIE, UNCLE, COUSIN)
    pub carriers: Vec<String>,

    /// YPX-007: Proof capability — "dmap" (default) or "zkvm"
    #[serde(default)]
    pub proof_cap: Option<String>,

    /// When validator was last seen responding (Unix timestamp)
    pub last_seen: Option<u64>,

    /// Ed25519 transport public key for this validator. `None` when
    /// the hint pre-dates a key binding (e.g., remote response from a
    /// peer that hadn't yet correlated the validator with its
    /// `approved_validators` row, or older Lambda builds that didn't
    /// emit this field). SDK clients treat this as a **first-guess
    /// hint** — the authoritative key for any given validator is the
    /// one extracted from a Core-verified VBC in a prev_receipt
    /// (`sdk/core/src/hints.rs::cross_check_vbc_keys` REPLACES a
    /// disagreeing hint key when VBC evidence arrives).
    #[serde(default)]
    pub ed25519_pk: Option<[u8; 32]>,

    /// Operator's encryption public key (e.g., PGP/GPG armoured public
    /// key block, or base64). Travels alongside the carrier URIs so a
    /// client that just discovered this validator can encrypt to it
    /// without a separate VSP round. Empty string = no encryption
    /// advertised (clients fall back to plain transport).
    #[serde(default)]
    pub encryption_public_key: String,

    /// Encryption scheme tag matching `OperatorConfig.supported_encryption`
    /// ("PGP", "GPG", "none", …). Lets clients decide whether to attempt
    /// encryption with the bundled key.
    #[serde(default)]
    pub supported_encryption: String,
}

/// Attestation that data is available from overlap witness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailabilityAttestation {
    /// Witness that attests to availability
    pub witness_pk: Vec<u8>,
    
    /// Signature over the data hash
    pub signature: Vec<u8>,
    
    /// Hash of the available data
    pub data_hash: [u8; 32],
}

/// Current state of a wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletState {
    /// Wallet's public key
    pub public_key: Vec<u8>,
    
    /// Current balance in atoms
    pub balance: u64,
    
    /// Current wallet sequence number
    pub wallet_seq: u64,
    
    /// Current state ID
    pub state_id: [u8; 32],
    
    /// Owner authentication key (optional — wallet protection against key theft)
    /// When set: Ed25519 public key derived from owner_secret.
    /// Derivation: Ed25519_pubkey(SHA3-256("AXIOM_OWNER_KEY" || owner_secret))
    /// Spending requires Ed25519 signature with the derived key (zero-knowledge).
    /// When None: wallet is unprotected (private key = full access)
    pub auth_hash: Option<[u8; 32]>,

    /// Canonical wallet_id bound to this public key (identity binding).
    /// Set on the first transaction and immutable thereafter.
    /// Core enforces: tx.sender_wallet_id must match this value when Some.
    /// Prevents lockup bypass and Ark policy spoofing — identity is
    /// cryptographically bound via the first signed transaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_id: Option<String>,

    /// Group wallet members (optional — None for personal wallets)
    /// When Some: this is a group wallet with percentage-based distribution.
    /// Every member holds the group wallet's private key (shared).
    /// Withdrawals are restricted: destination must be a member's wallet_id,
    /// amount must not exceed the member's available balance.
    /// Members list is immutable after creation.
    /// Max 32 members. sum(share_bps) must equal 10000.
    pub group_members: Option<Vec<GroupMember>>,

    /// YPX-020 — HIBERNATION: tick until which this wallet is "out of work".
    /// While `tx.tick < hibernation_until`, Core CL2 rejects every tx for this
    /// wallet (CL1 is exempt — a first tx has no prior state to hibernate on).
    /// Bound into `compute_state_hash` so it is witnessed + tamper-evident. A
    /// general primitive (timelocks, vesting, dispute windows); HAL sets it to
    /// `now + W` on a re-anchor so a concurrent spend can't race the wait.
    /// `0` = not hibernating (the normal case).
    #[serde(default)]
    pub hibernation_until: u64,
}

/// Maximum number of members in a group wallet
pub const MAX_GROUP_MEMBERS: usize = 32;

/// Total basis points must equal this (100.00%)
pub const TOTAL_SHARE_BPS: u16 = 10000;

/// A member of a group wallet
/// 
/// Members are identified by their public key. The wallet_id is derived from
/// the public key (deterministic). Members can only withdraw to their own
/// wallet, and only up to their available balance.
/// 
/// share_bps is in basis points: 100 bps = 1%, 10000 bps = 100%.
/// available tracks atoms allocated but not yet withdrawn.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroupMember {
    /// Member's public key (identity — wallet_id derived from this)
    pub member_pk: Vec<u8>,
    
    /// Member's share in basis points (10000 = 100%)
    pub share_bps: u16,
    
    /// Atoms allocated to this member but not yet withdrawn
    pub available: u64,
}

/// Genesis wallet definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisWallet {
    /// Wallet's public key
    pub public_key: [u8; 32],
    
    /// Initial balance in atoms
    pub balance: u64,
    
    /// Genesis state ID: H("AXIOM_GENESIS" || pk || balance)
    pub genesis_state_id: [u8; 32],
    
    /// Initial wallet_seq (always 0)
    pub wallet_seq: u64,
}

/// VBC Proof Bundle for validator authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VBCProofBundle {
    /// The VBC being verified
    pub target_vbc: VBC,
    
    /// Supporting VBCs for chain verification
    pub supporting_vbcs: Vec<VBC>,
}

/// 30 days — minimum VBC age before validator can approve new validators.
/// Genesis validators (in GENESIS_VALIDATORS) are exempt.
pub const VBC_APPROVAL_MATURITY_SECS: u64 = 30 * 86_400;

/// Meta-Validator Inheritance Binding (MVIB) — Yellow Paper §10.
///
/// When a validator joins the network, it publishes a signed binding to its
/// upstream admission set: the k=3 validators who signed its VBC. This binding
/// allows JFP voting responsibility to pass to meta-validators when a validator
/// disappears.
///
/// The commitment is: BLAKE3("AXIOM_MVIB" || validator_id || admission_set || tick)
/// The signature is Ed25519 over that commitment, using the validator's operational key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MvibBinding {
    /// The new validator's ID (BLAKE3 of SPHINCS+ PK)
    pub validator_id: [u8; 32],

    /// The k=3 validator IDs who signed this validator's VBC (admission set)
    pub admission_set: Vec<[u8; 32]>,

    /// Tick at which the binding was published
    pub binding_tick: u64,

    /// Ed25519 signature over BLAKE3("AXIOM_MVIB" || validator_id || admission_set || tick)
    pub signature: Vec<u8>,
}

// ── YPX-013: Console Engine ──────────────────────────────────────────────────

/// Console size: 15 validators (White Paper §7.4, Yellow Paper §21.10.2).
pub const CONSOLE_SIZE: usize = 15;

/// Ticks per year: 365 days × 86400 s/day ÷ 5 s/tick = 6,311,520.
pub const CONSOLE_TICKS_PER_YEAR: u64 = 6_311_520;

/// Election nomination window: 1 week = 120,960 ticks.
pub const CONSOLE_ELECTION_WINDOW_TICKS: u64 = 120_960;

/// Election retry cooldown: ~1 month = 525,960 ticks.
pub const CONSOLE_ELECTION_RETRY_TICKS: u64 = 525_960;

/// Maximum election attempts before permanent dissolution.
/// After this many failures, Console is gone for this Core version.
/// No restart mechanism. No override. New Core ELF required.
pub const CONSOLE_MAX_ELECTION_ATTEMPTS: u8 = 3;

/// Number of random selectors chosen from current Console for election.
pub const CONSOLE_SELECTOR_COUNT: usize = 3;

/// Each selector picks this many validators from nomination list.
pub const CONSOLE_PICKS_PER_SELECTOR: usize = 5;

/// Chain depth: keep this many generations in full, compress older ones.
pub const CONSOLE_CHAIN_DEPTH: u32 = 30;

/// Console compensation: 1 AXC per full service year (White Paper §G.4).
pub const CONSOLE_COMPENSATION_AXC: u64 = 1;

// ── YPX-018: BLOOM_PHASE_OUT constitutional limits ───────────────────────────
//
// These constants live in Core and are validated in CL11 when Core signs a
// `BloomPhaseOut` Console certificate. The Console **cannot** override them
// — only a new Core ELF (a worldline change, per YPX-013) can.
//
// Combined effect: any cheque issued in tick T cannot become unreachable
// before tick T + 55 years, no matter what the Console decides.

/// Minimum age of any era before it may be phased out.
/// 50 years = 50 × 6,311,520 = 315,576,000 ticks.
/// Set to span a full adult lifetime — anyone who received a cheque as a
/// young adult can still redeem it as an old person.
/// Reference: YPX-018 §4.3, YPX-013 §1.2.
pub const MIN_PHASE_OUT_AGE_TICKS: u64 = 50 * CONSOLE_TICKS_PER_YEAR;

/// Minimum grace period from proposal approval to effective phase-out.
/// 5 years = 5 × 6,311,520 = 31,557,600 ticks.
/// Reference: YPX-018 §4.3, YPX-013 §1.2.
pub const MIN_PHASE_OUT_GRACE_TICKS: u64 = 5 * CONSOLE_TICKS_PER_YEAR;

/// YPX-013: Console Certificate — Core-signed generational governance artifact.
///
/// Each Console term produces one certificate. The chain of certificates
/// traces Console authority back to genesis, like FACT traces money provenance.
/// All Console operations pass through the Console group wallet (DWP/ prefix).
///
/// The certificate hash (chain link) is:
/// BLAKE3("AXIOM_CONSOLE_CHAIN" || generation || seats || term_start || term_end || prev_hash)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleCertificate {
    /// Generation number (0 = genesis, increments each term)
    pub generation: u32,

    /// The 15 validator seats (validator_id for each)
    pub seats: Vec<[u8; 32]>,

    /// Term start (TARDIS tick)
    pub term_start_tick: u64,

    /// Term end (term_start_tick + TICKS_PER_YEAR)
    pub term_end_tick: u64,

    /// BLAKE3 hash of the previous ConsoleCertificate (all zeros for genesis)
    pub previous_link_hash: [u8; 32],

    /// Which election attempt produced this certificate (0-indexed)
    pub election_attempt: u8,

    /// Console group wallet address (DWP/CONSOLE/{generation})
    pub group_wallet_id: String,

    /// Core Ed25519 signature over the certificate hash
    pub core_signature: Vec<u8>,
}

/// A selector's picks during Console election.
/// Each of the 3 randomly-chosen selectors picks 5 validators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectorPick {
    /// The selector's validator_id (= BLAKE3(sphincs_pk), must be in current Console)
    pub selector_id: [u8; 32],

    /// The 5 validator_ids this selector chose from the nomination list
    pub picks: Vec<[u8; 32]>,

    /// Ed25519 signature over BLAKE3("AXIOM_CONSOLE_PICK" || selector_id || picks || generation)
    pub signature: Vec<u8>,

    /// AUDIT-FIX v2.11.14: Selector's Ed25519 public key (from VBC.subject_pubkey_ed25519).
    /// Required for signature verification. validator_id = BLAKE3(sphincs_pk) ≠ ed25519_pk.
    #[serde(default)]
    pub selector_ed25519_pk: [u8; 32],
}

/// Validator Birth Certificate (VBC) v0.9
///
/// The VBC is a validator's identity document, signed by 3 issuers.
/// Chain verification walks issuer_set → issuer VBCs → ... → root PKs.
/// Root PKs are hardcoded in Core — the trust anchor of the entire network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VBC {
    /// VBC format version (0x09 = v0.9)
    pub version: u8,
    
    /// Subject validator's unique ID (BLAKE3 hash of SPHINCS+ PK)
    pub validator_id: [u8; 32],
    
    /// Subject's SPHINCS+ public key — primary VBC identity (32 bytes)
    /// Used for VBC chain signatures. Quantum-resistant.
    pub subject_pubkey_sphincs: Vec<u8>,
    
    /// Subject's Dilithium (ML-DSA-65) public key — backup identity (1,952 bytes)
    /// Stored in VBC for algorithm-independence; covered by issuers' SPHINCS+ signatures.
    /// If SPHINCS+ ever breaks, this provides an authenticated fallback identity.
    pub subject_pubkey_dilithium: Vec<u8>,
    
    /// Subject's Ed25519 public key — witness signing + encryption (32 bytes)
    /// This is the key used for day-to-day transaction witnessing.
    /// Can be converted to X25519 for encrypted communication.
    pub subject_pubkey_ed25519: Vec<u8>,
    
    /// PGP fingerprint (optional, 20 bytes)
    /// Links AXIOM identity to real-world PGP web of trust.
    /// Empty if validator prefers anonymity.
    #[serde(default)]
    pub pgp_fingerprint: Vec<u8>,

    /// Human-readable node name chosen by operator.
    /// Authenticated: covered by issuers' SPHINCS+ signatures.
    /// Same concept as pgp_fingerprint — optional identity metadata.
    /// Max 64 bytes UTF-8. Supports any language (English, Chinese, Japanese, etc).
    /// Empty string if operator doesn't set a name.
    #[serde(default)]
    pub node_name: String,

    /// Proof capability at onboarding: "dmap" or "zkvm"
    /// Determined by benchmark. Covered by issuer SPHINCS+ signatures.
    #[serde(default)]
    pub proof_cap: String,

    /// Issued timestamp (Unix epoch seconds)
    pub issued_at: u64,
    
    /// Expires timestamp (Unix epoch seconds)
    pub expires_at: u64,
    
    /// Chain depth: 0 = signed by root keys, 1 = signed by genesis validators, etc.
    /// Maximum allowed depth defined by MAX_VBC_CHAIN_DEPTH.
    pub chain_depth: u8,
    
    /// Issuer SPHINCS+ public keys (exactly 3)
    /// For genesis VBCs: 3 root authority PKs
    /// For new validators: 3 existing validator SPHINCS+ PKs
    pub issuer_set: Vec<Vec<u8>>,
    
    /// Issuer SPHINCS+ signatures over VBC commitment (7,856 bytes each)
    /// Signs: BLAKE3("AXIOM_VBC_V1" || all fields above)
    pub signatures: Vec<Vec<u8>>,
    
    /// Maximum transaction (registration) budget for this NBC/VBC.
    /// Peers track registrations processed by this node and reject once past max_tx.
    /// On renewal, counter resets (new NBC = new budget).
    /// 0 means unlimited (backward compat with pre-budget NBCs).
    /// Covered by issuer SPHINCS+ signatures.
    #[serde(default)]
    pub max_tx: u64,

    /// Founding VBC hash — BLAKE3 hash of this validator's FIRST-EVER VBC.
    /// Set to [0; 32] on initial VBC (self-referential: hash of this VBC).
    /// Carried forward unchanged on every renewal.
    /// Allows anyone to verify founding date and original signing lineage.
    /// Not included in the signing commitment (immutable metadata).
    #[serde(default)]
    pub founding_vbc_hash: [u8; 32],

    /// OODS baseline (YPX-021 §7) — the issuer's PROVEN network-size view,
    /// stamped into the certificate at issuance/renewal. The subject node is
    /// "born with a baseline" inherited through the genesis-rooted cert
    /// chain: to hand a node a fake baseline you need a colluding issuer
    /// whose own cert chains to genesis.
    ///
    /// `0` = no baseline — genesis certs are the root of trust and are
    /// EXEMPT (their baseline is a ceremony concern, deferred per §7).
    /// When non-zero, the value is bound into the issuer signatures: see
    /// `compute_vbc_signing_payload_bytes`, which appends
    /// `network_size_baseline || baseline_tick` to the signing pre-image
    /// ONLY when the baseline is non-zero, keeping genesis/pre-baseline
    /// cert signatures byte-identical.
    #[serde(default)]
    pub network_size_baseline: u32,

    /// TARDIS tick at which `network_size_baseline` was measured by the
    /// issuer. `0` when no baseline (genesis exemption).
    #[serde(default)]
    pub baseline_tick: u64,
}

/// Public inputs to Core.bin (what goes into the zkVM)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInputs {
    /// Which mode to execute
    pub mode: CoreLogicMode,
    
    /// The transaction to validate (CL1-CL4)
    pub transaction: Transaction,
    
    /// Previous receipts (for balance/seq verification)
    pub prev_receipts: Vec<Receipt>,
    
    /// Current wallet state (if known)
    pub current_state: Option<WalletState>,
    
    /// VBC bundle for validator verification (CL2/CL3)
    pub vbc_bundle: Option<VBCProofBundle>,
    
    // === CL5 Redeem fields ===
    
    /// Cheque bundle for redemption (CL5 only)
    pub cheque_bundle: Option<ChequeBundle>,
    
    /// Receiver's public key (CL5 only)
    pub receiver_pk: Option<Vec<u8>>,
    
    /// Receiver's current balance before redeem (CL5 only)
    pub receiver_current_balance: Option<u64>,
    
    /// Receiver's wallet_seq (CL5 only)
    pub receiver_wallet_seq: Option<u64>,

    /// YPX-020 — receiver's CURRENT `hibernation_until` (CL5 only), supplied by
    /// the validator from its stored receiver state (same trusted path as
    /// `receiver_current_balance`; k-witnessing keeps it honest). CL5 CARRIES it
    /// into the produced state rather than zeroing it, so a self-redeem cannot
    /// clear a wallet's hibernation lock. `None`/0 = not hibernating.
    #[serde(default)]
    pub receiver_current_hibernation: Option<u64>,

    /// Expected new balance after redeem (CL5 only)
    pub receiver_new_balance: Option<u64>,
    
    /// Expected new state_id after redeem (CL5 only)
    pub receiver_new_state_id: Option<[u8; 32]>,

    // fee_breakdown on PublicInputs deleted 2026-06-05 PM. Pre-fix the
    // SDK proposed the per-validator allocation and Lambda forwarded it
    // here for Core CL5's NET balance binding. Replaced by reading
    // `cheque.rate_bps` (Dilithium-signed at issuance) from each cheque
    // in `cheque_bundle.cheques`. Core CL5 sums
    // `expected_fee_slot_amount(c.amount, c.rate_bps)` directly. No
    // client view of validator rates flows into the hash any more.
    // Closes `E_RECEIPT_COMMITMENT_MISMATCH` class. CLAUDE.md §13:
    // pre-mainnet, no shim — just delete.

    // === CL3 S-ABR Overlap fields ===
    
    /// This validator's public key (CL3 only)
    /// Used to determine if this validator is overlapped or fresh
    pub my_validator_pk: Option<Vec<u8>>,

    /// Overlapped signatures: witness sigs from previous-TX validators
    /// who have ALREADY signed THIS transaction (CL3 only)
    /// Fresh validators must provide ≥ k-1 overlapped sigs to proceed
    pub overlapped_signatures: Vec<WitnessSig>,

    // === Group wallet fields ===

    /// Member index for group wallet withdrawal (group wallet TX only)
    /// Identifies which member is withdrawing their share.
    /// Core verifies: members[index] exists and amount <= available.
    /// The receiver's personal wallet verifies wallet_id matches on redemption.
    pub group_member_index: Option<u32>,

    // === FACT chain fields (YPX-001) ===

    /// Sender's FACT chain for CL2 send validation.
    /// Lambda passes the sender's stored chain; Core verifies integrity.
    /// At CL5 redeem, FACT chain comes from cheque_bundle.fact_chain instead.
    pub sender_fact_chain: Option<FactChain>,

    /// Operator-configurable maximum FACT chain depth (from `lambda.toml`'s
    /// `max_fact_links`). Lambda passes this in CL2 calls so Core — not Lambda —
    /// enforces depth-gating. `None` = no operator limit (effectively unlimited;
    /// Core's hard protocol cap `MAX_TOTAL_LINKS` still applies in `fact.rs`).
    ///
    /// `is_heal && sender_wallet_id == receiver_wallet_id` is exempt: scar-burn
    /// recovery TXs need to bypass the depth gate to clear scars that prevent
    /// FACT compression. See `validation.rs` for the check and
    /// `feedback_layer_roles.md` for why this lives in Core, not Lambda.
    pub max_fact_links: Option<u32>,

    /// Receiver's existing FACT chain at CL5 redeem time.
    /// Core appends the new redeem link to this via `build_fact_link`
    /// when the finalizer's CL5 has all `required_k` witness sigs in
    /// `fact_witness_sigs`. None for first-time receivers (chain starts
    /// empty). The SDK passes this from `wallet.fact_chain()` so Core —
    /// not the SDK — assembles FACT links (CLAUDE.md §12).
    #[serde(default)]
    pub receiver_fact_chain: Option<FactChain>,

    // === Validator crypto keys (CL3 only) ===

    /// This validator's Dilithium private key (CL3 only).
    /// Core uses this to sign FACT commitments internally.
    /// Lambda MUST NOT sign FACT directly — it passes the key to Core.
    pub my_dilithium_sk: Option<Vec<u8>>,

    /// This validator's Dilithium public key (CL3 only).
    /// Included in FACT witness entries.
    pub my_dilithium_pk: Option<Vec<u8>>,

    /// This validator's ID (CL3 only).
    /// Included in FACT witness entries.
    pub my_validator_id: Option<[u8; 32]>,

    /// Accumulated FACT witness signatures from other validators (CL3/k=3 path only).
    /// At k=3, Core builds the FACT link using these sigs plus its own.
    pub fact_witness_sigs: Vec<WitnessSig>,

    // === CL8 NBC Issuance fields ===

    /// Issuer's SPHINCS+ private key for NBC signing (CL8 only).
    /// Core signs the NBC internally — Nabla MUST NOT call sign_sphincs directly.
    pub issuer_sphincs_sk: Option<Vec<u8>>,

    // === CL1 ZKP fields ===

    /// Client's CL1 execution proof (optional).
    /// When present, Lambda's ZkvmVerifier checks this before calling CL2.
    /// CL1 ZKP proves the client ran Core and got Accept — validator can fast-path.
    #[serde(default)]
    pub cl1_execution_proof: Option<Vec<u8>>,

    /// Fresh 256-bit random nonce for ZKP anti-replay binding.
    /// Core hashes this into PublicOutputs; verifier checks the binding.
    #[serde(default)]
    pub zkp_nonce: Option<[u8; 32]>,

    // === CL9 Scar Heal Signing fields ===

    /// Original transaction ID for scar heal (CL9 only).
    #[serde(default)]
    pub scar_heal_tx_id: Option<[u8; 32]>,

    /// Nabla node ID that confirmed the transaction (CL9 only).
    #[serde(default)]
    pub scar_heal_nabla_id: Option<[u8; 32]>,

    /// Nabla root hash at confirmation time (CL9 only).
    #[serde(default)]
    pub scar_heal_root_hash: Option<[u8; 32]>,

    // === §23.14 Peer Audit ===

    /// Audit confirmation from Lambda in response to a previous AuditDemand.
    /// If Core previously demanded an audit and the AVM countdown is active,
    /// Lambda MUST provide this within AUDIT_COUNTDOWN_TXS invocations.
    #[serde(default)]
    pub audit_confirmation: Option<AuditConfirmation>,

    // === YPX-009 Silicon Pulse ===

    /// Nonce response from Lambda (YPX-009 §3.6).
    /// Lambda answers the previous NonceChallenge with current wallet state.
    #[serde(default)]
    pub nonce_response: Option<NonceResponse>,

    /// Audit response from Lambda (YPX-009 §4.4).
    /// Lambda re-executed selected TXs and provides chain hash.
    #[serde(default)]
    pub audit_response: Option<PulseAuditResponse>,

    /// Wallet secret for CL5 ownership verification (never transmitted on wire).
    /// Client provides this for local DMAP proof; validator sees only the proof.
    #[serde(default)]
    pub wallet_secret: Option<[u8; 32]>,

    /// Fan-out message for CL10 verification (§18.8).
    #[serde(default)]
    pub fanout_message: Option<FanOutMessage>,

    /// Candidate's declared balance for VBC approval (CL8).
    /// Core checks this against stake tier requirements.
    /// k=3 independent validators verify independently — lying detected.
    #[serde(default)]
    pub candidate_balance: Option<u64>,

    /// NablaStakeProof for CL8 VBC approval — trustless stake verification (§25.5.4).
    /// Replaces candidate_balance. Core verifies Nabla attestation + k=3 receipt.
    #[serde(default)]
    pub nabla_stake_proof: Option<NablaStakeProof>,

    /// JFP §7: Frozen wallet PKs from active freeze orders in management_db.
    /// Lambda queries freeze_orders table and passes wallet PKs here.
    /// Core CL1 rejects transactions from any sender whose client_pk is in this set.
    /// Dual enforcement: Nabla SCAR marks for public knowledge, Core freeze blocks TXs.
    #[serde(default)]
    pub frozen_wallets: Option<Vec<[u8; 32]>>,

    // ── CL11: Console (YPX-013) ──────────────────────────────────────────────

    /// Current Console Certificate (for chain verification during election finalization).
    #[serde(default)]
    pub console_current_cert: Option<ConsoleCertificate>,

    /// New Console Certificate to validate (CL11 FinalizeElection).
    #[serde(default)]
    pub console_new_cert: Option<ConsoleCertificate>,

    /// Selector picks for election verification (CL11 FinalizeElection).
    #[serde(default)]
    pub console_selector_picks: Option<Vec<SelectorPick>>,

    /// Nomination list (validator_ids that self-nominated during election).
    #[serde(default)]
    pub console_nominations: Option<Vec<[u8; 32]>>,

    // === CL5 Txid Attestation (YPX-014) ===

    /// Client-provided Nabla txid attestation for global double-redeem prevention.
    /// Core CL5 verifies: Ed25519 signature, status == "NOT_REDEEMED", PK trust anchor.
    /// Lambda handles freshness (wall clock). Core handles cryptographic verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txid_attestation: Option<NablaTxidAttestation>,

    /// Client-provided Nabla cheque-claim proof — the synchronous-write
    /// chokepoint that closes the gossip-race window of `txid_attestation`.
    /// `Option<>` for back-compat with non-redeem CL paths only; **CL5
    /// requires this** and rejects with `E_CHEQUE_CLAIM_PROOF_MISSING`
    /// if absent (per CLAUDE.md §13 — no soft fallback).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cheque_claim_proof: Option<ChequeClaimProof>,

    // === YPX-021 OODS health flag (§8.2) ===

    /// Client-carried Nabla OODS reading for the health flag. When present,
    /// Core verifies it (`validation::verify_oods_attestation` — hard
    /// reject on an invalid one, never a silent downgrade) and stamps the
    /// derived `OodsFlag` into the receipt + `receipt_commitment`. `None`
    /// on paths with no Nabla reading (heal, genesis claim — Phase 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oods_attestation: Option<NablaOodsAttestation>,

    /// YPX-022 RECALL — Nabla recall attestation (proof the txid's consume-once
    /// landed). Core CL2 requires it on a RECALL self-send before it relaxes overlap
    /// + restores the pre-send balance. `None` on every non-RECALL path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recall_attestation: Option<RecallAttestation>,

    // === §13 Progressive Redeem Registration ===

    // === YPX-018 — CLARA wallet recovery attestation ===

    /// Client-provided Nabla CLARA attestation for partial-witness recovery.
    /// When present, Core CL2 verifies the Nabla signature and the roll-forward
    /// eligibility rule (validator's stored state must be in `garbage_state_ids`),
    /// then advances the validator's stored state to `healed_to_state_id`.
    /// See YPX-018 §2.3 and Yellow Paper §17.10.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clara_attestation: Option<ClaraAttestation>,

    // === YPX-018 — Console BLOOM_PHASE_OUT (CL11) ===

    /// Payload for a `BLOOM_PHASE_OUT` Console action. When present, CL11
    /// dispatches on this instead of the election finalization path.
    /// Validated against the constitutional limits in §6.2.3 (50-year minimum
    /// age, 5-year minimum grace, era exists, era not already phased out,
    /// effective_tick in the future). The Console cannot override these
    /// limits — only a new Core ELF can.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase_out_payload: Option<ConsoleProposalBloomPhaseOut>,

    /// Map of `era_id → era end_tick`, supplied by Lambda from the Bloom Age
    /// Index gossip state. Used by CL11 to verify the constitutional minimum
    /// age check (era.end_tick + MIN_PHASE_OUT_AGE_TICKS <= effective_tick).
    /// CBOR-encoded as `Vec<(u64, u64)>`. Empty when not in a BLOOM_PHASE_OUT
    /// CL11 invocation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub phase_out_era_end_ticks: Vec<(u64, u64)>,

    /// Set of era_ids that are already in `PhasedOut` or `ScheduledPhaseOut`
    /// status (per Lambda's view of the gossiped Bloom Age Index). CL11
    /// rejects re-phase-out of any era in this set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub phase_out_blocked_era_ids: Vec<u64>,

    /// Current TARDIS tick (passed in by Lambda for grace-period validation).
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub current_tick: u64,

    /// BLAKE3 of the Core ELF this host is running. Validators pass it in
    /// from compile-time `CANONICAL_CORE_ID` (release) or runtime hash of
    /// the loaded ELF (dev). CL2 Step −1.5 rejects with
    /// `ValidationError::CoreIdMismatch` if the incoming TX's `core_id`
    /// is non-zero and doesn't match — cheaper than running DMAP /
    /// signature verification just to discover the same thing deep in
    /// the proof.
    ///
    /// Defaults to all-zero, which disables the check (backward compat
    /// for callers built before this field existed and for dev paths
    /// that haven't wired the hash through yet).
    #[serde(default)]
    pub local_core_id: [u8; 32],

    /// CL13 (`VALIDATOR_WITHDRAWAL_MINT`) input bundle. Set by Lambda
    /// when driving a validator-withdrawal mint Core round; carries the
    /// signed earnings attestation, signed pool linkage, operator
    /// SPHINCS+ authorization, and `chosen_witnesses` set. `None` for
    /// every other mode — `execute_validator_withdrawal_mint` rejects
    /// with `WithdrawalInputsMissing` if CL13 is dispatched without it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawal_inputs:
        Option<crate::wire_client::ValidatorWithdrawalRequest>,
}

impl PublicInputs {
    /// Build minimal inputs for `CL12` (offline Send Proof verification): the
    /// proof's signed `transaction` plus its finalized `receipt` (carried as
    /// `prev_receipts[0]`); every other field empty/None. Lets an offline
    /// verifier (e.g. `tools/verify-send-proof`) pipe a retained proof straight
    /// into the Core ELF without hand-constructing 60 unrelated fields.
    pub fn for_send_proof_verify(transaction: Transaction, receipt: Receipt) -> Self {
        PublicInputs {
            mode: CoreLogicMode::CL12,
            transaction,
            prev_receipts: alloc::vec![receipt],
            current_state: None,
            vbc_bundle: None,
            cheque_bundle: None,
            receiver_pk: None,
            receiver_current_balance: None,
            receiver_wallet_seq: None,
            receiver_current_hibernation: None,
            receiver_new_balance: None,
            receiver_new_state_id: None,
            my_validator_pk: None,
            overlapped_signatures: alloc::vec![],
            group_member_index: None,
            sender_fact_chain: None,
            max_fact_links: None,
            receiver_fact_chain: None,
            my_dilithium_sk: None,
            my_dilithium_pk: None,
            my_validator_id: None,
            fact_witness_sigs: alloc::vec![],
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
            console_nominations: None,
            txid_attestation: None,
            cheque_claim_proof: None,
            oods_attestation: None,
            recall_attestation: None,
            clara_attestation: None,
            phase_out_payload: None,
            phase_out_era_end_ticks: alloc::vec![],
            phase_out_blocked_era_ids: alloc::vec![],
            current_tick: 0,
            local_core_id: [0u8; 32],
            withdrawal_inputs: None,
        }
    }
}

#[inline]
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

/// Public outputs from Core.bin (what comes out of the zkVM)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicOutputs {
    /// Accept or Reject
    pub result: ValidationResult,
    
    /// New state hash (if accepted)
    pub new_state_hash: Option<[u8; 32]>,
    
    /// Produced state ID (if accepted)
    pub produced_state_id: Option<[u8; 32]>,
    
    /// New wallet sequence number (if accepted)
    pub new_wallet_seq: Option<u64>,
    
    /// Rejection reason (if rejected)
    pub rejection_reason: Option<ValidationError>,
    
    /// S-ABR: Is the calling validator overlapped with prev_receipts?
    /// None = no VBC provided (can't determine)
    /// Some(true) = validator's PK found in prev_receipts witness sigs
    /// Some(false) = validator is new (not in prev_receipts)
    pub is_overlapped: Option<bool>,
    
    /// Commitment hash computed by Core for this transaction.
    /// BLAKE3("AXIOM_WITNESS_V2" || consumed_state_id || client_pk || ...)
    /// Validators MUST sign this hash. Lambda MUST NOT compute it.
    pub commitment_hash: Option<[u8; 32]>,
    
    /// Transaction ID computed by Core.
    /// BLAKE3("AXIOM_TXID" || consumed_state_id || client_pk || ...)
    /// Lambda MUST NOT compute this. Core returns it in outputs.
    pub txid: Option<[u8; 32]>,
    
    /// FACT commitment signature (Dilithium ML-DSA-65) for this validator.
    /// Core signs the FACT commitment internally using the validator's Dilithium SK.
    /// Lambda MUST NOT sign FACT directly — Core returns this in outputs.
    pub fact_signature: Option<Vec<u8>>,
    
    /// New balance after this transaction (for Lambda storage).
    /// Core computes balance math. Lambda MUST NOT do balance arithmetic.
    pub new_balance: Option<u64>,

    /// NBC signature bytes (SPHINCS+, CL8 only).
    /// Core signs the NBC and returns the 7,856-byte signature.
    pub nbc_signature: Option<Vec<u8>>,

    /// BLAKE3("AXIOM_ZKP_NONCE" || zkp_nonce) — binds this proof to one specific TX.
    /// Verifier MUST check this matches the expected nonce from the original TX.
    #[serde(default)]
    pub zkp_nonce_hash: Option<[u8; 32]>,

    /// Compressed FACT chain returned by Core after verify_and_compress.
    /// Core is the sole authority for FACT compression (Dilithium checkpoint signing).
    /// Lambda MUST use this instead of the input chain for the witness response.
    #[serde(default)]
    pub compressed_fact_chain: Option<FactChain>,

    /// Receiver's FACT chain after CL5 appended the redeem link.
    ///
    /// Populated only by `execute_cl5` on the finalizer validator (the one
    /// whose `inputs.fact_witness_sigs` plus its own sig reach `required_k`).
    /// All earlier validators in the redeem witness round leave this `None`;
    /// only the finalizer's Core call builds the link via `build_fact_link`.
    ///
    /// Lambda forwards this directly into the redeem response; the SDK stores
    /// it on the receiver's wallet via `wallet.set_fact_chain`. Replaces the
    /// pre-A2 SDK-side `build_and_append_fact_bridge` assembly path which
    /// violated CLAUDE.md §12 (Core is the sole cryptographic authority).
    #[serde(default)]
    pub receiver_fact_chain: Option<FactChain>,

    /// YPX-007: Required k extracted from receiver's wallet_id.
    /// Core fills this during validation. Lambda reads it for receipt threshold.
    #[serde(default)]
    pub required_k: u8,

    /// YPX-007: Proof type extracted from receiver's wallet_id.
    /// Core fills this during validation. Lambda reads it for DMAP/ZKP routing.
    #[serde(default)]
    pub extracted_proof_type: u8,

    // === §23.14 Peer Audit ===

    /// Audit demand generated by Core (§23.14 Ping Defense).
    /// When present, Lambda MUST initiate an audit of the target validator
    /// and provide `AuditConfirmation` within AUDIT_COUNTDOWN_TXS invocations.
    /// If Lambda fails to comply, the AVM interpreter self-terminates.
    #[serde(default)]
    pub audit_demand: Option<AuditDemand>,

    // === YPX-009 Silicon Pulse ===

    /// Audit request from AVM (YPX-009 §4.3).
    /// When present, Lambda must re-execute selected TXs and provide
    /// PulseAuditResponse in next PublicInputs.
    #[serde(default)]
    pub audit_request: Option<PulseAuditRequest>,

    /// Nonce challenge from AVM (YPX-009 §3.6).
    /// Lambda must look up the target wallet and respond with NonceResponse.
    #[serde(default)]
    pub nonce_challenge: Option<NonceChallenge>,

    /// Pulse proof data from AVM after successful audit (YPX-009 §5.1).
    /// Lambda forwards to Nabla for gossip broadcast.
    #[serde(default)]
    pub pulse_proof: Option<PulseProofData>,

    /// AVM detected audit failure (YPX-009 §4.5).
    /// Lambda should log and initiate restart.
    #[serde(default)]
    pub audit_failed: bool,

    /// Decremented TTL for fan-out forwarding (CL10 only).
    /// Lambda MUST use this value — cannot inflate.
    #[serde(default)]
    pub fanout_new_ttl: Option<u8>,

    /// CL11: Console chain hash of the verified new certificate.
    /// Lambda uses this to confirm Core accepted the election result.
    pub console_chain_hash: Option<[u8; 32]>,

    /// Receipt commitment — BLAKE3("AXIOM_RECEIPT_v1" || txid || state_hash
    /// || produced_state_id || new_wallet_seq || commitment_hash || epoch).
    /// Core computes this from its own outputs. Lambda signs it with
    /// Ed25519 and includes in WitnessSig.receipt_commitment_sig.
    /// CL2 on the next TX recomputes from receipt fields and verifies
    /// k signatures match — prevents receipt fabrication.
    #[serde(default)]
    pub receipt_commitment: Option<[u8; 32]>,

    /// CL13 (`VALIDATOR_WITHDRAWAL_MINT`) output. `Some` only when CL13
    /// accepted the proof and computed a net mint amount; `None` in
    /// every other mode and on any CL13 rejection. Lambda assembles the
    /// chosen-witness round around this — k=3 sign the mint receipt
    /// over this field. Nabla then verifies witnesses signed the same
    /// `(validator_id, linked_wallet_id, net_amount, claimed_through_tick)`
    /// tuple before advancing `last_claimed_tick`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator_withdrawal_mint: Option<ValidatorWithdrawalMintOutput>,

    /// Dev-class flag carried back from Core to Lambda so the Receipt
    /// Lambda builds (`receipt.rs::build_*_receipt`) stamps the SAME
    /// value Core just bound into `receipt_commitment`. Source of
    /// truth lives in Core (`modes.rs` CL3 reads
    /// `is_dev_wallet(tx.sender_wallet_id)`, CL5 cross-checks every
    /// cheque in the bundle); Lambda mirrors by copying this field
    /// onto the Receipt verbatim. `None` from non-TX modes is treated
    /// as `false` at the caller. See
    /// `AXIOM_DESIGN_FactClassIsolation.md`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_dev_class: Option<bool>,

    /// YPX-021 §8.2: the OODS health flag Core just derived from the
    /// verified `PublicInputs::oods_attestation` and bound into
    /// `receipt_commitment`. Carried back so Lambda/SDK stamp the SAME
    /// value onto `Receipt.oods_flag` (mirror of the `is_dev_class`
    /// pattern — source of truth lives in Core). `None` when no
    /// attestation was supplied (heal / genesis claim, Phase 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oods_flag: Option<OodsFlag>,

    /// YPX-020: the hibernation deadline the produced state carries after a HAL
    /// re-anchor (`Transaction::produced_hibernation_until()` — `epoch +
    /// HIBERNATION_WINDOW` ticks projected onto the unix-second stamp); `0` for
    /// every other tx. This is the SAME value `compute_new_state_hash` folds into
    /// the state hash, so Lambda persisting it keeps the stored state in lock-step
    /// with what k=3 witnessed (the §15 anchor recomputes with it). The Core CL2
    /// gate reads the PRIOR state's value and rejects `WalletHibernating` while
    /// `tx.epoch < hibernation_until`. Skipped from the wire when 0 so normal-tx
    /// output encodings are byte-unchanged.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub hibernation_until: u64,
}

/// CL13 mint result. Bound into the witness round's receipt commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorWithdrawalMintOutput {
    /// Validator whose pool is being drained. BLAKE3(sphincs_pk).
    pub validator_id: [u8; 32],
    /// Wallet that receives the mint (`pool_linkage.linked_wallet_id`).
    pub linked_wallet_id: [u8; 32],
    /// Atoms minted into `linked_wallet_id`. Equals
    /// `earnings_attestation.total_amount × 90 / 100` (10% stays in
    /// Nabla's deed_pool, already credited at /register time).
    pub net_amount: u64,
    /// Tick the validator is claiming through (= `until_tick` of the
    /// signed earnings attestation). Lambda includes this in the
    /// `MarkValidatorEarningsClaimedRequest` it sends post-mint;
    /// Nabla strict-monotonically advances `last_claimed_tick` to
    /// this value.
    pub claimed_through_tick: u64,
}

// === §23.14: Peer Audit Demand (The Ping Defense) ===

/// Audit demand constants
pub const AUDIT_TRIGGER_RATE: u64 = crate::validation::protocol_gen::AUDIT_TRIGGER_RATE;    // ~1 in 100 TXs triggers audit
pub const AUDIT_COUNTDOWN_TXS: u8 = 10;     // Self-audit: Lambda has 10 TXs to confirm
pub const PEER_AUDIT_COUNTDOWN_TXS: u8 = 100;  // Peer-audit: 100 TXs (email round-trip budget)
pub const PEER_AUDIT_TIMEOUT_SECS: u64 = crate::validation::protocol_gen::PEER_AUDIT_TIMEOUT_SECS;  // Peer-audit: 10 minutes wall-clock timeout
/// Ban duration: 24 hours as a TICK count (a tick is <=5s wall clock, so
/// 24h = 86400s / TICK_INTERVAL_SECS = 17280 ticks). Like HIBERNATION_WINDOW,
/// this is projected onto `epoch` unix-second stamps by multiplying by
/// TICK_INTERVAL_SECS — the ban holds for AT LEAST this many ticks.
/// NEVER compared against SystemTime::now().
pub const PEER_AUDIT_BAN_TICKS: u64 = crate::validation::protocol_gen::PEER_AUDIT_BAN_TICKS;
pub const PEER_AUDIT_CRASH_DELAY_SECS: u64 = crate::validation::protocol_gen::PEER_AUDIT_CRASH_DELAY_SECS; // Remote crash delay: 3 minutes (time for ANTIE to send response)

/// An audit demand generated by Core during CL2/CL3 execution.
///
/// Core deterministically selects a target validator from the current
/// transaction's witness set and demands that Lambda (the operator)
/// initiate an audit of that validator.
///
/// If Lambda does not provide an `AuditConfirmation` within
/// `AUDIT_COUNTDOWN_TXS` subsequent Core invocations, the AVM
/// interpreter refuses to execute — effectively terminating Core.
/// Restart incurs VBC re-verification, ZK benchmark, and operational
/// downtime: a real cost that makes non-compliance irrational.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditDemand {
    /// The challenge nonce (derived deterministically from txid).
    /// Lambda must echo this in the confirmation to prove it responded
    /// to this specific demand.
    pub challenge_nonce: [u8; 32],

    /// Public key of the validator to audit (selected from prev_receipts
    /// witness set of the current transaction).
    pub target_validator_pk: Vec<u8>,

    /// The txid that triggered this audit (for traceability).
    pub trigger_txid: [u8; 32],
}

/// Confirmation that Lambda performed the demanded audit.
///
/// §23.14 Audit confirmation — Lambda's response to an AuditDemand.
///
/// **Self-audit** (target == our PK): Lambda looks up trigger_txid in its DB
/// and sends back the raw stored fields. Core hashes them and compares against
/// the TxDigest in the audit buffer. Lambda does zero crypto.
///
/// **Peer-audit** (target != our PK): Lambda sends PeerAuditRequest via ANTIE
/// email. Remote Lambda looks up txid in DB, remote Core verifies. Response
/// hash is compared locally by Core. See PeerAuditRequest/PeerAuditResponse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfirmation {
    /// Must match the `challenge_nonce` from the `AuditDemand`.
    pub challenge_nonce: [u8; 32],

    /// Target validator's public key (must match demand).
    pub target_validator_pk: Vec<u8>,

    /// Raw DB data — Lambda sends these as-is, Core hashes and verifies.
    /// Lambda does ZERO crypto. Core is the sole cryptographic authority.
    /// tx_number is NOT included — Lambda doesn't know it (AVM-internal).
    /// AVM uses PendingAudit.trigger_tx_number to find the right entry.
    pub sender_balance: u64,
    pub receiver_balance: u64,
    pub state_id: [u8; 32],
    pub amount: u64,
}

// === §23.14.6: Peer Audit Protocol ===

/// Domain tag for peer audit hash computation.
pub const PEER_AUDIT_HASH_DOMAIN: &[u8] = b"AXIOM_PEER_AUDIT_V1";

/// Peer audit request — sent to remote validator via ANTIE email.
///
/// Contains the txid to audit and the hash computed by local Core from its
/// audit buffer. Remote Core uses the hash to verify its own Lambda's DB
/// integrity. The ping payload is minimal: txid + hash only.
///
/// Core computes the hash. Lambda carries it. Lambda does zero crypto.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAuditRequest {
    /// The txid to audit — remote Lambda looks this up in its DB.
    pub txid: [u8; 32],

    /// BLAKE3("AXIOM_PEER_AUDIT_V1" || txid || sender_balance || receiver_balance || state_id || amount)
    /// computed by local Core from its audit buffer. Remote Core independently
    /// computes the same hash from remote Lambda's DB data and compares.
    pub expected_hash: [u8; 32],

    /// Challenge nonce from the original AuditDemand (binding).
    pub challenge_nonce: [u8; 32],

    /// Requesting validator's public key (so remote knows who asked).
    pub requester_pk: Vec<u8>,
}

/// Peer audit response — sent back from remote validator via ANTIE email.
///
/// Contains the hash that remote Core computed from remote Lambda's raw DB data.
/// Local Core compares this against its own expected_hash.
///
/// Remote Core computes the hash from raw DB fields. Lambda carries it.
/// If remote Core detects mismatch (its own Lambda tampered), it waits
/// 3 minutes (PEER_AUDIT_CRASH_DELAY_SECS) for ANTIE to send this response,
/// then exits. The response hash will be wrong — local Core will ban.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAuditResponse {
    /// The txid that was audited.
    pub txid: [u8; 32],

    /// Hash computed by remote Core: BLAKE3("AXIOM_PEER_AUDIT_V1" || txid || fields...)
    /// from remote Lambda's DB data. If remote Lambda's DB is honest, this matches
    /// the expected_hash from the request.
    pub computed_hash: [u8; 32],

    /// Challenge nonce echo (binding to original demand).
    pub challenge_nonce: [u8; 32],

    /// Responding validator's public key.
    pub responder_pk: Vec<u8>,
}

/// Reason a validator was banned in peer-audit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PeerAuditBanReason {
    /// Peer responded with wrong hash — DB tampering detected.
    HashMismatch,
    /// Peer did not respond within 100 TXs / 10 minutes.
    NonResponds,
}

/// A banned validator entry — tracked in AVM (survives across TXs, clears on restart).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAuditBanEntry {
    /// Banned validator's public key.
    pub validator_pk: Vec<u8>,

    /// When the ban was imposed — the validated TARDIS tick stamp (the TX
    /// `epoch`, a unix-second-valued stamp per TICK_INTERVAL_SECS docs),
    /// NEVER SystemTime::now().
    pub banned_at_tick: u64,

    /// Why the ban was imposed.
    pub reason: PeerAuditBanReason,
}

// === §6.9 / §11.5: Ark Mode ⟠ — Offline Operation ===

/// Ark artifact — a locally generated, signed intent record for offline trading.
///
/// Created when sender transfers ⟠ value offline. Both sender and receiver
/// run Core/AVM locally with DMAP. No validators, no k=3.
///
/// The artifact is NOT a transaction — it becomes one at reconciliation.
/// Contains the transaction, sender's DMAP attestation hash, and Confidence Index.
///
/// Per White Paper §6.9: "Ark-Mode does not create valid transactions.
/// It preserves transaction intent under disconnection."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArkArtifact {
    /// The intended transaction (same Transaction struct as online TXs)
    pub transaction: Transaction,

    /// Reference to sender's last known valid wallet state_id
    pub last_state_id: [u8; 32],

    /// Locally monotonic nonce — prevents replay within offline chain.
    /// Each artifact from the same wallet increments this.
    pub ark_nonce: u64,

    /// BLAKE3 hash of sender's DMAP attestation for this execution.
    /// Proves Core/AVM ran locally and accepted the transaction.
    /// Receiver can verify by re-executing through their own AVM.
    pub dmap_attestation_hash: [u8; 32],

    /// Hash of previous artifact in this wallet's offline chain.
    /// None for the first offline TX after loading.
    /// Chains offline TXs within a single wallet (ordering guarantee).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_artifact_hash: Option<[u8; 32]>,

    /// Sender's Confidence Index — issued by validators during last online session.
    /// Cryptographically signed, sender cannot forge.
    /// Receiver inspects CI to decide whether to accept (GREEN/YELLOW/RED).
    pub confidence_index: ConfidenceIndex,

    /// Timestamp of artifact creation (sender's local clock — untrusted).
    pub created_at_secs: u64,
}

/// Confidence Index (CI) — offline risk assessment for Ark ⟠ trades (YPX-010).
///
/// Computed by the RECEIVER from the sender's FACT chain. Not pre-issued.
/// The receiver reads the FACT chain, extracts the five trust factors, and
/// Core evaluates them against the CI matrix to produce GREEN/YELLOW/RED.
///
/// All five factors are computable offline from the FACT chain alone.
/// No network queries. No external oracles.
///
/// Status mapping (YPX-010 §4):
///   GREEN  — Low risk, normal offline acceptance
///   YELLOW — Moderate risk, reduced limits or extra caution
///   RED    — High risk, offline payment discouraged or refused
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceIndex {
    /// Wallet public key this CI belongs to
    pub wallet_pk: Vec<u8>,

    // === Factor 1: K=3 Staleness (YPX-010 §2 Factor 1) ===

    /// Unix timestamp of last successful k=3 validation (from FACT chain)
    pub last_k3_at: u64,

    // === Factor 2: Ark TX Count Since Last K=3 (YPX-010 §2 Factor 2) ===

    /// Number of Ark (k=0) transactions since last k=3 (from FACT chain)
    pub ark_tx_count_since_k3: u64,

    // === Factor 3: Stakes Ratio (YPX-010 §2 Factor 3) ===

    /// Wallet balance at last k=3 transaction (from FACT chain)
    pub k3_balance: u64,

    // === Factor 4: TX vs History Pattern (YPX-010 §2 Factor 4) ===

    /// Mean transaction amount from prior Ark links (from FACT chain)
    pub ark_tx_mean_amount: u64,

    // === Factor 5: Validator Ecosystem Depth (YPX-010 §2 Factor 5) ===

    /// Number of distinct validators that have processed prior Ark settlements
    pub ark_validator_count: u8,

    // === Override checks ===

    /// Whether a FACT scar is present in the chain
    pub has_fact_scar: bool,

    /// Whether the wallet has ever had a k=3 transaction
    pub has_any_k3: bool,

    /// Number of detected double-spend conflicts (lifetime)
    pub conflict_count: u64,

    // === Validator attestation (optional, for online-issued CI) ===

    /// Validator-signed attestation over CI fields (optional).
    /// Present when CI was issued online by a validator.
    /// Absent when CI is computed locally by receiver from FACT chain.
    #[serde(default)]
    pub validator_signature: Vec<u8>,

    /// Public key of the validator who signed this CI (if any)
    #[serde(default)]
    pub issuer_validator_pk: Vec<u8>,
}

/// Domain tag for Confidence Index signing
pub const CI_DOMAIN: &[u8] = b"AXIOM_CI_V1";

/// Domain tag for Ark artifact hashing
pub const ARK_ARTIFACT_DOMAIN: &[u8] = b"AXIOM_ARK_ARTIFACT_V1";

// === YPX-009: Silicon Pulse — Core-Initiated Lambda Audit ===

/// Silicon Pulse constants (YPX-009 §4/§8)
///
/// Dual-trigger audit design:
///   TIME:  every 5 minutes, audit fires regardless of TX count.
///          Catches low-traffic validators (even 1 TX/hour gets audited).
///   COUNT: buffer reaches 80% of PULSE_BUFFER_MAX (prevents overflow).
///          High-traffic validators don't accumulate unbounded entries.
///
/// Sample sizing: 10% of buffer contents, randomly selected (Fiat-Shamir).
///   Lambda can't predict which 10% — must keep ALL entries honest.
///   Detection probability per audit (if Lambda tampers with 5% of TXs):
///     5 entries sampled: 23%    | 50 entries: 92%    | 160 entries: 99.98%
///   Multiple audits compound: after 3 audits with 50 samples, detection > 99.9%.
///
/// Argon2id uses 32MB (32768 KiB) per call — exceeds L3 cache on commodity
/// hardware (8-36MB) where attacks are likely. Primary purpose: tamper-evident
/// chain ensuring Lambda records data honestly. Secondary: detect multi-validator
/// co-location. High-end server CPUs (64-384MB L3) are not the threat model —
/// operators with such hardware are traceable and have skin in the game.
/// Time trigger: audit fires every 5 minutes regardless of TX count.
pub const PULSE_AUDIT_INTERVAL_SECS: u64 = crate::validation::protocol_gen::PULSE_AUDIT_INTERVAL_SECS;

/// Hard cap on buffer entries. Prevents unbounded memory growth.
/// At 32MB Argon2id (~30ms/call release), 2000 entries = ~60 seconds
/// of accumulated work. Buffer memory: 2000 × ~105 bytes ≈ 210 KB.
pub const PULSE_BUFFER_MAX: u32 = 2000;

/// Count trigger ratio: audit fires when buffer reaches this fraction of max.
/// 80% = 1600 entries, leaving 20% headroom before hard cap.
pub const PULSE_BUFFER_TRIGGER_RATIO: f64 = 0.80;

/// Sample ratio: fraction of buffer entries to audit per cycle.
/// 10% keeps replay under 9 seconds at max buffer (160 entries × 55ms).
/// Random Fiat-Shamir selection ensures Lambda can't predict which entries.
pub const PULSE_SAMPLE_RATIO: f64 = 0.10;

pub const PULSE_AUDIT_BASELINE_MS: f64 = 50.0;           // reference DMAP time (Pi-class)
pub const PULSE_AUDIT_DEADLINE_TICKS: u64 = 60;          // 300s to respond to audit
pub const PULSE_EPOCH_LENGTH_TICKS: u64 = 720;           // 1 hour — pulse evaluation window
pub const PULSE_MISS_TOLERANCE: u32 = 3;                 // miss 3 → degraded
pub const PULSE_MISS_EVICTION: u32 = 10;                 // miss 10 → evicted
pub const PULSE_GRACE_CYCLES: u32 = 6;                   // new nodes get 6 epochs grace
pub const NONCE_MISMATCH_TOLERANCE: u32 = 3;             // 3 consecutive mismatches → audit_failed

/// Calibration benchmark duration in milliseconds.
/// Longer = more accurate, but delays startup. 200ms is a good balance.
pub const PULSE_CALIBRATION_MS: u64 = 200;

/// Transaction digest stored in AVM audit buffer (YPX-009 §3.4).
/// Captures financial/state integrity fields only — the data Lambda stores
/// in its DB and could tamper with. DMAP has its own independent verification
/// path (re-execution, Merkle proofs). Mixing would couple two security layers
/// and break ZKP-mode validators that don't use DMAP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxDigest {
    /// Transaction sequence number (monotonic per AVM instance)
    pub tx_number: u64,
    /// Sender balance at time of TX
    pub sender_balance: u64,
    /// Receiver balance at time of TX (0 if unknown)
    pub receiver_balance: u64,
    /// Produced state_id from Core (SHA3-256)
    pub state_id: [u8; 32],
    /// Transaction amount
    pub amount: u64,
}

impl TxDigest {
    /// Serialize to canonical bytes for hashing (Argon2id input, audit verification).
    /// Domain-tagged: "AXIOM_TX_DIGEST" prefix ensures no collision with other hashes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(b"AXIOM_TX_DIGEST");
        buf.extend_from_slice(&self.tx_number.to_le_bytes());
        buf.extend_from_slice(&self.sender_balance.to_le_bytes());
        buf.extend_from_slice(&self.receiver_balance.to_le_bytes());
        buf.extend_from_slice(&self.state_id);
        buf.extend_from_slice(&self.amount.to_le_bytes());
        buf
    }

    /// Build TxDigest from AuditConfirmation raw fields + stored tx_number.
    /// Used by Core to reconstruct the digest for verification.
    /// tx_number comes from PendingAudit (AVM-internal), not from Lambda.
    pub fn from_confirmation(conf: &AuditConfirmation, tx_number: u64) -> Self {
        TxDigest {
            tx_number,
            sender_balance: conf.sender_balance,
            receiver_balance: conf.receiver_balance,
            state_id: conf.state_id,
            amount: conf.amount,
        }
    }
}

/// Audit request emitted by AVM when buffer is full (YPX-009 §4.3).
/// Attached to PublicOutputs. Lambda must re-execute selected TXs
/// and return an AuditResponse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PulseAuditRequest {
    /// Selected entry indices into the buffer (ordered)
    pub selected_indices: Vec<u32>,
    /// The tx_number for each selected entry (AVM-internal sequence)
    pub tx_numbers: Vec<u64>,
    /// produced_state_id for each selected entry (Lambda DB lookup key)
    pub state_ids: Vec<[u8; 32]>,
    /// Core's chain hash over the selected subset (the expected answer)
    pub expected_hash: [u8; 32],
    /// Epoch number (for freshness)
    pub epoch: u64,
}

/// Audit response from Lambda (YPX-009 §4.4).
/// Lambda sends back raw DB fields — zero crypto. Core replays
/// Argon2id→BLAKE3 chain and compares against expected_hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PulseAuditResponse {
    /// Raw TX data from Lambda's DB (one per requested TX, in order).
    /// Core replays Argon2id→BLAKE3 chain over these to verify.
    pub entries: Vec<TxDigest>,
    /// Epoch (must match request)
    pub epoch: u64,
}

/// Nonce challenge emitted by AVM every TX (YPX-009 §3.6).
/// AVM picks a random wallet from its cache and asks Lambda to prove
/// it still holds the correct state for that wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceChallenge {
    /// Which wallet to look up
    pub target_wallet_pk: [u8; 32],
    /// Expected state_id (from AVM's wallet cache)
    pub expected_state_id: [u8; 32],
}

/// Nonce response from Lambda (YPX-009 §3.6).
/// Lambda looks up the wallet in its DB and returns current state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceResponse {
    /// The wallet that was looked up
    pub target_wallet_pk: [u8; 32],
    /// Current state_id in Lambda's DB
    pub current_state_id: [u8; 32],
    /// Current balance in Lambda's DB
    pub current_balance: u64,
}

/// Pulse proof data emitted by AVM after successful audit (YPX-009 §5.1).
/// Lambda forwards this to Nabla for gossip broadcast.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PulseProofData {
    /// Global epoch number at time of audit
    pub epoch: u64,
    /// Core's accumulator over the audited buffer
    pub full_accumulator: [u8; 32],
    /// Total entries in audit buffer at trigger time.
    pub entry_count: u32,
    /// Number of entries selected for re-execution (PULSE_SAMPLE_RATIO × entry_count)
    pub sample_size: u32,
    /// Hash of the audit response (proves Lambda responded correctly)
    pub audit_hash: [u8; 32],
    /// Measured Argon2id(64MB,t=1) throughput (iterations/sec).
    /// Reported for peer validation — peers can compare expected vs actual.
    #[serde(default)]
    pub argon2id_per_sec: u64,
}

// === YPX-007: ZKP Qualification ===

/// ZKP qualification constants
pub const ZKP_QUAL_THRESHOLD_SECS: u64 = 5;
pub const ZKP_QUAL_TTL_SECS: u64 = 86_400; // 24 hours

/// ZKP qualification state — lives in Core, not Lambda.
/// Core generates the benchmark challenge, verifies the STARK proof,
/// measures elapsed time, and decides qualification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualificationState {
    pub zkp_qualified: bool,
    pub qualified_at: Option<u64>,
    pub qual_ttl_secs: u64,
}

impl Default for QualificationState {
    fn default() -> Self {
        Self {
            zkp_qualified: false,
            qualified_at: None,
            qual_ttl_secs: ZKP_QUAL_TTL_SECS,
        }
    }
}

impl QualificationState {
    pub fn is_valid(&self, current_time: u64) -> bool {
        self.zkp_qualified
            && self.qualified_at
                .map(|t| current_time.saturating_sub(t) < self.qual_ttl_secs)
                .unwrap_or(false)
    }
}

/// Validation errors
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationError {
    // State errors
    StateIdAlreadyConsumed,
    InvalidStateId,

    /// §15: client-supplied `current_state.balance` / `wallet_seq` does NOT
    /// re-derive to `prev_receipts.last().state_hash`. Either the SDK shipped
    /// state from a different chain timeline (stale wallet against fresh env,
    /// pre-rebuild Mac client, etc) or Lambda fell back to a default-zero
    /// state. Recovery: `RecoveryHint::ClaraHealNextSend` — the wallet must
    /// heal-forward to re-anchor cryptographically. See CLAUDE.md §15 +
    /// `docs/AXIOM_HANDOFF_MacClientStaleState.md`.
    StateNotAnchored,


    // Wallet sequence errors
    InvalidWalletSeq,
    WalletSeqOverflow,
    
    // Wallet ID errors
    InvalidWalletId,
    MalformedAddress,
    
    // Signature errors
    InvalidClientSignature,
    InvalidWitnessSignature,
    UnsupportedSignatureAlgorithm,
    
    // Balance errors
    InsufficientBalance,
    ConservationViolation,
    ZeroAmount,  // C2 fix: Explicit rejection of amount=0
    DustAmount,  // G2 fix: Rejection of amount below MINIMUM_TX_ATOMS (anti-spam)
    
    // VBC errors
    InvalidVBC,
    /// VBC `expires_at` is in the past. Carries the expiry tick and
    /// the validator's current tick view so clients can populate
    /// `VbcLifecycleDetail` (§4 Errors YP). Phase 2b.14 upgrade from
    /// a unit variant — breaking ValidationError enum shape change,
    /// requires ELF rebuild.
    VBCExpired { expires_at: u64, current_tick: u64 },
    /// VBC `issued_at` is in the future. Same shape as VBCExpired.
    VBCNotYetValid { issued_at: u64, current_tick: u64 },
    VBCChainTooDeep,
    VBCMissingIssuer,
    /// CRITICAL: VBC issuer claims to be root-level (chain_depth=0) but issuer PKs
    /// do not match any compiled ROOT_AUTHORITY_PKS. This means either:
    /// 1. Core was compiled with stale genesis.rs (re-run ceremony, paste constants, rebuild)
    /// 2. A mirror universe attack — VBC signed by keys outside this universe's trust root
    ///    Either way, this validator MUST NOT process any transactions until resolved.
    VBCRootKeyMismatch,
    DuplicateValidator,
    InvalidVBCCount,
    
    // Genesis errors
    MissingPrevReceipts,
    InvalidGenesisTransaction,
    
    // Proof errors
    InvalidExecutionProof,
    ProgramDigestMismatch,
    
    // JSON errors
    InvalidCanonicalJson,
    
    // Cheque errors
    InsufficientCheques,
    InconsistentChequeBundle,
    InvalidChequeSignature,
    ChequeAlreadyRedeemed,
    /// A2: redeem requires a non-empty sender_fact_chain on the cheque
    /// bundle (or its first ValidatorCheque). The chain's tip becomes
    /// the redeem link's sender_anchor. Without it, the receiver's
    /// chain cannot be anchored to the sender's verified provenance.
    RedeemSenderAnchorMissing,

    /// YP §17.10.5.3 — Core CL5 rejects a redeem whose sender FACT
    /// chain tip carries a `NablaConfirmation` with
    /// `committed_at_tick >= inputs.current_tick`.  The redeem must
    /// happen at least 1 TARDIS tick after the sender's commit, so
    /// gossip has had time to propagate that commit through the
    /// Nabla mesh before any receiver redeems against it.
    /// Scarred links (no NablaConfirmation) are exempt — Ark-mode
    /// operation continues unchanged.
    RedeemBeforeCommitPropagated,

    // YPX-014 Txid attestation errors (CL5)
    TxidAttestationMissing,    // No attestation provided
    TxidAttestationInvalidSig, // Ed25519 signature verification failed
    TxidAttestationRedeemed,   // Status is REDEEMED (global double-redeem)
    TxidAttestationBadStatus,  // Status is not "NOT_REDEEMED" or "REDEEMED"
    TxidAttestationUntrusted,  // Attester PK not in trusted set (not a known Nabla node)

    // Cheque-claim-proof errors (CL5, synchronous double-redeem prevention)
    /// No `cheque_claim_proof` provided in PublicInputs.  This is the
    /// proof the Nabla writer signs on successful `register_cheque_claim`;
    /// missing it means the receiver bypassed the §4.6 verify path —
    /// reject hard, no soft fallback (CLAUDE.md §13).
    ChequeClaimProofMissing,
    /// Ed25519 signature on the claim proof failed verification.
    ChequeClaimProofInvalidSig,
    /// Proof's `cheque_id` doesn't match the redeem's bundle txid — proof
    /// was for a different cheque (stolen / forwarded).
    ChequeClaimProofTxidMismatch,
    /// Proof's `client_pk` doesn't match the redeem's `receiver_pk` —
    /// proof was issued to a different wallet (replay across receivers).
    ChequeClaimProofReceiverMismatch,
    /// Proof's `nabla_node_pk` is not bound by a valid NBC chained back
    /// to a Nabla root authority.  Catches self-signed forgeries.
    ChequeClaimProofUntrusted,
    /// Defense-in-depth: the redeem's txid already appears in the
    /// receiver's FACT chain.  Closes the post-finalization replay
    /// window even when Nabla state is unavailable.
    TxidAlreadyInReceiverChain,
    /// Cheque-claim proof's tick is outside the freshness window —
    /// the Nabla writer's claim entry would have expired (24h TTL),
    /// so the proof no longer represents a current reservation.
    ChequeClaimProofExpired,

    // Redeem errors (CL5)
    RedeemBalanceMismatch,     // old_balance + amount != new_balance
    RedeemBalanceOverflow,     // Addition would overflow u64
    MissingExecutionProof,     // Witness has empty execution_proof (§37)
    MissingRedeemInputs,       // Required CL5 fields not provided
    MissingVBC,                // VBC bundle required (production mode)

    // Fee ledger errors (YP §19.6 amendment — receiver-pays-only fee model)
    /// A single validator's fee_breakdown slot exceeds MAX_VALIDATOR_FEE_BPS
    /// (30 bps = 0.30%) of the transaction amount.
    FeeExceedsValidatorCap,
    /// The sum of fee_breakdown slots exceeds MAX_TOTAL_TX_FEE_BPS
    /// (90 bps = 0.90%) of the transaction amount.
    FeeExceedsAggregateCap,
    /// The sum of fee_breakdown slots is greater than the transaction amount
    /// (no fees can exceed the value being moved). Defense-in-depth — the
    /// aggregate cap already enforces this for non-zero amounts; this guards
    /// the amount=0 / dust edge cases.
    FeeExceedsAmount,
    /// A WitnessSig's `slot_amount` doesn't equal
    /// `min(rate_bps, MAX_VALIDATOR_FEE_BPS) × amount / FEE_BPS_DIVISOR`.
    /// Either the validator signed an inconsistent (rate, slot) pair or a
    /// downstream actor tampered with one of the two fields. Every Core that
    /// touches the receipt re-derives the slot and rejects on mismatch.
    /// Closes the "SDK can lie about a validator's fee" gap.
    FeeSlotMathInvalid,
    /// A `receipt.fee_breakdown[i].amount` doesn't equal the corresponding
    /// `witness_sigs[i].slot_amount`. The SDK is supposed to assemble the
    /// fee_breakdown mechanically by copying each WitnessSig's slot_amount;
    /// a mismatch means the SDK either substituted an amount or skipped a
    /// signer. CL5 receiver-side check.
    FeeSlotReceiptMismatch,
    /// `receipt.fee_breakdown.len() != witness_sigs.len()`. The SDK shipped
    /// a different number of slots than signers; CL5 rejects rather than
    /// guessing which side is right.
    FeeSlotCountMismatch,
    
    // Carrier errors (Section 26.9.3)
    CarriersTooLarge,     // Total carriers exceed 512 bytes
    
    // Validator hint errors (Section 27.5)
    InvalidHintCount,     // Validators MUST include 0-3 hints (max 3)
    SelfHintNotAllowed,   // Validator MUST NOT include own contact in hints
    
    // S-ABR overlap errors (CL3)
    SABRInsufficientOverlap,   // Fresh validator: not enough overlapped sigs
    SABROverlapNotInPrev,      // Overlapped sig PK not found in prev_receipts
    SABRMissingValidatorPK,    // CL3 called without my_validator_pk
    SABRHashMismatch,          // CL3: Lambda's reported state doesn't match client's consumed_state_id
    
    // YPX-007: Security level errors
    ZkpNotQualified,        // Validator not qualified to provide ZKP service
    ArkNotImplemented,      // k=0 Ark mode not yet implemented

    // YPX-012: Oracle claim errors
    OracleSenderMismatch,          // sender != receiver (oracle is self-payout only)
    OracleInsufficientK,           // k < 5 (oracle requires k=5)
    OracleVBCTooOld,               // Witness VBC older than ORACLE_VBC_RENEWAL_TICKS (24h). Renew via CL8.
    OracleInsufficientStake,       // Validator balance < ORACLE_MIN_STAKE (1M AXC)
    OracleStakeScarred,            // Stake wallet has unresolved FACT scars — disqualifies oracle witnessing.
    OraclePlatformInvalid,         // platform URL not in whitelist
    OracleLivingSignatureMissing,  // username missing AXM_<hex> signature
    OracleZeroDelta,               // credit_delta == 0 (no new work)
    OracleNonZeroAmount,           // oracle TX must have amount == 0
    OracleMaturityNotReached,      // cheque age < 48h at redeem

    // Reference field
    ReferenceTooLarge,             // reference > 256 bytes (DoS prevention)

    // CL13 — validator-withdrawal mint (YP §20.10 Step 9B+)
    /// CL13 dispatched without `PublicInputs.withdrawal_inputs`
    /// populated. Caller bug — Lambda must set the withdrawal input
    /// bundle before driving CL13.
    WithdrawalInputsMissing,
    /// SPHINCS+ identity binding failed: `BLAKE3(sphincs_pk) !=
    /// validator_id`. Forged or mismatched binding.
    WithdrawalIdMismatch,
    /// Fewer than k=3 distinct chosen_witnesses provided. Mirrors
    /// Lambda's `REJECTED_WITNESS_COUNT`.
    WithdrawalWitnessCount,
    /// chosen_witnesses contains duplicates. Mirrors Lambda's
    /// `REJECTED_WITNESS_DUPLICATE`.
    WithdrawalWitnessDuplicate,
    /// Earnings attestation came from a bloom-mode Nabla node
    /// (`is_authoritative == false`). Mirrors Lambda's
    /// `REJECTED_NOT_AUTHORITATIVE`.
    WithdrawalNotAuthoritative,
    /// Nabla earnings attestation Ed25519 signature failed to verify
    /// against the recomputed canonical hash. Tampering with totals,
    /// entries, or per-entry fee_breakdowns.
    WithdrawalEarningsSig,
    /// Pool linkage `validator_id` doesn't match the operator's
    /// declared `validator_id`. Mirrors `REJECTED_POOL_VID_MISMATCH`.
    WithdrawalPoolVidMismatch,
    /// Operator hasn't called RegisterValidatorPool yet, or
    /// `linked_wallet_id` is zero. Mirrors `REJECTED_POOL_NOT_REGISTERED`.
    WithdrawalPoolNotRegistered,
    /// SPHINCS+ withdrawal authorization signature didn't verify over
    /// the canonical `compute_validator_withdrawal_payload` bytes —
    /// operator didn't sign THIS specific
    /// (validator_id, attestation_hash, chosen_witnesses) tuple.
    WithdrawalSig,
    /// §20.10 disjoint-witness violation: at least one chosen_witness
    /// appears in an earnings entry's `full_fee_breakdown`. Mirrors
    /// Lambda's `REJECTED_CONFLICT_OF_INTEREST`.
    WithdrawalConflictOfInterest,

    // Other
    InvalidMode,
    InternalError,
    
    // Auth hash errors (wallet owner protection)
    AuthHashRequired,       // Wallet has auth_hash but tx missing owner_proof
    InvalidAuthProof,       // owner_proof verification failed
    
    // Lineage binding errors (YP §23.11)
    ReceiptFromWrongWorldline,  // SDID mismatch — receipt from different fork
    ReceiptLineageMismatch,     // Lineage hash not from our upgrade path
    ReceiptCommitmentMismatch,  // Receipt fields don't match k-validator signed commitment
    
    // Group wallet errors
    GroupTooManyMembers,        // members.len() > MAX_GROUP_MEMBERS (32)
    GroupShareBpsInvalid,       // sum(share_bps) != 10000
    GroupNotMember,             // withdrawal destination is not a member's wallet_id
    GroupInsufficientAvailable, // withdrawal amount > member's available balance
    GroupChecksumFailed,        // sum(available) != balance
    GroupMembersImmutable,      // attempted to change members list
    GroupDistributionOverflow,  // distribution math would overflow
    GroupMemberMismatch,        // client_pk does not match members[index].member_pk
    
    // FACT chain errors (YPX-001)
    FactChainTooDeep,           // chain.links exceeds limit (Core's MAX_TOTAL_LINKS or operator's max_fact_links); self-send heal exempt
    FactChainBreak,             // state_id discontinuity between links
    FactInsufficientWitnesses,  // link has <3 witnesses
    FactInvalidSignature,       // witness signature doesn't verify
    FactDuplicateWitness,       // same validator_id appears twice in a link
    FactInvalidCheckpoint,      // checkpoint integrity failure
    FactChainEmpty,             // SEC-11: checkpoint provenance anchor read from an empty link set
    FactAmountOverflow,         // SEC-11: checkpoint total_amount/compressed_count addition overflowed u64

    // Burn errors (YPX-001 §1.5.4)
    BurnNoFactChain,            // burn TX but sender has no FACT chain
    BurnMissingTarget,          // burn_target_tx_id set but receiver != BURN_ADDRESS (self-send heal-burn exempt)
    BurnTargetNotFound,         // target tx_id not found in sender's FACT chain
    BurnTargetNotScarred,       // target link already has nabla_confirmation (not scarred)
    BurnTargetAlreadyBurned,    // target link already has burn_proof
    BurnAmountMismatch,         // burn TX amount != scarred link amount

    // BurnProof structural errors (verify_fact_link / verify_fact_chain).
    // Closes pre-2026-05-07 forge: BurnProof { burn_tx_id: any, validator_sigs: vec![] }
    // made link.is_resolved() return true with zero verifier checks.
    BurnProofInsufficientWitnesses, // burn_proof.validator_sigs.len() < MIN_FACT_WITNESSES
    BurnProofDuplicateValidator,    // same validator_id twice in burn_proof.validator_sigs
    BurnTxIdNotInChain,             // burn_proof.burn_tx_id doesn't match any link's tx_id
    BurnTargetMismatch,             // named burn link's witnessed burn_target_tx_id != this scar (COPY forge, 2026-07-17)

    // Heal errors
    HealNotNeeded,              // is_heal=true but FACT chain last link has k witnesses (fully committed)

    // Scar cap
    TooManyUnresolvedScars,     // wallet has > MAX_UNRESOLVED_SCARS unhealed/unburned FACT links

    // Wallet state errors
    MissingWalletState,         // No wallet state — Lambda must provide it (no silent fallbacks)

    // Version errors
    VersionMismatch,            // Transaction core_version doesn't match this binary
    CoreIdMismatch,             // Transaction core_id (BLAKE3 of ELF) doesn't match validator's local Core ELF — non-poisoning, non-byzantine; wallet should not blacklist on this

    // CL9 scar heal signing errors
    MissingDilithiumKey,        // CL9 called without my_dilithium_sk
    MissingDilithiumPk,         // CL9 verify-after-sign requires my_dilithium_pk
    MissingField,               // Required input field not provided

    // Wallet secret errors
    WalletSecretMismatch,       // wallet_secret + pk don't match wallet_id checksum

    // Fan-Out errors (CL10, §18.8)
    FanOutMissingMessage,
    FanOutTtlExceeded,
    FanOutInvalidFanout,
    FanOutContentEmpty,
    FanOutContentTooLarge,
    FanOutTtlExpired,
    FanOutTtlInflated,
    FanOutUnknownContentType,
    FanOutTimestampFuture,
    FanOutTimestampExpired,
    FanOutDiffusionIdMismatch,
    FanOutInvalidOriginator,
    FanOutOriginatorPkMismatch,
    FanOutInvalidSignature,
    /// Candidate's stake is below the required tier minimum (CL8)
    InsufficientStake,
    /// Wallet is frozen by an approved JFP order (§7). All transactions rejected.
    WalletFrozen,
    /// sender_wallet_id does not match the wallet's stored identity (identity binding).
    /// Prevents lockup bypass and Ark policy spoofing.
    SenderWalletIdMismatch,
    /// Ark wallet (k=0) cannot send to non-Ark wallet (§11.9.2). Ark-to-Ark only.
    ArkToNonArkRejected,
    /// Only the wallet owner can charge their own Ark wallet (§11.9.1).
    ArkChargeNotOwner,
    /// Ark→Normal unload requires FACT chain fully clean — zero scars (§11.9.3).
    ArkUnloadScarred,
    /// Ark→Ark in the ONLINE witnessed pipeline is a category error: Ark-to-Ark
    /// is the OFFLINE trade (§11). (BUILD §2.2 "W7".)
    ArkOnlineTradeRejected,
    /// Self-send rejected — cannot send to own address except Ark (§11.9.4).
    SelfSendRejected,
    /// Receiver wallet_id has -XX email change suffix but no receiver_address provided.
    ReceiverAddressRequired,
    /// Receiver address has invalid checksum (typo protection).
    InvalidReceiverAddress,
    /// Nabla response is from a WRITER node — security violation. Core must exit.
    NablaWriterDetected,
    /// NablaStakeProof wallet_pk doesn't match VBC subject_pubkey_ed25519
    StakeWalletMismatch,
    /// NablaStakeProof Nabla attestation signature invalid
    StakeNablaSignatureInvalid,
    /// NablaStakeProof state mismatch (receipt_state_id != attested_state_id)
    StakeStateMismatch,
    /// NablaStakeProof has fewer than 3 valid receipt signatures
    StakeInsufficientReceipts,
    /// NablaStakeProof is too old (nabla_tick too far from current time)
    StakeProofExpired,

    // MVIB errors (YP §10)
    /// MVIB admission set is empty (must have k=3 issuers)
    MvibEmptyAdmissionSet,
    /// MVIB admission set has wrong size (must be exactly 3)
    MvibInvalidAdmissionSetSize,
    /// MVIB admission set contains duplicate validator IDs
    MvibDuplicateIssuer,
    /// MVIB signature verification failed
    MvibInvalidSignature,
    /// MVIB binding tick is zero (invalid)
    MvibInvalidTick,

    // Console errors (YPX-013)
    /// Console certificate generation doesn't increment by exactly 1
    ConsoleInvalidGeneration,
    /// Console certificate previous_link_hash doesn't match current certificate
    ConsoleChainMismatch,
    /// Console certificate doesn't have exactly CONSOLE_SIZE (15) seats
    ConsoleInvalidSeatCount,
    /// Console certificate has duplicate validator_ids in seats
    ConsoleDuplicateSeat,
    /// Console certificate term_start doesn't match previous term_end
    ConsoleTermMismatch,
    /// Console certificate term_end != term_start + TICKS_PER_YEAR
    ConsoleInvalidTermLength,
    /// Selector is not a member of the current Console
    ConsoleInvalidSelector,
    /// Selector picks contain validator not in nomination list
    ConsoleInvalidPick,
    /// Not all 3 selectors submitted picks
    ConsoleIncompleteSelection,
    /// Console action TX sender is not in Console seats
    ConsoleNotMember,

    // Genesis lockup errors (White Paper §2.10.1)
    /// Sender is a genesis validator wallet in the 3-year lockup period.
    GenesisStakeLocked,

    // YPX-018 — CLARA & Tiered Bloom Memory (v2.11.15)
    /// CLARA attestation Ed25519 signature verification failed.
    ClaraInvalidSignature,
    /// CLARA attestation `wallet_pk` does not match the witness request's wallet.
    ClaraWalletPkMismatch,
    /// Validator's stored state for this wallet is not in the attestation's
    /// `garbage_state_ids`. Cannot roll forward — the attestation does not
    /// describe a heal of this validator's poisoned state.
    ClaraStateNotGarbage,
    /// CLARA attestation NBC trust anchor failed (issuer not root authority,
    /// or SPHINCS+ signature invalid, or commitment mismatch).
    ClaraNbcTrustFailed,
    /// CLARA attestation `garbage_state_ids` is empty. Must declare at least
    /// one abandoned state.
    ClaraEmptyGarbage,
    /// Console BLOOM_PHASE_OUT proposal violates a constitutional limit
    /// (era too young, grace period too short, era already phased out, or
    /// effective tick in the past). Core CL11 refuses to sign.
    ConsolePhaseOutInvalid,
    /// Txid attestation status is `PhasedOut` — the bloom era containing
    /// this txid was retired by Console action. Cheque is irrevocably dead.
    TxidPhasedOut,

    // §13 Progressive Redeem Registration
    /// Redeem registration incomplete (progress < required_k) and no scar_passcode.
    RedeemRegistrationIncomplete,

    // §17.11 Genesis Claim
    /// Genesis claim rejected: wallet_seq must be 1 and prev_seq must be 0.
    GenesisClaimInvalidSeq,
    /// Genesis claim rejected: tx.amount must be 0 (pool amount is protocol-determined).
    GenesisClaimInvalidAmount,
    /// CL5 redeem rejected: a self-send cheque carrying GENESIS_CLAIM_AMOUNT
    /// (i.e., an airdrop cheque) was presented for redemption against a wallet
    /// whose stored state is already advanced (balance != 0 OR wallet_seq != 0).
    /// Genesis-claim cheques are one-shot by §17.11 invariant — a replay
    /// against a funded wallet is the infinite-mint attack class. Closes the
    /// hole where per-validator try_mark_cheque_redeemed and the
    /// receiver_fact_chain check (Step 3.5c) both failed to fire on a
    /// rescan-resurrected airdrop bundle.
    GenesisClaimWalletAlreadyFunded,

    /// SEC-02 (cap-at-mint via FACT scar). A genesis claim (self-send of
    /// GENESIS_CLAIM_AMOUNT) was presented for redemption but its FACT link
    /// is SCARRED — it carries no `nabla_confirmation`. The only thing that
    /// gates a genesis draw against the 100M/1M pool ceiling is the admitting
    /// Nabla's `try_claim`, and a Nabla emits its blessing (NablaConfirmation)
    /// ONLY after `try_claim` succeeds. An un-blessed genesis link therefore
    /// means the pool was never debited: the mint would be unaccounted supply.
    /// Hard reject. See docs/security_review_20260612/SEC-02_*.
    GenesisNablaBlessingMissing,

    /// FACT class isolation Rule R1 violation
    /// (`AXIOM_DESIGN_FactClassIsolation.md` §2.1, §3).
    /// Sender and receiver wallet_ids belong to different classes —
    /// one is dev (`@axiom.internal`), the other public. Cross-class
    /// TXs are forbidden in either direction.
    DomainMismatch,

    /// YPX-020 — the wallet is HIBERNATING: its witnessed prev-state
    /// `hibernation_until` is still in the future relative to `tx.epoch`, so
    /// the wallet is "out of work" and CL2 rejects every returning tx until the
    /// period elapses. CL1 (no prev state) is exempt.
    WalletHibernating,

    /// YPX-021 §8.2 — a supplied `NablaOodsAttestation` failed verification
    /// (bad Ed25519 signature, missing/invalid NBC trust anchor, or the
    /// claimed baseline is not bound into the issuer-signed cert). A hard
    /// reject: an invalid attestation never silently downgrades to
    /// "no flag" — that would let an attacker strip an unhealthy reading.
    OodsAttestationInvalid,
    /// YPX-021 §8.5 (2026-07-05) — a RECOVERY re-anchor (HAL / RECALL / HEAL)
    /// was attempted while the network's OODS is NOT verified-healthy (unhealthy
    /// reading, or no reading at all). Recovery ops are overlap-relaxed, so their
    /// double-spend backstop (Nabla consume-once) is weakest exactly during a
    /// partition/eclipse — which is what unhealthy OODS signals. So a recovery is
    /// BLOCKED until OODS is healthy. This is RETRYABLE (RecoveryHint::WaitAndRetry):
    /// the wallet re-attempts when the network recovers — it is NOT stranded, and
    /// NOT poisoned. Distinct from `OodsAttestationInvalid` (a forged reading, hard
    /// reject) — this is an honestly-unhealthy or absent reading.
    OodsUnhealthyRetry,
    /// YPX-022 — a RECALL attestation failed verification (bad Nabla sig / NBC anchor).
    RecallAttestationInvalid,
}

impl core::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StateIdAlreadyConsumed => write!(f, "E_STATE_ID_CONSUMED"),
            Self::InvalidStateId => write!(f, "E_INVALID_STATE_ID"),
            Self::InvalidWalletSeq => write!(f, "E_INVALID_WALLET_SEQ"),
            Self::WalletSeqOverflow => write!(f, "E_WALLET_SEQ_OVERFLOW"),
            Self::InvalidWalletId => write!(f, "E_INVALID_WALLET_ID"),
            Self::MalformedAddress => write!(f, "E_MALFORMED_ADDRESS"),
            Self::InvalidClientSignature => write!(f, "E_INVALID_CLIENT_SIG"),
            Self::InvalidWitnessSignature => write!(f, "E_INVALID_WITNESS_SIG"),
            Self::UnsupportedSignatureAlgorithm => write!(f, "E_UNSUPPORTED_SIG_ALG"),
            Self::InsufficientBalance => write!(f, "E_INSUFFICIENT_BALANCE"),
            Self::ConservationViolation => write!(f, "E_CONSERVATION_VIOLATION"),
            Self::ZeroAmount => write!(f, "E_ZERO_AMOUNT"),
            Self::DustAmount => write!(f, "E_DUST_AMOUNT"),
            Self::InvalidVBC => write!(f, "E_INVALID_VBC"),
            Self::VBCExpired { .. } => write!(f, "E_VBC_EXPIRED"),
            Self::VBCNotYetValid { .. } => write!(f, "E_VBC_NOT_YET_VALID"),
            Self::VBCChainTooDeep => write!(f, "E_VBC_CHAIN_TOO_DEEP"),
            Self::VBCMissingIssuer => write!(f, "E_VBC_MISSING_ISSUER"),
            Self::VBCRootKeyMismatch => write!(f, "E_VBC_ROOT_KEY_MISMATCH"),
            Self::DuplicateValidator => write!(f, "E_DUPLICATE_VALIDATOR"),
            Self::InvalidVBCCount => write!(f, "E_INVALID_VBC_COUNT"),
            Self::MissingPrevReceipts => write!(f, "E_MISSING_PREV_RECEIPTS"),
            Self::InvalidGenesisTransaction => write!(f, "E_INVALID_GENESIS_TX"),
            Self::InvalidExecutionProof => write!(f, "E_INVALID_EXECUTION_PROOF"),
            Self::ProgramDigestMismatch => write!(f, "E_PROGRAM_DIGEST_MISMATCH"),
            Self::InvalidCanonicalJson => write!(f, "E_INVALID_JSON"),
            Self::TxidAttestationMissing => write!(f, "E_TXID_ATTESTATION_MISSING"),
            Self::TxidAttestationInvalidSig => write!(f, "E_TXID_ATTESTATION_INVALID_SIG"),
            Self::TxidAttestationRedeemed => write!(f, "E_TXID_ATTESTATION_REDEEMED"),
            Self::TxidAttestationBadStatus => write!(f, "E_TXID_ATTESTATION_BAD_STATUS"),
            Self::TxidAttestationUntrusted => write!(f, "E_TXID_ATTESTATION_UNTRUSTED"),
            Self::InsufficientCheques => write!(f, "E_INSUFFICIENT_CHEQUES"),
            Self::InconsistentChequeBundle => write!(f, "E_INCONSISTENT_CHEQUE_BUNDLE"),
            Self::InvalidChequeSignature => write!(f, "E_INVALID_CHEQUE_SIG"),
            Self::ChequeAlreadyRedeemed => write!(f, "E_CHEQUE_ALREADY_REDEEMED"),
            Self::RedeemSenderAnchorMissing => write!(f, "E_REDEEM_SENDER_ANCHOR_MISSING"),
            Self::RedeemBeforeCommitPropagated => write!(f, "E_REDEEM_BEFORE_COMMIT_PROPAGATED"),
            Self::RedeemBalanceMismatch => write!(f, "E_REDEEM_BALANCE_MISMATCH"),
            Self::RedeemBalanceOverflow => write!(f, "E_REDEEM_BALANCE_OVERFLOW"),
            Self::MissingExecutionProof => write!(f, "E_MISSING_EXECUTION_PROOF"),
            Self::MissingRedeemInputs => write!(f, "E_MISSING_REDEEM_INPUTS"),
            Self::MissingVBC => write!(f, "E_MISSING_VBC"),
            Self::FeeExceedsValidatorCap => write!(f, "E_FEE_EXCEEDS_VALIDATOR_CAP"),
            Self::FeeExceedsAggregateCap => write!(f, "E_FEE_EXCEEDS_AGGREGATE_CAP"),
            Self::FeeExceedsAmount => write!(f, "E_FEE_EXCEEDS_AMOUNT"),
            Self::FeeSlotMathInvalid => write!(f, "E_FEE_SLOT_MATH_INVALID"),
            Self::FeeSlotReceiptMismatch => write!(f, "E_FEE_SLOT_RECEIPT_MISMATCH"),
            Self::FeeSlotCountMismatch => write!(f, "E_FEE_SLOT_COUNT_MISMATCH"),
            Self::CarriersTooLarge => write!(f, "E_CARRIERS_TOO_LARGE"),
            Self::InvalidHintCount => write!(f, "E_INVALID_HINT_COUNT"),
            Self::SelfHintNotAllowed => write!(f, "E_SELF_HINT_NOT_ALLOWED"),
            Self::ZkpNotQualified => write!(f, "E_ZKP_NOT_QUALIFIED"),
            Self::ArkNotImplemented => write!(f, "E_ARK_NOT_IMPLEMENTED"),
            Self::OracleSenderMismatch => write!(f, "E_ORACLE_SENDER_MISMATCH"),
            Self::OracleInsufficientK => write!(f, "E_ORACLE_INSUFFICIENT_K"),
            Self::OracleVBCTooOld => write!(f, "E_ORACLE_VBC_TOO_OLD"),
            Self::OracleInsufficientStake => write!(f, "E_ORACLE_INSUFFICIENT_STAKE"),
            Self::OracleStakeScarred => write!(f, "E_ORACLE_STAKE_SCARRED"),
            Self::OraclePlatformInvalid => write!(f, "E_ORACLE_PLATFORM_INVALID"),
            Self::OracleLivingSignatureMissing => write!(f, "E_ORACLE_LIVING_SIG_MISSING"),
            Self::OracleZeroDelta => write!(f, "E_ORACLE_ZERO_DELTA"),
            Self::OracleNonZeroAmount => write!(f, "E_ORACLE_NONZERO_AMOUNT"),
            Self::OracleMaturityNotReached => write!(f, "E_ORACLE_MATURITY_NOT_REACHED"),
            Self::ReferenceTooLarge => write!(f, "E_REFERENCE_TOO_LARGE"),
            Self::WithdrawalInputsMissing => write!(f, "E_WITHDRAWAL_INPUTS_MISSING"),
            Self::WithdrawalIdMismatch => write!(f, "E_WITHDRAWAL_ID_MISMATCH"),
            Self::WithdrawalWitnessCount => write!(f, "E_WITHDRAWAL_WITNESS_COUNT"),
            Self::WithdrawalWitnessDuplicate => write!(f, "E_WITHDRAWAL_WITNESS_DUPLICATE"),
            Self::WithdrawalNotAuthoritative => write!(f, "E_WITHDRAWAL_NOT_AUTHORITATIVE"),
            Self::WithdrawalEarningsSig => write!(f, "E_WITHDRAWAL_EARNINGS_SIG"),
            Self::WithdrawalPoolVidMismatch => write!(f, "E_WITHDRAWAL_POOL_VID_MISMATCH"),
            Self::WithdrawalPoolNotRegistered => write!(f, "E_WITHDRAWAL_POOL_NOT_REGISTERED"),
            Self::WithdrawalSig => write!(f, "E_WITHDRAWAL_SIG"),
            Self::WithdrawalConflictOfInterest => write!(f, "E_WITHDRAWAL_CONFLICT_OF_INTEREST"),
            Self::InvalidMode => write!(f, "E_INVALID_MODE"),
            Self::InternalError => write!(f, "E_INTERNAL"),
            Self::AuthHashRequired => write!(f, "E_AUTH_HASH_REQUIRED"),
            Self::InvalidAuthProof => write!(f, "E_INVALID_AUTH_PROOF"),
            Self::SABRInsufficientOverlap => write!(f, "E_SABR_INSUFFICIENT_OVERLAP"),
            Self::SABROverlapNotInPrev => write!(f, "E_SABR_OVERLAP_NOT_IN_PREV"),
            Self::SABRMissingValidatorPK => write!(f, "E_SABR_MISSING_VALIDATOR_PK"),
            Self::SABRHashMismatch => write!(f, "E_SABR_HASH_MISMATCH"),
            Self::ReceiptFromWrongWorldline => write!(f, "E_RECEIPT_WRONG_WORLDLINE"),
            Self::ReceiptLineageMismatch => write!(f, "E_RECEIPT_LINEAGE_MISMATCH"),
            Self::ReceiptCommitmentMismatch => write!(f, "E_RECEIPT_COMMITMENT_MISMATCH"),
            Self::GroupTooManyMembers => write!(f, "E_GROUP_TOO_MANY_MEMBERS"),
            Self::GroupShareBpsInvalid => write!(f, "E_GROUP_SHARE_BPS_INVALID"),
            Self::GroupNotMember => write!(f, "E_GROUP_NOT_MEMBER"),
            Self::GroupInsufficientAvailable => write!(f, "E_GROUP_INSUFFICIENT_AVAILABLE"),
            Self::GroupChecksumFailed => write!(f, "E_GROUP_CHECKSUM_FAILED"),
            Self::GroupMembersImmutable => write!(f, "E_GROUP_MEMBERS_IMMUTABLE"),
            Self::GroupDistributionOverflow => write!(f, "E_GROUP_DISTRIBUTION_OVERFLOW"),
            Self::GroupMemberMismatch => write!(f, "E_GROUP_MEMBER_MISMATCH"),
            // FACT chain errors
            Self::FactChainTooDeep => write!(f, "E_FACT_CHAIN_TOO_DEEP"),
            Self::FactChainBreak => write!(f, "E_FACT_CHAIN_BREAK"),
            Self::FactInsufficientWitnesses => write!(f, "E_FACT_INSUFFICIENT_WITNESSES"),
            Self::FactInvalidSignature => write!(f, "E_FACT_INVALID_SIGNATURE"),
            Self::FactDuplicateWitness => write!(f, "E_FACT_DUPLICATE_WITNESS"),
            Self::FactInvalidCheckpoint => write!(f, "E_FACT_INVALID_CHECKPOINT"),
            Self::FactChainEmpty => write!(f, "E_FACT_CHAIN_EMPTY"),
            Self::FactAmountOverflow => write!(f, "E_FACT_AMOUNT_OVERFLOW"),
            // Burn errors
            Self::BurnNoFactChain => write!(f, "E_BURN_NO_FACT_CHAIN"),
            Self::BurnMissingTarget => write!(f, "E_BURN_MISSING_TARGET"),
            Self::BurnTargetNotFound => write!(f, "E_BURN_TARGET_NOT_FOUND"),
            Self::BurnTargetNotScarred => write!(f, "E_BURN_TARGET_NOT_SCARRED"),
            Self::BurnTargetAlreadyBurned => write!(f, "E_BURN_TARGET_ALREADY_BURNED"),
            Self::BurnAmountMismatch => write!(f, "E_BURN_AMOUNT_MISMATCH"),
            Self::BurnProofInsufficientWitnesses => write!(f, "E_BURN_PROOF_INSUFFICIENT_WITNESSES"),
            Self::BurnProofDuplicateValidator => write!(f, "E_BURN_PROOF_DUPLICATE_VALIDATOR"),
            Self::BurnTxIdNotInChain => write!(f, "E_BURN_TX_ID_NOT_IN_CHAIN"),
            Self::BurnTargetMismatch => write!(f, "E_BURN_TARGET_MISMATCH"),
            Self::TooManyUnresolvedScars => write!(f, "E_TOO_MANY_UNRESOLVED_SCARS"),
            Self::MissingWalletState => write!(f, "E_MISSING_WALLET_STATE"),
            Self::VersionMismatch => write!(f, "E_VERSION_MISMATCH"),
            Self::CoreIdMismatch => write!(f, "E_CORE_ID_MISMATCH"),
            Self::MissingDilithiumKey => write!(f, "E_MISSING_DILITHIUM_KEY"),
            Self::MissingDilithiumPk => write!(f, "E_MISSING_DILITHIUM_PK"),
            Self::MissingField => write!(f, "E_MISSING_FIELD"),
            Self::WalletSecretMismatch => write!(f, "E_WALLET_SECRET_MISMATCH"),
            // Fan-Out errors (CL10)
            Self::FanOutMissingMessage => write!(f, "E_FANOUT_MISSING_MESSAGE"),
            Self::FanOutTtlExceeded => write!(f, "E_FANOUT_TTL_EXCEEDED"),
            Self::FanOutInvalidFanout => write!(f, "E_FANOUT_INVALID_FANOUT"),
            Self::FanOutContentEmpty => write!(f, "E_FANOUT_CONTENT_EMPTY"),
            Self::FanOutContentTooLarge => write!(f, "E_FANOUT_CONTENT_TOO_LARGE"),
            Self::FanOutTtlExpired => write!(f, "E_FANOUT_TTL_EXPIRED"),
            Self::FanOutTtlInflated => write!(f, "E_FANOUT_TTL_INFLATED"),
            Self::FanOutUnknownContentType => write!(f, "E_FANOUT_UNKNOWN_CONTENT_TYPE"),
            Self::FanOutTimestampFuture => write!(f, "E_FANOUT_TIMESTAMP_FUTURE"),
            Self::FanOutTimestampExpired => write!(f, "E_FANOUT_TIMESTAMP_EXPIRED"),
            Self::FanOutDiffusionIdMismatch => write!(f, "E_FANOUT_DIFFUSION_ID_MISMATCH"),
            Self::FanOutInvalidOriginator => write!(f, "E_FANOUT_INVALID_ORIGINATOR"),
            Self::FanOutOriginatorPkMismatch => write!(f, "E_FANOUT_ORIGINATOR_PK_MISMATCH"),
            Self::FanOutInvalidSignature => write!(f, "E_FANOUT_INVALID_SIGNATURE"),
            Self::InsufficientStake => write!(f, "Insufficient stake for validator onboarding"),
            Self::WalletFrozen => write!(f, "Wallet frozen by Judicial Freeze Protocol"),
            Self::ArkToNonArkRejected => write!(f, "Ark wallet can only send to other Ark wallets"),
            Self::ArkChargeNotOwner => write!(f, "Only the wallet owner can charge their Ark wallet"),
            Self::ArkUnloadScarred => write!(f, "Ark unload requires fully clean FACT chain (zero scars)"),
            Self::ArkOnlineTradeRejected => write!(f, "Ark-to-Ark trades are offline-only; rejected in the online witnessed pipeline"),
            Self::SelfSendRejected => write!(f, "Cannot send to own address (except Ark)"),
            Self::ReceiverAddressRequired => write!(f, "Receiver has changed email (-XX suffix). Provide receiver_address."),
            Self::InvalidReceiverAddress => write!(f, "Receiver address has invalid checksum"),
            Self::NablaWriterDetected => write!(f, "FATAL: Nabla response from WRITER node — security violation"),
            Self::StakeWalletMismatch => write!(f, "NablaStakeProof wallet_pk does not match VBC subject_pubkey_ed25519"),
            Self::StakeNablaSignatureInvalid => write!(f, "NablaStakeProof Nabla attestation signature invalid"),
            Self::StakeStateMismatch => write!(f, "NablaStakeProof state mismatch: receipt_state_id != attested_state_id"),
            Self::StakeInsufficientReceipts => write!(f, "NablaStakeProof has fewer than 3 valid receipt signatures"),
            Self::StakeProofExpired => write!(f, "NablaStakeProof is too old (nabla_tick expired)"),
            // MVIB errors
            Self::MvibEmptyAdmissionSet => write!(f, "E_MVIB_EMPTY_ADMISSION_SET"),
            Self::MvibInvalidAdmissionSetSize => write!(f, "E_MVIB_INVALID_ADMISSION_SET_SIZE"),
            Self::MvibDuplicateIssuer => write!(f, "E_MVIB_DUPLICATE_ISSUER"),
            Self::MvibInvalidSignature => write!(f, "E_MVIB_INVALID_SIGNATURE"),
            Self::MvibInvalidTick => write!(f, "E_MVIB_INVALID_TICK"),
            // Console errors (YPX-013)
            Self::ConsoleInvalidGeneration => write!(f, "E_CONSOLE_INVALID_GENERATION"),
            Self::ConsoleChainMismatch => write!(f, "E_CONSOLE_CHAIN_MISMATCH"),
            Self::ConsoleInvalidSeatCount => write!(f, "E_CONSOLE_INVALID_SEAT_COUNT"),
            Self::ConsoleDuplicateSeat => write!(f, "E_CONSOLE_DUPLICATE_SEAT"),
            Self::ConsoleTermMismatch => write!(f, "E_CONSOLE_TERM_MISMATCH"),
            Self::ConsoleInvalidTermLength => write!(f, "E_CONSOLE_INVALID_TERM_LENGTH"),
            Self::ConsoleInvalidSelector => write!(f, "E_CONSOLE_INVALID_SELECTOR"),
            Self::ConsoleInvalidPick => write!(f, "E_CONSOLE_INVALID_PICK"),
            Self::ConsoleIncompleteSelection => write!(f, "E_CONSOLE_INCOMPLETE_SELECTION"),
            Self::ConsoleNotMember => write!(f, "E_CONSOLE_NOT_MEMBER"),
            Self::GenesisStakeLocked => write!(f, "E_GENESIS_STAKE_LOCKED"),
            Self::SenderWalletIdMismatch => write!(f, "E_SENDER_WALLET_ID_MISMATCH"),
            // YPX-018 CLARA & Tiered Bloom
            Self::ClaraInvalidSignature => write!(f, "E_CLARA_INVALID_SIGNATURE"),
            Self::ClaraWalletPkMismatch => write!(f, "E_CLARA_WALLET_PK_MISMATCH"),
            Self::ClaraStateNotGarbage => write!(f, "E_CLARA_STATE_NOT_GARBAGE"),
            Self::ClaraNbcTrustFailed => write!(f, "E_CLARA_NBC_TRUST_FAILED"),
            Self::ClaraEmptyGarbage => write!(f, "E_CLARA_EMPTY_GARBAGE"),
            Self::ConsolePhaseOutInvalid => write!(f, "E_CONSOLE_PHASE_OUT_INVALID"),
            Self::TxidPhasedOut => write!(f, "E_TXID_PHASED_OUT"),
            Self::RedeemRegistrationIncomplete => write!(f, "E_REDEEM_REGISTRATION_INCOMPLETE"),
            Self::GenesisClaimInvalidSeq => write!(f, "E_GENESIS_CLAIM_INVALID_SEQ"),
            Self::GenesisClaimInvalidAmount => write!(f, "E_GENESIS_CLAIM_NON_ZERO_AMOUNT"),
            Self::GenesisClaimWalletAlreadyFunded => write!(f, "E_GENESIS_CLAIM_WALLET_ALREADY_FUNDED"),
            Self::GenesisNablaBlessingMissing => write!(f, "E_GENESIS_NABLA_BLESSING_MISSING"),
            Self::DomainMismatch => write!(f, "E_DOMAIN_MISMATCH"),
            Self::WalletHibernating => write!(f, "E_WALLET_HIBERNATING"),
            Self::OodsAttestationInvalid => write!(f, "E_OODS_ATTESTATION_INVALID"),
            Self::OodsUnhealthyRetry => write!(f, "E_OODS_UNHEALTHY_RETRY"),
            Self::RecallAttestationInvalid => write!(f, "E_RECALL_ATTESTATION_INVALID"),
            Self::HealNotNeeded => write!(f, "E_HEAL_NOT_NEEDED"),
            // Cheque-claim proof (CL5 synchronous double-redeem prevention)
            Self::ChequeClaimProofMissing => write!(f, "E_CHEQUE_CLAIM_PROOF_MISSING"),
            Self::ChequeClaimProofInvalidSig => write!(f, "E_CHEQUE_CLAIM_PROOF_INVALID_SIG"),
            Self::ChequeClaimProofTxidMismatch => write!(f, "E_CHEQUE_CLAIM_PROOF_TXID_MISMATCH"),
            Self::ChequeClaimProofReceiverMismatch => write!(f, "E_CHEQUE_CLAIM_PROOF_RECEIVER_MISMATCH"),
            Self::ChequeClaimProofUntrusted => write!(f, "E_CHEQUE_CLAIM_PROOF_UNTRUSTED"),
            Self::TxidAlreadyInReceiverChain => write!(f, "E_TXID_ALREADY_IN_RECEIVER_CHAIN"),
            Self::ChequeClaimProofExpired => write!(f, "E_CHEQUE_CLAIM_PROOF_EXPIRED"),
            Self::StateNotAnchored => write!(f, "E_STATE_NOT_ANCHORED"),
        }
    }
}
// ============================================================================
// Wire types — moved from lambda/src/types.rs (UMP consolidation, 2026-05-10).
// Live here so ANTIE/Nabla/SDK can deserialize/serialize without maintaining
// mirror structs (the drift pattern that produced E_RECEIPT_COMMITMENT_MISMATCH
// 5+ times). See CLAUDE.md §13.
// ============================================================================

/// Witness request from Gateway
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessRequest {
    /// Request ID for correlation. SDK ships this on the email envelope
    /// header (`axiom_sdk::redeem::build_email`), NOT inside the CBOR
    /// body. `#[serde(default)]` keeps the typed deserialize from
    /// rejecting a body without the field; ANTIE substitutes
    /// `email.request_id` post-deserialize.
    #[serde(default)]
    pub request_id: String,

    /// The transaction to witness
    pub transaction: Transaction,

    /// Signatures from overlapped validators (for S-ABR)
    pub overlapped_signatures: Vec<WitnessSig>,

    /// Previous receipts proving prior state was legitimately consumed.
    /// REQUIRED — for genesis send the producer sends `Vec::new()`
    /// explicitly. No `#[serde(default)]`: if the field is absent from
    /// the wire payload, that's a producer bug we want surfaced (§13).
    pub prev_receipts: Vec<Receipt>,
    
    /// Client's claimed balance for S-ABR new-validator path.
    /// 
    /// SECURITY: This is NOT trusted blindly. Core cryptographically verifies it:
    /// Core computes produced_state_id using this balance, and compares against
    /// the hash that overlapped validators (who have the real balance from storage)
    /// already verified. If the client lies, the hashes won't match → TX rejected.
    /// 
    /// Only used when a NEW validator (not overlapped) processes a transaction.
    /// Overlapped validators IGNORE this and use their stored TransactionRecord.
    /// 
    /// Optimization: could be replaced with balance embedded in overlapped validator
    /// responses. Current approach is secure — Core verifies via SHA3-256 hash match.
    /// If client lies, state_id hash won't match and TX is rejected.
    #[serde(alias = "declared_balance")]
    pub claimed_balance_for_sabr: u64,

    /// YPX-020 — client's declared `hibernation_until` for the §15 anchor
    /// check, mirroring `claimed_balance_for_sabr`. NOT trusted blindly:
    /// Core's `verify_state_anchored` recomputes
    /// `compute_state_hash(pk, balance, seq, hibernation_until)` and rejects
    /// unless it matches the k-signed `prev_receipt.state_hash`, so a wrong
    /// value (e.g. 0 to dodge the hibernation gate) fails the hash. REQUIRED
    /// because the overlap-relaxed HAL completion reaches FRESH validators
    /// that never stored the re-anchor's produced state — they cannot source
    /// the real `H` from local storage, so the client must declare it and
    /// Core verifies. 0 for every non-hibernating tx (omitted from the wire).
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub claimed_hibernation_until: u64,

    /// YPX-021 §8.2 — client-fetched Nabla OODS reading. ANTIE forwards
    /// verbatim (never strips — CLAUDE.md §12 mirror-struct rule); Lambda
    /// passes it into the CL2/CL3 `PublicInputs`; Core verifies and stamps
    /// the derived `OodsFlag` into the receipt. `None` on paths with no
    /// Nabla reading (heal, genesis claim, WASM webclient — Phase 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oods_attestation: Option<NablaOodsAttestation>,

    /// YPX-022 RECALL — Nabla recall attestation carried on the RECALL self-send wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recall_attestation: Option<RecallAttestation>,

    /// YPX-001 §1.5.1 — scar-consent voucher carried on a re-initiated
    /// scarred send AFTER the generating validator verified the receiver's
    /// passcode (hop 1 of the retry round). Later overlapped hops verify
    /// the issuer signature against this request's prev-receipt witness
    /// set and skip the gate. `None` on every non-consent send.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scar_consent_voucher: Option<ScarConsentVoucher>,

    /// Requester's address. SDK doesn't ship this in the body — ANTIE
    /// substitutes `email.from` post-deserialize. `#[serde(default)]`
    /// for the same reason as `request_id`.
    #[serde(default)]
    pub requester_address: String,

    /// Offered fee in atoms
    #[serde(default)]
    pub offered_fee: u64,

    /// Validator hints from requester (YP §27). SDK conditionally
    /// ships when the wallet has hints worth relaying (empty hint
    /// list is omitted by `relay_validator_hints_cbor`).
    /// `#[serde(default)]` so an honest empty-hints body decodes.
    #[serde(default)]
    pub validator_hints: Vec<ValidatorHint>,
    
    /// The produced_state_id computed by Core (CL2) at Gateway
    /// Lambda MUST use this value, NOT compute its own!
    /// This ensures only Core computes state_ids
    #[serde(default)]
    pub produced_state_id: Option<Vec<u8>>,
    
    /// The commitment_hash computed by Core (CL2) at Gateway
    /// Lambda MUST use this for signing — Core computes, Lambda signs.
    #[serde(default)]
    pub commitment_hash: Option<Vec<u8>>,
    
    /// Member index for group wallet withdrawal (group wallet TX only)
    /// Passed through to Core's PublicInputs.group_member_index
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_member_index: Option<usize>,
    
    /// Client's FACT chain — money provenance history (YPX-001 §1.6).
    /// The FACT chain is CARRIED BY THE CLIENT, not stored by validators.
    /// Client includes this in every witness request. Validators:
    ///   1. Verify it (Core CL3)
    ///   2. Sign FACT commitment (witness role)
    ///   3. Build updated chain at k=3 → return in WitnessResponse.sender_fact_chain
    ///   4. Attach to cheque for receiver
    ///      Validators do NOT store FACT chains. S-ABR stores tx records for balance verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_fact_chain: Option<FactChain>,

    /// Client's CL1 execution proof (ZKP proving client ran Core locally).
    /// CL1 is mandatory everywhere (post-v2.13). ANTIE passes this through
    /// without inspection — Core/Lambda verifies.
    ///
    /// `#[serde(default)]` because the SDK conditionally omits the field
    /// when the proof is empty (`build_witness_payload_cbor_v3` only
    /// pushes when `proof.is_empty() == false`). The typed deserialize
    /// would otherwise reject every witness round with no proof yet —
    /// the genesis-claim path produces the proof only after the
    /// witness round completes. Lambda's own CL1 mandate is the
    /// authoritative check, not this wire constraint.
    #[serde(default)]
    pub cl1_execution_proof: Vec<u8>,

    /// §17.11: auth_hash for genesis claims (wallet protection setup).
    /// Ed25519 verify key derived from owner_secret. Set once during genesis
    /// claim. Subsequent TXs must include matching owner_proof. Without this,
    /// genesis-claimed wallets would fail the auth_hash policy gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_hash: Option<Vec<u8>>,

    /// §23.14: Audit confirmation from client (carrying target validator's response).
    /// Client received AuditDemand in a prior WitnessResponse, carried it to the
    /// target validator, and now returns AuditConfirmation for Lambda to pass to Core.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_confirmation: Option<AuditConfirmation>,

    /// YPX-009: Nonce response from Lambda (answer to prior NonceChallenge).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_response: Option<NonceResponse>,

    /// YPX-009: Audit response from Lambda (re-executed TXs chain hash).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_response: Option<PulseAuditResponse>,

    /// YPX-002 §3.2 — sender's designated (sticky) Nabla node.
    /// The sender pre-declares which Nabla node it will register with;
    /// each witnessing validator stamps this into the `nabla_hint` field
    /// of the `ValidatorCheque` it issues. The receiver reads it from the
    /// cheque and queries that node first (per §4.2 step 2). Sender and
    /// receiver never communicate directly — the validator is the courier.
    /// Lambda treats this as opaque pass-through; Core never validates it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nabla_hint: Option<NablaHint>,

    /// YPX-018 — CLARA attestation. When present, Lambda forwards this to
    /// Core CL2 which verifies the Nabla signature, the wallet binding, and
    /// the roll-forward eligibility (validator's stored state must be in
    /// `garbage_state_ids`). On Accept, Lambda atomically advances its
    /// stored wallet state from the garbage entry to `healed_to_state_id`.
    /// See YPX-018 §2.3 and Yellow Paper §17.10.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clara_attestation: Option<ClaraAttestation>,
}

/// Witness response to Gateway
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessResponse {
    /// Request ID for correlation
    pub request_id: String,
    
    /// Whether witnessing succeeded
    pub success: bool,
    
    /// Our witness signature (if success)
    pub witness_signature: Option<WitnessSig>,
    
    /// All collected signatures (for sender's record)
    pub overlapped_signatures: Vec<WitnessSig>,
    
    /// Rejection reason (if !success)
    pub rejection: Option<RejectionInfo>,
    
    /// The ValidatorCheque to send to receiver (if success)
    /// Gateway should deliver this to receiver via ANTIE
    pub cheque_for_receiver: Option<ValidatorCheque>,
    
    /// The complete receipt for sender's records (if success and k reached)
    pub receipt: Option<Receipt>,
    
    /// The produced state_id after this transaction (for client state tracking)
    /// Client MUST use this as consumed_state_id for their next transaction
    #[serde(default)]
    pub produced_state_id: Option<Vec<u8>>,
    
    /// The commitment_hash computed by Core (CL2) that this validator signed.
    /// Returned on EVERY successful witness response (not just k=3 receipt).
    /// Client uses this to build receipts with non-zero commitment_hash.
    #[serde(default)]
    pub commitment_hash: Option<Vec<u8>>,

    /// State hash computed by Core (CL2/CL3) for this transaction.
    /// Top-level (mirrors commitment_hash) so the SDK can reconstruct
    /// receipt_commitment locally for partial-commit shapes where
    /// `receipt: Option<Receipt>` is None (k<3 path produces no
    /// finalised Receipt). Returned on every successful witness
    /// response, not just at k=3.
    #[serde(default)]
    pub state_hash: Option<Vec<u8>>,

    /// Receipt commitment computed by Core (CL3) — BLAKE3 over the
    /// six receipt input fields (txid || state_hash || produced_state_id
    /// || new_wallet_seq || commitment_hash || epoch). Top-level so
    /// the SDK embeds it in receipts built for prev_receipts use,
    /// including partial-commit receipts where Core CL3 always
    /// produces this value but Lambda's full Receipt isn't yet
    /// finalised. See `core/logic/src/crypto.rs::compute_receipt_commitment`.
    #[serde(default)]
    pub receipt_commitment: Option<Vec<u8>>,

    /// Transaction ID (BLAKE3 of canonical transaction bytes), exposed
    /// top-level so the SDK can build partial-commit receipts on the
    /// V1/V2 path where `receipt: Option<Receipt>` is None. Both V1/V2
    /// and V3 finalize paths populate this; receivers MUST compare it
    /// against `cheque.txid` for sanity. No `#[serde(default)]` —
    /// missing = producer bug.
    pub txid: Vec<u8>,

    /// Validator hints from this validator (1-3 required).
    /// Per Yellow Paper Section 27: Every witness response MUST include hints.
    /// No `#[serde(default)]`: missing on the wire = producer bug (§13).
    pub validator_hints: Vec<ValidatorHint>,
    
    /// Sender's updated FACT chain after this transaction (YPX-001).
    /// Only present when k=3 reached (overlapped validator builds the chain).
    /// Client includes this in ChequeBundle.fact_chain for the receiver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_fact_chain: Option<FactChain>,

    /// §23.14: Audit demand from Core — client must carry this to the target
    /// validator and return AuditConfirmation in a subsequent WitnessRequest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_demand: Option<AuditDemand>,

    /// YPX-009: Audit request from AVM — Lambda must re-execute selected TXs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_request: Option<PulseAuditRequest>,

    /// YPX-009: Nonce challenge from AVM — Lambda must respond with NonceResponse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_challenge: Option<NonceChallenge>,

    /// YPX-009: Pulse proof data from AVM after successful audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pulse_proof: Option<PulseProofData>,

    /// YPX-009: AVM detected audit failure — Lambda should log and restart.
    #[serde(default)]
    pub audit_failed: bool,

    /// §23.14.6: Outbound peer-audit request to send via ANTIE email.
    /// When Core demands a peer-audit and Lambda has the target's email,
    /// this is populated so Gateway can build and send the email.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_peer_audit: Option<OutboundPeerAudit>,

    /// §11.5: Confidence Index for the sender's wallet.
    /// Issued by this validator on every successful TX. Client stores this
    /// and presents it during offline ⟠ Ark trades for risk assessment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_index: Option<ConfidenceIndex>,

    /// YPX-001 §1.5.1: Scar-consent notification (receiver informed consent).
    /// Populated ONLY on the gate-fire rejection shape (`success = false`,
    /// rejection code `E_LAMBDA_SCAR_CONSENT_REQUIRED`) by the overlapped
    /// validator. Gateway (ANTIE) MUST deliver this to the RECEIVER's mailbox
    /// (like `cheque_for_receiver`) and MUST NOT forward it to the sender —
    /// the passcode travels receiver → sender out-of-band, that is the
    /// consent. Host-wire plumbing only: never read inside guest Core.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scar_consent_for_receiver: Option<ScarConsentNotification>,

    /// YPX-001 §1.5.1: consent voucher issued to the SENDER by the
    /// passcode-verifying validator on the successful verify hop. The
    /// sender's SDK attaches it to the round's remaining witness requests
    /// (`WitnessRequest.scar_consent_voucher`) so the other overlapped
    /// validators can verify consent instead of re-gating. Forwarded to
    /// the sender by ANTIE (unlike `scar_consent_for_receiver`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scar_consent_voucher: Option<ScarConsentVoucher>,
}

/// YPX-001 §1.5.1: consent voucher issued by the passcode-verifying validator.
///
/// Under S-ABR every prior witness is "overlapped", so up to k validators
/// independently run the scar-consent gate — but the 6-digit passcode is
/// stored only at the validator that generated it. After that validator
/// verifies the receiver's passcode (single-use, consumed on match), it
/// signs this voucher over the txid; the SENDER carries it to the round's
/// remaining hops, each of which verifies the Ed25519 signature against the
/// prev-receipt witness set it already validates (client-carried, no
/// cross-validator state, no new trust edge — "one of MY OWN prior
/// witnesses attests the receiver consented"). A bare `scar_passcode`
/// without a voucher NEVER skips the gate, so a fabricated passcode cannot
/// bypass consent at any validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScarConsentVoucher {
    /// Txid of the consented transaction (passcode-independent).
    pub txid: [u8; 32],
    /// Issuing validator's id (must appear in the tx's prev-receipt
    /// witness set — that is what makes it verifiable by peers).
    pub validator_id: [u8; 32],
    /// Ed25519 signature by the issuer's witness key over
    /// `compute_scar_consent_voucher_payload(txid)`.
    pub signature: Vec<u8>,
}

/// YPX-001 §1.5.1: Scar-consent notification (validator → receiver via ANTIE).
///
/// "Incoming payment of {amount} from {sender}. This money has {scar_count}
/// unverified link(s) in its provenance. If you accept, your wallet inherits
/// these scars. Passcode: {passcode}." The receiver ACCEPTS by giving the
/// sender the passcode out-of-band; the sender re-initiates the same tx
/// (same txid — `compute_txid` excludes `scar_passcode`) with the passcode
/// set. REJECT = do nothing; the paused TX was never witnessed and dies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScarConsentNotification {
    /// Txid of the paused transaction (BLAKE3, passcode-independent).
    pub txid: [u8; 32],
    /// Sender's wallet_id (as carried on the paused tx).
    pub sender_wallet_id: String,
    /// Receiver's wallet_id (delivery target).
    pub receiver_wallet_id: String,
    /// Amount of the paused transaction (atoms).
    pub amount: u64,
    /// Number of unresolved (non-Ark) links in the sender's provenance.
    pub scar_count: u32,
    /// 6-digit consent passcode generated + stored by the overlapped
    /// validator. Single-use: deleted on first successful verification.
    pub passcode: u32,
}

/// §23.14.6: Outbound peer audit request data (piggybacked on WitnessResponse).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundPeerAudit {
    /// The PeerAuditRequest to send (txid + expected_hash + challenge_nonce + our PK)
    pub request: PeerAuditRequest,
    /// Target validator's email address (resolved from hints)
    pub target_email: String,
}

/// Rejection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectionInfo {
    pub code: String,
    pub message: String,
}


/// Redeem response to Gateway
/// 
/// Contains this validator's witness signature for receiver's new state.
/// Receiver must collect k such responses to finalize their balance update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedeemResponse {
    /// Request ID for correlation
    pub request_id: String,
    
    /// Whether this validator accepted the redemption
    pub success: bool,
    
    /// New balance after redemption (if success)
    pub new_balance: Option<u64>,
    
    /// New state_id (if success)
    pub new_state_id: Option<[u8; 32]>,
    
    /// This validator's witness signature (if success)
    /// Receiver needs k of these to prove their balance update
    pub witness_signature: Option<WitnessSig>,
    
    /// The commitment_hash that was signed (for receiver's receipt)
    #[serde(default)]
    pub commitment_hash: Option<Vec<u8>>,

    /// State hash computed by Core during redeem CL5 — top-level so
    /// the receiver SDK can rebuild receipt_commitment locally for
    /// the redeem receipt. Mirror of WitnessResponse.state_hash;
    /// without it the receiver writes a redeem receipt with
    /// state_hash=[0u8;32] and the next send fails CL2 with
    /// E_RECEIPT_COMMITMENT_MISMATCH (same drop-by-mirror-drift
    /// pattern as the witness path; CLAUDE.md §13).
    #[serde(default)]
    pub state_hash: Option<Vec<u8>>,

    /// Receipt commitment computed by Core during redeem CL5 — Core
    /// always produces this in strict mode (post-4a81a34). Receiver
    /// stores it in the redeem receipt for use as prev_receipts on
    /// the next send.
    #[serde(default)]
    pub receipt_commitment: Option<Vec<u8>>,

    /// Structured error response. Populated on every failure,
    /// `None` on success. See `docs/AXIOM_YellowPaper_Errors.md`.
    /// Clients MUST read this to get the failure reason — the legacy
    /// `error: Option<String>` field was removed in Phase 2b.15.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_response: Option<axiom_errors::ErrorResponse>,

    /// Validator hints from this validator (1-3 required)
    #[serde(default)]
    pub validator_hints: Vec<ValidatorHint>,

    /// This validator's FACT signature for the redeem transaction (YPX-001).
    /// Signs: BLAKE3("AXIOM_FACT" || tx_id || prev_state_id || new_state_id || amount)
    /// Receiver uses this when they later send funds (proves FACT continuity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fact_signature: Option<Vec<u8>>,
    
    /// Receiver's updated FACT chain after redeem (YPX-001 §1.6).
    /// Contains the sender's chain (from cheque) plus the new redeem link.
    /// Client stores this and includes it in future WitnessRequest.sender_fact_chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver_fact_chain: Option<FactChain>,
}

// ============================================================================
// Lambda IPC types — moved from lambda/src/types.rs (UMP consolidation,
// 2026-05-10). All wire types between Gateway/ANTIE/SDK ↔ Lambda live
// here so there is exactly ONE definition. Mirror-drift is structurally
// impossible. See CLAUDE.md §13.
// ============================================================================
/// State query request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateQueryRequest {
    pub request_id: String,
    pub wallet_pk: Vec<u8>,
}

// ============================================================================
// VSP — Validator Status Protocol (YPX-008)
// ============================================================================

/// VSP query request — client asks a validator for its status + known peers.
/// Free service, no authentication required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorStatusRequest {
    pub request_id: String,
}

/// VSP query response — validator returns its public profile + peer referrals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorStatusResponse {
    pub request_id: String,
    /// Validator's human-friendly name (from VBC node_name)
    pub validator_name: String,
    /// Validator unique ID (hex-encoded)
    pub validator_id: String,
    /// Proof capability: "dmap" or "zkvm"
    pub proof_cap: String,
    /// Carrier URIs for reaching this validator
    pub carriers: Vec<String>,
    /// Core version string (e.g., "Kyoto/1.1/GENESIS")
    pub core_version: String,
    /// Uptime in seconds since process start
    pub uptime_secs: u64,
    /// Total transactions witnessed (sender side)
    pub witness_count: u64,
    /// Total transactions redeemed (receiver side)
    pub redeem_count: u64,
    /// Whether this validator is ZKP-qualified
    pub zkp_qualified: bool,
    /// 3 known peer validators (for client routing/discovery)
    pub known_validators: Vec<ValidatorHint>,
    /// Fee rate in basis points (1 bps = 0.01%). 50 = 0.50%.
    #[serde(default)]
    pub fee_rate_bps: u32,
    /// Unix timestamp when fee schedule expires (0 = no expiry)
    #[serde(default)]
    pub fee_valid_until: u64,
    /// Minimum fee in atoms
    #[serde(default)]
    pub fee_min_amount: u64,
    /// Operator jurisdiction (ISO 3166-1 alpha-2, e.g., "SG", "US", or "NONE")
    #[serde(default)]
    pub jurisdiction: String,
    /// Operator name/organization (self-reported, not protocol-verified)
    #[serde(default)]
    pub operator_name: String,
    /// Operator contact (optional)
    #[serde(default)]
    pub operator_contact: String,
    /// Supported encryption for cheque delivery (e.g., "PGP", "GPG", "none")
    /// Clients with matching encryption suffix (-P, -G) in their wallet_id
    /// can expect encrypted cheque emails from this validator.
    #[serde(default)]
    pub supported_encryption: String,
    /// Encryption public key (e.g., PGP/GPG public key block, base64-encoded)
    /// Clients can use this to encrypt messages TO this validator.
    #[serde(default)]
    pub encryption_public_key: String,
    /// Validator's current stake in AXC atoms (from bound wallet).
    /// Public — clients can verify the validator meets tier requirements.
    #[serde(default)]
    pub stake: u64,
    /// Free-text notes from the validator operator (e.g., maintenance schedule,
    /// service announcements, terms of service URL)
    #[serde(default)]
    pub notes: String,
    /// L$ digit_version (White Paper §J.14-J.18). Presentation-only.
    /// 0 = 1 AXC = 1 L$. N = 1 AXC = 10^N L$. Console-managed.
    #[serde(default)]
    pub digit_version: u8,
}

/// State query response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateQueryResponse {
    pub request_id: String,
    pub found: bool,
    pub wallet_state: Option<StoredWalletState>,
}

/// Stored wallet state (Lambda's view)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredWalletState {
    /// Public key
    pub public_key: Vec<u8>,
    
    /// Current balance in atoms
    pub balance: u64,
    
    /// Current wallet sequence number
    pub wallet_seq: u64,
    
    /// Current state ID
    pub state_id: [u8; 32],
    
    /// Last transaction ID
    pub last_tx_id: Option<[u8; 32]>,
    
    /// State status: PENDING (awaiting ACK) or CONFIRMED (committed)
    /// Wallet state status: PENDING after witness, CONFIRMED after ACK (fee paid).
    /// Pending states are valid for subsequent transactions (balance/state_id usable)
    /// but the consumed_state_id is only marked permanent at ACK time.
    #[serde(default = "default_status")]
    pub status: WalletStateStatus,
    
    /// Group wallet members (None for personal wallets)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_members: Option<Vec<GroupMember>>,
    
    /// Owner authentication key (optional — wallet protection against key theft).
    /// When set: Ed25519 pubkey derived from owner_secret (v2.11.13). Every TX must
    /// include owner_proof (Ed25519 signature) to pass Core validation. See YP §39.3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_hash: Option<[u8; 32]>,

    /// Canonical wallet_id bound to this public key (identity binding).
    /// Set from tx.sender_wallet_id on the first transaction; immutable thereafter.
    /// Passed to Core in WalletState so Core can enforce sender_wallet_id consistency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_id: Option<String>,

    /// YPX-020 — persisted hibernation tick (see `WalletState::hibernation_until`).
    /// Persisted so a node restart cannot un-hibernate a wallet (restart-bypass).
    #[serde(default)]
    pub hibernation_until: u64,
}

/// Wallet state status for pending/confirmed tracking
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum WalletStateStatus {
    /// State is committed and valid
    #[default]
    Confirmed,
    /// State is pending ACK from client
    Pending,
}

fn default_status() -> WalletStateStatus {
    WalletStateStatus::Confirmed
}

/// Transaction record for S-ABR overlap lookup
/// 
/// Each validator stores a record for every transaction they witness.
/// Lookup is by `produced_state_id` - when a new transaction arrives,
/// we check if we have a record where `produced_state_id` matches
/// the new transaction's `consumed_state_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    /// Transaction ID
    pub tx_id: [u8; 32],
    
    /// The state_id produced by this transaction
    /// This is the KEY for lookup - next tx's consumed_state_id
    pub produced_state_id: [u8; 32],
    
    /// Wallet public key (for TX_ID collision verification)
    pub wallet_pk: Vec<u8>,
    
    /// Balance after this transaction
    pub balance_after: u64,
    
    /// Wallet sequence after this transaction
    pub wallet_seq_after: u64,
    
    /// Group members after this transaction (post-deduction)
    /// Needed for S-ABR: next TX's overlapped validators must know
    /// the correct group_members to pass to Core for checksum validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_members_after: Option<Vec<GroupMember>>,
    
    /// Whether this was a genesis claim TX (§17.11).
    /// Genesis claims are self-sends that are allowed to self-redeem.
    #[serde(default)]
    pub is_genesis_claim: Option<bool>,

    /// Status: PENDING until ACK, then CONFIRMED
    pub status: WalletStateStatus,

    /// YPX-007: Required k for this transaction (Core-extracted from receiver address).
    /// Persisted so next TX's S-ABR overlap can use the previous TX's k.
    #[serde(default)]
    pub required_k: u8,

    /// YPX-007: Proof type for this transaction (0=ZKP, 1=DMAP, 2=Ark).
    #[serde(default)]
    pub proof_type: u8,

    /// Transaction amount (self-audit: Core verifies Lambda stored correct amount).
    #[serde(default)]
    pub amount: u64,

    /// Sender balance BEFORE this transaction (self-audit: Core needs pre-TX balance
    /// to rebuild TxDigest for Argon2id→BLAKE3 chain replay).
    #[serde(default)]
    pub sender_balance: u64,
}

impl From<StoredWalletState> for WalletState {
    fn from(s: StoredWalletState) -> Self {
        WalletState {
            public_key: s.public_key,
            balance: s.balance,
            wallet_seq: s.wallet_seq,
            state_id: s.state_id,
            auth_hash: s.auth_hash,
            wallet_id: s.wallet_id,
            group_members: s.group_members,
            hibernation_until: s.hibernation_until,
        }
    }
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub core_connected: bool,
    pub pending_transactions: usize,
}

/// Redeem request from Gateway (NEW MODEL)
/// 
/// Receiver brings k cheques (from sender's validators) to this validator
/// to have their balance updated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedeemRequestEnvelope {
    /// Request ID for correlation. The SDK ships this on the email
    /// envelope header (see `axiom_sdk::redeem::build_email`), NOT
    /// inside the CBOR body — `#[serde(default)]` keeps the typed
    /// deserialize from rejecting a body without the field. ANTIE's
    /// `gateway::handle_redeem_request` substitutes
    /// `email.request_id` after deserializing the typed envelope.
    #[serde(default)]
    pub request_id: String,
    
    /// The bundle of k cheques from sender's validators
    pub cheque_bundle: ChequeBundle,
    
    /// Receiver's public key
    pub receiver_pk: Vec<u8>,
    
    /// Receiver's current wallet state (if exists)
    pub current_state: Option<WalletState>,
    
    /// Receiver's overlapped signatures from their PREVIOUS transaction
    /// Used for S-ABR validation on receiver side
    #[serde(default)]
    pub overlapped_signatures: Vec<WitnessSig>,
    
    /// Receiver's signature proving ownership
    /// Signs: BLAKE3("AXIOM_REDEEM" || txid || receiver_pk)
    pub receiver_sig: Vec<u8>,
    
    /// Validator hints from requester (1-3 required)
    #[serde(default)]
    pub validator_hints: Vec<ValidatorHint>,
    
    /// Receiver's existing FACT chain (YPX-001 §1.6).
    /// Client carries their own FACT chain. If receiver already holds money from
    /// prior transactions, they include their chain here. For first-time receivers,
    /// this is None. The validator builds a new FACT link for the receive and
    /// returns the updated chain in RedeemResponse.receiver_fact_chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver_fact_chain: Option<FactChain>,

    /// CL5 DMAP execution proof — wallet ownership verification.
    /// Client runs CL5 locally with wallet_secret, produces DMAP attestation
    /// proving they own the receiver_wallet_id without revealing the secret.
    /// Validator verifies the DMAP proof structurally (CoreID + Merkle).
    ///
    /// §15: MANDATORY. No exceptions. No fallback. No "if present." No
    /// signature-only legacy path. Empty `Vec` is rejected by Lambda's
    /// `process_redeem_request` (mirroring the CL1 gate at consensus.rs:2421).
    /// Pre-§15 this was `Option<Vec<u8>>` with `#[serde(default,
    /// skip_serializing_if)]` and a "legacy mode (signature-only)" fallback —
    /// see CLAUDE.md §15 regression watch + AXIOM_HANDOFF_MacClientStaleState.md.
    pub cl5_execution_proof: Vec<u8>,

    /// Nabla txid attestation — proves this txid has NOT been redeemed globally.
    /// Client fetches from Nabla (GET /query-txid), includes in redeem request.
    /// Lambda verifies the Nabla node signature. Lambda NEVER queries Nabla directly.
    /// Required: redeem without attestation is rejected (no fallback).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txid_attestation: Option<NablaTxidAttestation>,

    /// Stream B (2026-05-13): Nabla-writer-signed cheque-claim proof.
    /// Receiver obtains by calling `register_cheque_claim` during the
    /// §4.6 verify step.  Core CL5 hard-rejects redeems without this
    /// (E_CHEQUE_CLAIM_PROOF_MISSING); Lambda forwards it into the CL5
    /// PublicInputs verbatim.  See `ChequeClaimProof` for the wire shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cheque_claim_proof: Option<ChequeClaimProof>,

    /// YPX-021 §8.2 — client-fetched Nabla OODS reading for the redeem
    /// receipt's health flag. Same forwarding contract as
    /// `WitnessRequest::oods_attestation`. `None` = no flag (Phase 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oods_attestation: Option<NablaOodsAttestation>,

    /// Accumulated FACT witness signatures from prior validators in the
    /// redeem witness round.
    ///
    /// Distinct from `overlapped_signatures` (which is the S-ABR overlap
    /// proof on the send path — Ed25519 over `commitment_hash`). On the
    /// redeem path the SDK collects k WitnessSigs from validators
    /// serially; each carries a `fact_signature` (Dilithium ML-DSA-65
    /// over the FACT commitment, NOT the S-ABR commitment_hash). The
    /// SDK populates this field with the prior k-1 entries; the
    /// finalizer's Lambda forwards them into Core CL5 as
    /// `inputs.fact_witness_sigs`, where Core's AVM assembles the
    /// receiver's redeem FactLink via `build_fact_link` (CLAUDE.md §12 —
    /// Core is the sole authority for FactLink assembly).
    ///
    /// Why a separate field from `overlapped_signatures`: the two sig
    /// sets are over different commitments with different algorithms
    /// (Ed25519 vs Dilithium) and serve different protocol concepts
    /// (S-ABR overlap vs FACT chain provenance). Sharing one field
    /// forced every reader to disambiguate by mode and was the source
    /// of the post-A2 receiver-link assembly bug.
    #[serde(default)]
    pub fact_witness_sigs: Vec<WitnessSig>,

    // fee_breakdown deleted 2026-06-05 PM. Pre-fix the SDK proposed a
    // per-validator slot allocation that flowed into Core CL5's NET
    // balance binding — a stale client `validators.list` would propose
    // wrong slots and the resulting `state_hash` diverged from what each
    // validator actually charges, producing E_RECEIPT_COMMITMENT_MISMATCH.
    // Replaced by `ValidatorCheque.rate_bps` (Dilithium-signed at cheque
    // issuance time). Core CL5 sums
    // `expected_fee_slot_amount(c.amount, c.rate_bps)` across the bundle
    // to derive `total_fee` deterministically. No client influence.
    // CLAUDE.md §13: pre-mainnet, no back-compat shim. Wire breaks cleanly.
}

///
/// After client receives k=3 witness signatures, they send ACK to each
/// validator to transition state from PENDING to CONFIRMED. v3.x: no
/// per-TX fee payment at ACK — fees settle at CL5 via fee_breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckRequest {
    /// Request ID for correlation
    pub request_id: String,

    /// The ACK envelope
    pub ack: AckWithFee,

    /// Client's public key (sender or receiver)
    pub client_pk: Vec<u8>,
}

/// ACK response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckResponse {
    /// Request ID for correlation
    pub request_id: String,

    /// Whether ACK was accepted
    pub success: bool,

    /// New status after ACK (should be Confirmed)
    pub new_status: Option<String>,

    /// Structured error response. Populated on every failure,
    /// `None` on success. Legacy `error: Option<String>` was removed
    /// in Phase 2b.15.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_response: Option<axiom_errors::ErrorResponse>,
}


/// Gateway request envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[allow(clippy::large_enum_variant)] // Architectural: variants carry protocol payloads of varying size
pub enum GatewayRequest {
    #[serde(rename = "witness")]
    Witness(WitnessRequest),
    
    #[serde(rename = "query_state")]
    QueryState(StateQueryRequest),
    
    #[serde(rename = "redeem")]
    Redeem(RedeemRequestEnvelope),
    
    #[serde(rename = "ack")]
    Ack(AckRequest),

    /// CL13 / fee ledger Step 9B.3 — chosen-witness mint witnessing.
    /// Operator's Lambda sends to each chosen_witness's Lambda admin
    /// gateway after `verify_validator_withdrawal` returns VERIFIED.
    /// Each witness re-runs the 7-step verify + AVM CL13, signs the
    /// mint commitment with Ed25519, returns the signature.
    #[serde(rename = "withdrawal_mint_witness")]
    WithdrawalMintWitness(WithdrawalMintWitnessRequest),

    #[serde(rename = "health")]
    Health(HealthRequest),

    #[serde(rename = "shutdown")]
    Shutdown(ShutdownRequest),

    /// Multi-carrier discovery (YP §27.5.2 — Phase 1).
    /// ANTIE pushes the canonical carrier URI list at startup.
    #[serde(rename = "set_carriers")]
    SetCarriers(SetCarriersRequest),

    /// VSP: Validator Status Protocol query (free, unauthenticated)
    #[serde(rename = "validator_status")]
    ValidatorStatus(ValidatorStatusRequest),

    /// Initialize genesis state for a wallet (DEV/TEST MODE ONLY)
    #[serde(rename = "init_genesis_dev")]
    InitGenesis(InitGenesisRequest),

    /// Load pre-computed test state directly (DEV/TEST MODE ONLY)
    #[serde(rename = "load_test_state")]
    LoadTestState(LoadTestStateRequest),

    /// Phase 1: New validator requests VBC signing (discovery)
    #[serde(rename = "vbc_sign_request")]
    VBCSignRequest(VBCSignRequestPayload),

    /// Phase 2: New validator requests actual signature (with complete issuer_set)
    #[serde(rename = "vbc_sign_commit")]
    VBCSignCommit(VBCSignCommitPayload),

    /// §23.14.6: Inbound peer audit request from remote validator (via ANTIE)
    #[serde(rename = "peer_audit_request")]
    PeerAuditRequest(PeerAuditRequestEnvelope),

    /// §23.14.6: Inbound peer audit response from remote validator (via ANTIE)
    #[serde(rename = "peer_audit_response")]
    PeerAuditResponse(PeerAuditResponseEnvelope),

    /// §4.5 / §30.2: Set auth_hash on a wallet (stolen-key protection).
    #[serde(rename = "set_auth_hash")]
    SetAuthHash(SetAuthHashRequest),

    /// Fan-Out dedup check — persistent replay prevention (READ-ONLY).
    #[serde(rename = "fanout_dedup")]
    FanOutDedup(FanOutDedupRequest),

    /// Fan-Out mark — record diffusion_id as processed (WRITE).
    #[serde(rename = "fanout_mark")]
    FanOutMark(FanOutMarkRequest),
}

/// Genesis funding result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisResult {
    pub state_id: Vec<u8>,
    pub wallet_seq: u64,
}

// ============================================================================
// IPC named-payload structs — used in tuple variants of GatewayRequest /
// GatewayResponse so ANTIE/clients can deserialize each variant's payload
// as a single named type. With `#[serde(tag = "type")]` on the enum, a
// tuple variant with a struct payload serializes IDENTICALLY to an inline
// struct variant — wire format unchanged. Existence in this module
// guarantees Lambda + ANTIE see the same definition; mirror impossible.
// (UMP consolidation, 2026-05-10.)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitGenesisRequest {
    pub request_id: String,
    pub public_key: Vec<u8>,
    pub balance: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_members: Option<Vec<GroupMember>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestStateRequest {
    pub request_id: String,
    pub public_key: Vec<u8>,
    pub state_id: Vec<u8>,
    pub balance: u64,
    pub wallet_seq: u64,
}

/// CL13 / fee ledger Step 9B.3 — chosen-witness handler request.
///
/// The operator's Lambda sends this to each `chosen_witness` Lambda's
/// admin gateway after `verify_validator_withdrawal` returns VERIFIED.
/// Each chosen-witness Lambda independently re-runs the 7-step verify,
/// dispatches Core CL13 via the AVM, and signs the mint commitment.
///
/// No trust is placed in the originating Lambda: every chosen-witness
/// runs the same proof through its own Core ELF. A compromised operator
/// Lambda cannot smuggle a bad withdrawal — the chosen-witness AVM
/// reject closes that path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalMintWitnessRequest {
    pub request_id: String,
    /// The full ValidatorWithdrawalRequest the operator already verified.
    /// Embedded verbatim — chosen-witness Lambda doesn't trust any
    /// intermediate processing, it runs its own verify chain.
    pub withdrawal: crate::wire_client::ValidatorWithdrawalRequest,
}

/// CL13 / fee ledger Step 9B.3 — chosen-witness handler response.
///
/// Carries the witness's Ed25519 signature over the canonical mint
/// commitment (computed via `compute_withdrawal_mint_commitment`) plus
/// the mint result Core CL13 produced. Operator's Lambda collects k=3
/// of these and assembles the final mint receipt in Step 9B.4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalMintWitnessResponse {
    pub request_id: String,
    /// `"VERIFIED"` on accept, or one of the `"REJECTED_*"` strings
    /// mirroring Lambda's existing `ValidatorWithdrawalResponse`.
    pub status: String,
    /// Witness validator's Ed25519 public key. Lambda derives this
    /// from its own SPHINCS+ identity (validator_id = BLAKE3(sphincs_pk)).
    pub witness_pk: Vec<u8>,
    /// Ed25519 signature over
    /// `compute_withdrawal_mint_commitment(validator_id,
    /// linked_wallet_id, net_amount, claimed_through_tick)`.
    /// `None` on rejection.
    pub witness_sig: Option<Vec<u8>>,
    /// Step 9B.8 — Ed25519 signature over
    /// `compute_validator_claim_payload(validator_id,
    /// claimed_through_tick)`. Same Ed25519 key as `witness_sig`,
    /// different hash. The operator's Lambda collects k=3 of these
    /// into a `MarkValidatorEarningsClaimedRequest` sent to Nabla
    /// post-mint so `last_claimed_tick` advances and the same
    /// earnings can't be re-claimed from a fresh Lambda.
    ///
    /// Computed in the same witness round as `witness_sig` so the
    /// operator gets both signatures with one TCP fan-out. `None` on
    /// rejection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_sig: Option<Vec<u8>>,
    /// CL13 mint output. `None` on rejection.
    pub mint: Option<ValidatorWithdrawalMintOutput>,
    /// Structured error response. Populated on every rejection,
    /// `None` on accept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_response: Option<axiom_errors::ErrorResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VBCSignRequestPayload {
    pub request_id: String,
    pub sphincs_pk_hex: String,
    pub dilithium_pk_hex: String,
    pub ed25519_pk_hex: String,
    #[serde(default)]
    pub pgp_fingerprint_hex: String,
    #[serde(default)]
    pub proof_cap: String,
    #[serde(default)]
    pub node_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VBCSignCommitPayload {
    pub request_id: String,
    pub sphincs_pk_hex: String,
    pub dilithium_pk_hex: String,
    pub ed25519_pk_hex: String,
    #[serde(default)]
    pub pgp_fingerprint_hex: String,
    #[serde(default)]
    pub proof_cap: String,
    #[serde(default)]
    pub node_name: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub chain_depth: u8,
    pub issuer_set_hex: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAuditRequestEnvelope {
    pub request_id: String,
    pub peer_audit_request: PeerAuditRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAuditResponseEnvelope {
    pub request_id: String,
    pub peer_audit_response: PeerAuditResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetAuthHashRequest {
    pub request_id: String,
    pub public_key: Vec<u8>,
    pub auth_hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FanOutDedupRequest {
    pub request_id: String,
    pub diffusion_id: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FanOutMarkRequest {
    pub request_id: String,
    pub diffusion_id: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitGenesisResponse {
    pub request_id: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<GenesisResult>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestStateResponse {
    pub request_id: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VBCSignApprovalResponse {
    pub request_id: String,
    pub approval: VBCSignApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VBCSignCommitResponse {
    pub request_id: String,
    pub success: bool,
    pub signature_hex: String,
    pub signer_sphincs_pk_hex: String,
    pub commitment_hex: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAuditResultPayload {
    pub request_id: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<PeerAuditResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester_email: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAuditResponseAck {
    pub request_id: String,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetAuthHashResponse {
    pub request_id: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FanOutDedupResponse {
    pub request_id: String,
    pub already_seen: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FanOutMarkResponse {
    pub request_id: String,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownAck {
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthRequest {
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownRequest {
    pub request_id: String,
}

/// Multi-carrier discovery (YP §27.5.2 — Phase 1, 2026-05-14).
///
/// ANTIE pushes the operator's configured inbound carrier set to Lambda
/// at gateway startup, in canonical URI form (`tcp:H:P`, `ws:H:P`,
/// `email:<address>`). The list flows out through `validator_status`
/// (VSP) so peers and clients can route via any supported channel.
///
/// Empty list is permitted but logs a loud warning at Lambda; VSP will
/// emit an empty `carriers` Vec so downstream tools can flag the
/// validator as discovery-incomplete without breaking the rest of the
/// VSP response (peer hints, fee config, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetCarriersRequest {
    pub request_id: String,
    /// Canonical YP §27.5.2 URI strings. Order is preserved for VSP.
    pub carriers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetCarriersAck {
    pub request_id: String,
    /// Number of carriers Lambda accepted (echo of `carriers.len()`).
    pub accepted: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    pub request_id: String,
    pub error_response: axiom_errors::ErrorResponse,
}

/// Gateway response envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[allow(clippy::large_enum_variant)]
pub enum GatewayResponse {
    #[serde(rename = "witness_result")]
    WitnessResult(Box<WitnessResponse>),
    
    #[serde(rename = "state_result")]
    StateResult(StateQueryResponse),
    
    #[serde(rename = "redeem_result")]
    RedeemResult(RedeemResponse),
    
    #[serde(rename = "ack_result")]
    AckResult(AckResponse),

    /// CL13 / Step 9B.3 — chosen-witness signed mint approval.
    #[serde(rename = "withdrawal_mint_witness_result")]
    WithdrawalMintWitnessResult(WithdrawalMintWitnessResponse),

    #[serde(rename = "health_result")]
    HealthResult(HealthResponse),
    
    #[serde(rename = "shutdown_ack")]
    ShutdownAck(ShutdownAck),

    /// Multi-carrier discovery ack (YP §27.5.2 — Phase 1).
    #[serde(rename = "set_carriers_ack")]
    SetCarriersAck(SetCarriersAck),

    /// VSP: Validator Status Protocol response
    #[serde(rename = "validator_status_result")]
    ValidatorStatusResult(ValidatorStatusResponse),

    #[serde(rename = "init_genesis_dev_result")]
    InitGenesisResult(InitGenesisResponse),

    #[serde(rename = "load_test_state_result")]
    LoadTestStateResult(LoadTestStateResponse),

    /// Error variant — structured error response is the sole source of
    /// truth. The legacy `message: String` field was removed in Phase
    /// 2b.15. Clients read `error_response.code` for dispatch and
    /// `error_response.message` for display.
    #[serde(rename = "error")]
    Error(ErrorEnvelope),

    /// Phase 1: Lambda's business decision on VBC signing
    #[serde(rename = "vbc_sign_approval")]
    VBCSignApprovalResult(VBCSignApprovalResponse),

    /// Phase 2: Core's VBC signature (after Lambda approved)
    #[serde(rename = "vbc_sign_commit_result")]
    VBCSignCommitResult(VBCSignCommitResponse),

    /// §23.14.6: Peer audit result (response to inbound peer audit request)
    #[serde(rename = "peer_audit_result")]
    PeerAuditResult(PeerAuditResultPayload),

    /// §23.14.6: Peer audit response acknowledgement
    #[serde(rename = "peer_audit_response_ack")]
    PeerAuditResponseAck(PeerAuditResponseAck),

    /// §4.5: Set auth_hash result
    #[serde(rename = "set_auth_hash_result")]
    SetAuthHashResult(SetAuthHashResponse),

    #[serde(rename = "fanout_dedup_result")]
    FanOutDedupResult(FanOutDedupResponse),

    #[serde(rename = "fanout_mark_result")]
    FanOutMarkResult(FanOutMarkResponse),
}

// ============================================================================
// VBC Signing Types (for new validator onboarding)
// ============================================================================

/// Lambda's business decision on whether to sign a VBC
/// Lambda ONLY approves/rejects — Core does the actual cryptography
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VBCSignApproval {
    pub approved: bool,
    /// Reason for rejection (None if approved)
    pub reason: Option<String>,
    /// How many VBC signs this validator has remaining
    pub signs_remaining: u8,
    /// Our chain depth (new validator will be depth + 1)
    pub our_chain_depth: u8,
    /// Accepted proof capability ("dmap" or "zkvm")
    #[serde(default)]
    pub accepted_proof_cap: String,
}



#[cfg(test)]
mod dev_wallet_hibernation_tests {
    use super::*;

    // SAFETY PROOF: the dev-wallet short hibernation window applies ONLY to an
    // `@axiom.internal` (dev-class) wallet and can NEVER shorten a public wallet's
    // window — i.e. it cannot touch real money.
    #[test]
    fn dev_wallet_gate_never_shortens_public_money() {
        let base = 1_000_000u64;
        let t = TICK_INTERVAL_SECS;

        // ── hibernation_until_for routing: is_dev_class selects the window ──
        assert_eq!(hibernation_until_for(base, true, false, false), base + HIBERNATION_WINDOW * t,
            "PUBLIC HAL → FULL window (never shortened)");
        assert_eq!(hibernation_until_for(base, true, false, true), base + DEV_WALLET_HIBERNATION_WINDOW * t,
            "DEV HAL → dev-wallet window");
        assert_eq!(hibernation_until_for(base, false, true, false), base + RECALL_HIBERNATION_WINDOW * t,
            "PUBLIC recall → FULL window");
        assert_eq!(hibernation_until_for(base, false, true, true), base + DEV_WALLET_RECALL_HIBERNATION_WINDOW * t,
            "DEV recall → dev-wallet window");
        assert_eq!(hibernation_until_for(base, false, false, true), 0, "non-reanchor → 0 (dev)");
        assert_eq!(hibernation_until_for(base, false, false, false), 0, "non-reanchor → 0 (public)");

        // Dev-wallet window is never LONGER than the public one (real never shortened /
        // dev never lengthened). PROD invariant only: dev-mode deliberately gives dev
        // wallets a LONGER recall window (60) than the minimal public dev window (20)
        // so a dev recall survives a dev witness round (§2.2.4 dev tables).
        if cfg!(not(feature = "dev-mode")) {
            assert!(DEV_WALLET_HIBERNATION_WINDOW <= HIBERNATION_WINDOW);
            assert!(DEV_WALLET_RECALL_HIBERNATION_WINDOW <= RECALL_HIBERNATION_WINDOW);
        }

        // ── the gate is is_dev_wallet(@axiom.internal) EXACTLY — nothing else ──
        assert!(crate::wallet_id::is_dev_wallet("bob@axiom.internal"));
        assert!(!crate::wallet_id::is_dev_wallet("alice@example.net"));
        assert!(!crate::wallet_id::is_dev_wallet("x@axiom.io"));           // near-miss domain
        assert!(!crate::wallet_id::is_dev_wallet("m@axiom.internal.evil")); // suffix trick
        assert!(!crate::wallet_id::is_dev_wallet(""));                      // no domain

        // ── Core path (produced_hibernation_until) routes a PUBLIC sender to FULL ──
        let mut pub_hal = Transaction::default();
        pub_hal.sender_wallet_id = "alice@example.net".into();
        pub_hal.epoch = base;
        pub_hal.kind = TxKind::HalReanchor;
        assert_eq!(pub_hal.produced_hibernation_until(), base + HIBERNATION_WINDOW * t,
            "Core: PUBLIC HAL sender gets the FULL window — real money cannot be shortened");

        let mut dev_hal = pub_hal.clone();
        dev_hal.sender_wallet_id = "bob@axiom.internal".into();
        assert_eq!(dev_hal.produced_hibernation_until(), base + DEV_WALLET_HIBERNATION_WINDOW * t,
            "Core: @axiom.internal HAL sender gets the dev-wallet window");
    }
}

#[cfg(test)]
mod canonical_tx_cbor_tests {
    use super::*;

    /// A fully-populated Transaction fixture — every field set to a
    /// non-default value where possible. Used by the round-trip test
    /// to catch "field added to struct but encoder doesn't emit it"
    /// drift mechanically: if a field is in the struct but not the
    /// encoder, its value gets lost on round-trip and the assertion
    /// fails with a clear key list.
    fn populated_tx_fixture() -> Transaction {
        Transaction {
            consumed_state_id: [0xAA; 32],
            client_pk: vec![0xBB; 32],
            sender_wallet_id: "alice@axiom/abcd1234".to_string(),
            wallet_seq: 7,
            receiver_wallet_id: "bob@axiom/deadbeef".to_string(),
            receiver_address: Some("override@example.com".to_string()),
            amount: 10_000_000_000,
            reference: "lunch".to_string(),
            nonce: 42,
            epoch: 1_700_000_000,
            client_sig: vec![0xCC; 64],
            owner_proof: Some(vec![0xDD; 64]),
            scar_passcode: Some(123456),
            burn_target_tx_id: Some([0xEE; 32]),
            recall_target_tx_id: Some([0xDD; 32]),
            oracle_claim: None,
            required_k: 3,
            proof_type: 1,
            core_version: crate::version::CORE_VERSION_TAG.to_string(),
            core_id: [0u8; 32],
            kind: TxKind::Normal,
        }
    }

    /// The canonical encoder is the single source of truth for the
    /// SDK ↔ validator wire format. This test pins it to a byte-stable
    /// fixture: if the encoded length or any byte changes, a downstream
    /// breakage is imminent. Update the fixture only when intentionally
    /// changing the wire format (which requires a soak gate).
    #[test]
    fn canonical_encoder_is_byte_stable() {
        let tx = populated_tx_fixture();
        let bytes = tx.to_canonical_cbor_bytes();
        // 18-field shape, array-of-int byte representation. 32-byte
        // consumed_state_id, 32-byte client_pk, 64-byte client_sig,
        // 64-byte owner_proof, 32-byte burn_target_tx_id (all CBOR
        // arrays of Integer), plus scalars + field-name keys. Bumping
        // this number is a wire-format change — document why.
        // 859 = 828 (pre-9B.1) + 31:
        //   28 ("is_validator_withdrawal_mint" Text key)
        //   1 (CBOR False value byte for the new bool emit)
        //   2 (CBOR map-entry overhead: one for the key, one for the
        //      tagged value pair under ciborium's map encoding)
        // The encoder still emits `is_heal: bool` (derived from `kind`)
        // for receipt-commitment stability — the byte length difference
        // is purely the additive `is_validator_withdrawal_mint` emit.
        // 828 = 786 (pre-core_id) + 42:
        //   8 ("core_id" Text key)
        //   34 (CBOR array of 32 Integer entries, all-zero in fixture
        //       = one byte per entry + 2 bytes array header)
        // Bumped intentionally for the core_id wire-format addition
        // (see Transaction::core_id field doc + CL2 Step −1.5).
        //
        // Post-refactor (fee ledger 2026-06-02): fee_breakdown lives ONLY
        // on the redeem-side wire (RedeemRequestEnvelope + Receipt). The
        // Transaction struct is send-side only — sends have no fee notion
        // (YP §20.8: receiver pays fees at redeem time). So the canonical
        // Transaction CBOR is back to its pre-Step-2 shape: 828 bytes.
        //
        // 861 = 859 + 2: phase-marker addition (24958220, 2026-06-09) extended
        // CORE_VERSION_TAG from "Kyoto/1.1" → "Kyoto/1.1/GENESIS". The fixture
        // takes CORE_VERSION_TAG, so the encoded core_version Text bytes grew.
        // Field completeness is separately guarded by the INTENTIONALLY_UNEMITTED
        // round-trip test, so this is a value-length change, not a new field.
        // 878 = 861 + 17: YPX-020 HAL added the `is_hal_reanchor` bool emit.
        //   16 ("is_hal_reanchor" Text key: 1-byte CBOR header + 15 chars)
        //   1 (CBOR False value byte)
        // 878: YPX-020 §2 removed the `is_hal_complete` bool emit (−17 bytes,
        // 895 → 878) — completion is now the distress-cheque redeem, not a
        // separate kind. `is_hal_reanchor` remains. Field completeness is
        // separately guarded by the INTENTIONALLY_UNEMITTED round-trip test.
        // 889 = 878 + 11: YPX-022 RECALL added the `is_recall` bool emit
        //   (10-byte "is_recall" Text key + 1 CBOR False value byte). Same
        //   pattern as `is_hal_reanchor`; makes the RECALL kind survive the wire.
        // 975 = 889 + 86: YPX-022 RECALL added the `recall_target_tx_id` field
        //   (20-byte key + 66-byte Some([0xDD;32]) value in the fixture). Mirrors
        //   `burn_target_tx_id`; audit reference for the recalled send.
        assert_eq!(
            bytes.len(),
            975,
            "canonical encoder byte length changed — check this is intentional"
        );
    }

    /// Round-trip: encode via canonical encoder, decode to a CBOR
    /// `Value` map, assert every emitted key survives with the expected
    /// value. Validates that the encoder produces well-formed CBOR a
    /// downstream verifier can read.
    ///
    /// 9B.1 note: the canonical encoder emits `is_heal` (derived from
    /// `kind`) for receipt-commitment stability, but the `Transaction`
    /// struct no longer has a top-level `is_heal` field. We can't decode
    /// straight into `Transaction` via serde anymore (the field-name
    /// mismatch is intentional — the encoder is a signing payload, not
    /// a wire format). Decode into `ciborium::Value` and compare the
    /// emitted fields by name.
    #[test]
    fn canonical_encoder_round_trips_through_serde() {
        let tx = populated_tx_fixture();
        let bytes = tx.to_canonical_cbor_bytes();
        let decoded: ciborium::Value = ciborium::de::from_reader(bytes.as_slice())
            .expect("canonical CBOR must decode as a CBOR Value");
        let map = decoded.as_map().expect("Transaction encoded as CBOR map");

        let get = |key: &str| -> &ciborium::Value {
            map.iter()
                .find(|(k, _)| k.as_text() == Some(key))
                .map(|(_, v)| v)
                .unwrap_or_else(|| panic!("missing key {key}"))
        };
        // Scalar / string fields.
        assert_eq!(get("sender_wallet_id").as_text(), Some(tx.sender_wallet_id.as_str()));
        assert_eq!(get("wallet_seq").as_integer(), Some(tx.wallet_seq.into()));
        assert_eq!(get("receiver_wallet_id").as_text(), Some(tx.receiver_wallet_id.as_str()));
        assert_eq!(get("amount").as_integer(), Some(tx.amount.into()));
        assert_eq!(get("reference").as_text(), Some(tx.reference.as_str()));
        assert_eq!(get("nonce").as_integer(), Some(tx.nonce.into()));
        assert_eq!(get("epoch").as_integer(), Some(tx.epoch.into()));
        assert_eq!(get("required_k").as_integer(), Some(tx.required_k.into()));
        assert_eq!(get("proof_type").as_integer(), Some(tx.proof_type.into()));
        assert_eq!(get("core_version").as_text(), Some(tx.core_version.as_str()));
        // Derived bool fields (post-9B.1 emit shape).
        assert_eq!(get("is_heal").as_bool(), Some(tx.is_heal()));
        assert_eq!(get("is_validator_withdrawal_mint").as_bool(),
                   Some(tx.is_validator_withdrawal_mint()));
        assert_eq!(get("is_hal_reanchor").as_bool(), Some(tx.is_hal_reanchor()));
        assert_eq!(get("is_recall").as_bool(), Some(tx.is_recall()));
    }

    /// Drift-prevention check (the whole point of this consolidation):
    /// every field on `Transaction` is either (a) emitted by the canonical
    /// encoder, or (b) explicitly listed in `INTENTIONALLY_UNEMITTED`.
    /// Adding a field to the struct without touching either fails this
    /// test — same shape as the CLAUDE.md §13 recurring drift class fix.
    ///
    /// The trick: serde's default `Serialize` impl emits every public
    /// field that doesn't have `#[serde(skip)]`. Decode the serde output
    /// to a map and we have the authoritative key list. The canonical
    /// encoder's key list must be a subset, with any missing keys
    /// enumerated.
    #[test]
    fn canonical_encoder_covers_all_struct_fields() {
        let tx = populated_tx_fixture();

        let mut serde_buf = Vec::new();
        ciborium::ser::into_writer(&tx, &mut serde_buf)
            .expect("serde Transaction encode");
        let serde_value: ciborium::Value =
            ciborium::de::from_reader(serde_buf.as_slice())
                .expect("re-decode serde Transaction");
        let serde_keys: Vec<String> = serde_value
            .as_map()
            .expect("Transaction is a CBOR map")
            .iter()
            .filter_map(|(k, _)| k.as_text().map(String::from))
            .collect();

        let canonical_value = tx.to_canonical_cbor_value();
        let canonical_keys: std::collections::HashSet<String> = canonical_value
            .as_map()
            .expect("canonical encoder produces a CBOR map")
            .iter()
            .filter_map(|(k, _)| k.as_text().map(String::from))
            .collect();

        let mut missing: Vec<String> = Vec::new();
        for key in &serde_keys {
            if canonical_keys.contains(key) {
                continue;
            }
            if Transaction::INTENTIONALLY_UNEMITTED.contains(&key.as_str()) {
                continue;
            }
            missing.push(key.clone());
        }

        assert!(
            missing.is_empty(),
            "Transaction fields exist in the struct but the canonical \
             encoder doesn't emit them: {:?}.\n\
             Either add them to `to_canonical_cbor_value` (intentional wire \
             extension — requires soak validation) or add them to \
             `INTENTIONALLY_UNEMITTED` with a clear reason. This is the \
             CLAUDE.md §13 drift class — silent default-fill on the receiver \
             side has bitten us five times pre-mainnet.",
            missing
        );
    }
}
