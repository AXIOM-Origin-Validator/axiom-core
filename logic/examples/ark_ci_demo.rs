//! Ark §7 demo — Tier 1(b): scar-graded acceptance + staleness grading, driven
//! through the REAL `axiom_core_logic::ark::evaluate_ci` (the same code compiled
//! into the deployed Core ELF). No Python re-implementation, no mock: this is the
//! receiver's Confidence-Index law as it actually ships.
//!
//! Emits a human table AND a CSV (ark_ci_grid.csv) that tools/ark_demo figures
//! consume. Run:
//!   cargo run -p axiom-core-logic --example ark_ci_demo
//!
//! HONEST SCOPE (see the demo's Tier-2 gap report):
//!  - `evaluate_ci` is real + unit-tested and lives in the deployed ELF, but it
//!    has NO production caller — there is no receiver "decide via CI" path today.
//!    This demo IS that caller, standing in for the receiver.
//!  - The paper's liveness gate L (receiver pings Nabla for the live tick →
//!    "stale in a provably-live world" → RED) is NOT a factor in evaluate_ci.
//!    What we CAN show with real code is the STALENESS grading (Fresh→Cold),
//!    which is L's precursor; the missing piece is called out in the report.

use axiom_core_logic::ark::{evaluate_ci, CIStatus, L_DELTA_SECS};
use axiom_core_logic::types::ConfidenceIndex;

const MIN: u64 = 60;
const NOW: u64 = 10_000_000; // the receiver's "current time" (a live clock)

/// A healthy baseline: recently k=3-anchored, well-funded, dense Ark history,
/// deep validator ecosystem, no scar, no conflict.
fn base_ci() -> ConfidenceIndex {
    ConfidenceIndex {
        wallet_pk: vec![1u8; 32],
        last_k3_at: NOW - 5 * MIN, // 5 min ago → Fresh
        ark_tx_count_since_k3: 20, // HIGH history
        k3_balance: 1_000_000,
        ark_tx_mean_amount: 10_000,
        ark_validator_count: 5, // Deep ecosystem
        has_fact_scar: false,
        has_any_k3: true,
        conflict_count: 0,
        validator_signature: vec![],
        issuer_validator_pk: vec![],
    }
}

fn grade(ci: &ConfidenceIndex, amount: u64) -> CIStatus {
    evaluate_ci(ci, NOW, amount, None, true) // receiver dark → L neutral
}

/// Same as `grade` but with a receiver liveness measurement (the L input).
fn grade_live(ci: &ConfidenceIndex, amount: u64, live_tick: Option<u64>) -> CIStatus {
    evaluate_ci(ci, NOW, amount, live_tick, true)
}

fn tag(s: CIStatus) -> &'static str {
    match s {
        CIStatus::Green => "GREEN",
        CIStatus::Yellow => "YELLOW",
        CIStatus::Red => "RED",
    }
}

fn main() {
    let amount = 5_000u64; // in-pattern amount (mean 10k)
    let mut csv = String::from("scenario,staleness_min,detail,ci\n");

    println!("=== Ark CI — receiver's accept decision, via real ark::evaluate_ci (CoreID {}) ===",
             include_str!("../../artifacts/CORE_ID.txt").trim().get(..8).unwrap_or("unknown"));
    println!("receiver clock NOW={NOW}, ark_amount={amount}\n");

    // ── (1) STALENESS SWEEP — a healthy sender graded down as its last k=3 ages ──
    // This is the empirical spine of the "stale sender → RED" result. current_time
    // is the receiver's live clock; last_k3_at walks from minutes to a full day.
    println!("── Staleness sweep (healthy sender, only last-k=3 age varies) ──");
    println!("  {:>10}  {:>8}  {}", "age(min)", "band", "CI");
    let ages_min = [5u64, 60, 200, 400, 600, 800, 1440];
    for a in ages_min {
        let mut ci = base_ci();
        ci.last_k3_at = NOW - a * MIN;
        let g = grade(&ci, amount);
        let band = if a < 30 { "Fresh" } else if a < 300 { "Warm" } else if a <= 720 { "Stale" } else { "Cold" };
        println!("  {a:>10}  {band:>8}  {}", tag(g));
        csv.push_str(&format!("staleness,{a},{band},{}\n", tag(g)));
    }

    // ── (2) SCAR-GRADED ACCEPTANCE — the withheld-registration (scarred) link ──
    // The Tier-1 harness produces a real ≥3-witnessed-but-UNREGISTERED link
    // (auto-scarred). has_fact_scar is the receiver's read of exactly that.
    println!("\n── Scar override (Fresh, healthy — only the scar flag flips) ──");
    for scar in [false, true] {
        let mut ci = base_ci();
        ci.has_fact_scar = scar;
        let g = grade(&ci, amount);
        println!("  has_fact_scar={:<5} → {}", scar, tag(g));
        csv.push_str(&format!("scar,{},has_fact_scar={},{}\n", 5, scar, tag(g)));
    }

    // ── (3) DOUBLE-SPEND SEEN — the detect-and-punish result, receiver-side ──
    // Tier-1(a) shows the network ban a double-spender; here is the CI's own
    // unconditional RED once any conflict is known.
    println!("\n── Conflict override (Fresh, healthy — only conflict_count varies) ──");
    for c in [0u64, 1, 2] {
        let mut ci = base_ci();
        ci.conflict_count = c;
        let g = grade(&ci, amount);
        println!("  conflict_count={c} → {}", tag(g));
        csv.push_str(&format!("conflict,{},conflict_count={c},{}\n", 5, tag(g)));
    }

    // ── (4) STAKES / ECOSYSTEM — the other unconditional REDs ──
    println!("\n── Stakes & ecosystem overrides (Fresh, healthy baseline) ──");
    // Underwater: amount far exceeds k3_balance-backed stake.
    let ci = base_ci();
    let big = ci.k3_balance * 100;
    println!("  amount {big} vs k3_balance {} (underwater) → {}", ci.k3_balance, tag(grade(&ci, big)));
    csv.push_str(&format!("stakes,5,underwater_amount={big},{}\n", tag(grade(&ci, big))));
    // Unknown ecosystem + significant amount.
    let mut ci2 = base_ci();
    ci2.ark_validator_count = 0; // Unknown
    let sig_amt = ci2.ark_tx_mean_amount * 3;
    println!("  ark_validator_count=0 (Unknown) + amount {sig_amt} → {}", tag(grade(&ci2, sig_amt)));
    csv.push_str(&format!("ecosystem,5,unknown_validators_amount={sig_amt},{}\n", tag(grade(&ci2, sig_amt))));

    // ── (5) LIVENESS GATE L — the paper's contribution, demonstrated ──────────
    // The SAME strong sender (dense history, deep ecosystem) that caps at YELLOW when
    // Cold now yields YELLOW *or* RED depending purely on the RECEIVER's own liveness
    // measurement `live_tick`. This is L: staleness is excused when the world may be
    // dark, but is unexplained — and refused — when the receiver has proven it live.
    println!("\n── Liveness gate L (Δ = {L_DELTA_SECS}s) — same strong+Cold sender, receiver measurement varies ──");
    let mut cold = base_ci();
    cold.last_k3_at = NOW - 1440 * MIN; // 24 h stale → Cold (caps at YELLOW without L)
    let gap_cold = NOW - cold.last_k3_at;
    // (a) receiver also dark → L neutral → the compensatory matrix applies → YELLOW
    let a = grade_live(&cold, amount, None);
    println!("  (a) live_tick=None            gap={gap_cold}s  → {}   (both dark: outage excuses staleness)", tag(a));
    csv.push_str(&format!("liveness_L,1440,live_tick=None,{}\n", tag(a)));
    // (b) receiver reached the network → world provably live → unexplained-stale → RED
    let b = grade_live(&cold, amount, Some(NOW));
    println!("  (b) live_tick=Some(now) gap>Δ → {}      (network live: staleness unexplained)", tag(b));
    csv.push_str(&format!("liveness_L,1440,live_tick=Some_gap>D,{}\n", tag(b)));
    // (c) contrast — same strong sender but CURRENT (within Δ) → L does not fire
    let mut fresh = base_ci();
    fresh.last_k3_at = NOW - 5; // 5 s ago → within Δ
    let c = grade_live(&fresh, amount, Some(NOW));
    println!("  (c) live_tick=Some(now) gap≤Δ → {}    (sender current: nothing to explain)", tag(c));
    csv.push_str(&format!("liveness_L,0,live_tick=Some_gap<=D,{}\n", tag(c)));
    println!("  → SAME staleness, {} (dark) vs {} (live) — that is the L demonstration.", tag(a), tag(b));

    std::fs::write("ark_ci_grid.csv", &csv).expect("write ark_ci_grid.csv");
    println!("\n[wrote ark_ci_grid.csv — {} rows]", csv.lines().count() - 1);
}
