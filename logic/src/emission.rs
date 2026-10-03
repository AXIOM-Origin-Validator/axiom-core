//! Contribution emission — the epoch arithmetic, as ONE pure function set that
//! every Nabla node calls (`AXIOM_DESIGN_ValidatorEmission.md` §4, YP §25.2.4
//! v2.21.0). Core owns the arithmetic so a node that computes a different share
//! or top-up is disagreeing with Core, not with a peer. Nothing here reads state:
//! the inputs are the registers and the counts Nabla observed.
//!
//! Registers (protocol_core.toml): `validator_emission_target_atoms_per_day`,
//! `nabla_emission_target_atoms_per_day`, `deed_draw_cap_validator_bps`,
//! `deed_draw_cap_nabla_bps`. Epoch length: the FOB epoch (Nabla's register).

use crate::validation::protocol_gen::{
    DEED_DRAW_CAP_NABLA_BPS, DEED_DRAW_CAP_VALIDATOR_BPS,
    NABLA_EMISSION_TARGET_ATOMS_PER_DAY, VALIDATOR_EMISSION_TARGET_ATOMS_PER_DAY,
};
use crate::types::FEE_BPS_DIVISOR;

const SECS_PER_DAY: u128 = 86_400;

/// A group's per-epoch NEED in atoms: `target_atoms_per_day × epoch_secs / 86_400`.
pub fn epoch_need(target_atoms_per_day: u64, epoch_secs: u64) -> u64 {
    (target_atoms_per_day as u128 * epoch_secs as u128 / SECS_PER_DAY) as u64
}

pub fn validator_epoch_need(epoch_secs: u64) -> u64 {
    epoch_need(VALIDATOR_EMISSION_TARGET_ATOMS_PER_DAY, epoch_secs)
}

pub fn nabla_epoch_need(epoch_secs: u64) -> u64 {
    epoch_need(NABLA_EMISSION_TARGET_ATOMS_PER_DAY, epoch_secs)
}

/// The per-claim SHARE for epoch e: the group's need divided by LAST epoch's
/// claim count (`k_prev`), equal within the group until Pulse weights it. A zero
/// count (nobody claimed last epoch) counts as one, so the first claimant of a
/// new group takes the whole need — bounded by it.
pub fn share_for_epoch(need: u64, k_prev: u64) -> u64 {
    need / k_prev.max(1)
}

/// The DEED → Emission top-up at an epoch boundary, ONE rule every node applies
/// from the same settled inputs (§4.3):
///   shortfall = max(0, need_v + need_n − pool_balance)
///   split in the targets' proportion, each half bounded by its remaining DEED
///   draw cap and by what DEED holds.
/// Returns `(draw_v, draw_n)`; the caller moves `draw_v + draw_n` from DEED to
/// the pool and advances the two cumulative-draw counters.
pub fn top_up(
    need_v: u64,
    need_n: u64,
    pool_balance: u64,
    deed_settled: u64,
    cap_v_remaining: u64,
    cap_n_remaining: u64,
) -> (u64, u64) {
    let need = need_v as u128 + need_n as u128;
    let shortfall = need.saturating_sub(pool_balance as u128);
    if shortfall == 0 || need == 0 {
        return (0, 0);
    }
    let want_v = shortfall * need_v as u128 / need;
    let want_n = shortfall - want_v;
    let draw_v = want_v.min(cap_v_remaining as u128).min(deed_settled as u128) as u64;
    let draw_n = want_n
        .min(cap_n_remaining as u128)
        .min(deed_settled as u128 - draw_v as u128) as u64;
    (draw_v, draw_n)
}

/// A group's remaining DEED draw cap: `cap_bps` of cumulative DEED inflow minus
/// what the group has already drawn. The developer share is the remainder and
/// never leaves DEED.
pub fn cap_remaining(cumulative_deed_inflow: u64, cap_bps: u64, drawn_so_far: u64) -> u64 {
    let cap = (cumulative_deed_inflow as u128 * cap_bps as u128 / FEE_BPS_DIVISOR as u128) as u64;
    cap.saturating_sub(drawn_so_far)
}

pub fn validator_cap_remaining(cumulative_deed_inflow: u64, drawn_so_far: u64) -> u64 {
    cap_remaining(cumulative_deed_inflow, DEED_DRAW_CAP_VALIDATOR_BPS, drawn_so_far)
}

pub fn nabla_cap_remaining(cumulative_deed_inflow: u64, drawn_so_far: u64) -> u64 {
    cap_remaining(cumulative_deed_inflow, DEED_DRAW_CAP_NABLA_BPS, drawn_so_far)
}

#[cfg(test)]
mod tests {
    use super::*;
    const DAY: u64 = 86_400;

    #[test]
    fn need_is_target_times_epoch_days() {
        // 123.3 AXC/day over exactly one day = the register itself.
        assert_eq!(validator_epoch_need(DAY), VALIDATOR_EMISSION_TARGET_ATOMS_PER_DAY);
        assert_eq!(nabla_epoch_need(2 * DAY), 2 * NABLA_EMISSION_TARGET_ATOMS_PER_DAY);
        assert_eq!(epoch_need(1_000, DAY / 2), 500);
    }

    #[test]
    fn share_divides_by_last_count_and_never_by_zero() {
        assert_eq!(share_for_epoch(9_000, 90), 100);
        assert_eq!(share_for_epoch(9_000, 0), 9_000, "no claimants last epoch → one whole share");
        assert_eq!(share_for_epoch(9_000, 1), 9_000);
        assert_eq!(share_for_epoch(0, 5), 0);
    }

    #[test]
    fn top_up_is_the_shortfall_only() {
        // Pool already covers the need → nothing moves (E10).
        assert_eq!(top_up(100, 50, 150, 1_000, 1_000, 1_000), (0, 0));
        assert_eq!(top_up(100, 50, 200, 1_000, 1_000, 1_000), (0, 0));
        // Short by 30 → split 2:1 in the targets' proportion.
        assert_eq!(top_up(100, 50, 120, 1_000, 1_000, 1_000), (20, 10));
        // Empty pool → the whole need.
        assert_eq!(top_up(100, 50, 0, 1_000, 1_000, 1_000), (100, 50));
    }

    #[test]
    fn top_up_is_bounded_by_deed_and_by_the_caps() {
        // DEED holds less than the shortfall: validators first (their share of
        // the split), Nabla gets what is left.
        assert_eq!(top_up(100, 50, 0, 110, 1_000, 1_000), (100, 10));
        // Caps bind per group; the other group is not compensated.
        assert_eq!(top_up(100, 50, 0, 1_000, 30, 1_000), (30, 50));
        assert_eq!(top_up(100, 50, 0, 1_000, 1_000, 5), (100, 5));
        // Zero need → nothing, even with an empty pool.
        assert_eq!(top_up(0, 0, 0, 1_000, 1_000, 1_000), (0, 0));
    }

    #[test]
    fn caps_are_bps_of_cumulative_inflow_minus_drawn() {
        // 20 % of 10,000 = 2,000; 500 already drawn → 1,500 left.
        assert_eq!(cap_remaining(10_000, 2_000, 500), 1_500);
        assert_eq!(cap_remaining(10_000, 2_000, 2_000), 0);
        assert_eq!(cap_remaining(10_000, 2_000, 9_999), 0, "never underflows");
        assert_eq!(validator_cap_remaining(10_000, 0), 2_000);
        assert_eq!(nabla_cap_remaining(10_000, 0), 3_000);
        // The registers: validators + Nabla < 100 %, the developer remainder is real.
        assert!(DEED_DRAW_CAP_VALIDATOR_BPS + DEED_DRAW_CAP_NABLA_BPS < FEE_BPS_DIVISOR as u64);
    }
}
