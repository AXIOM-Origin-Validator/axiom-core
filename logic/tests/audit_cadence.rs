//! §23.14 audit cadence (YP §23.14 AS BUILT items 1 and 9, amended 2026-09-26).
//! the owner: "1 in 50 should be enough, and make sure time bonded audit is executed".
//! Pins the volume rate (every build) and the time-bond floor (dev / real), so a
//! register edit that drifts from the ruling fails here.
use axiom_core_logic::types::{AUDIT_MAX_TICK_GAP, AUDIT_TRIGGER_RATE};

#[test]
fn volume_trigger_is_one_in_fifty_in_every_build() {
    assert_eq!(AUDIT_TRIGGER_RATE, 50);
}

#[test]
fn time_bond_floor_is_build_selected() {
    #[cfg(feature = "dev-mode")]
    assert_eq!(AUDIT_MAX_TICK_GAP, 1_800, "dev time-bond floor: 30 min");
    #[cfg(not(feature = "dev-mode"))]
    assert_eq!(AUDIT_MAX_TICK_GAP, 17_000, "real time-bond floor: ~4.7 h");
}
