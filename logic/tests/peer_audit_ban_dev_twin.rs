//! §23.14 ban length has a dev twin (YP §23.14 AS BUILT item 7, amended 2026-09-26).
//! A `dev-mode` build must use `peer_audit_ban_ticks_dev` (720 ≈ 1 h) so a soak can
//! watch a ban LIFT; every other build keeps the ≈ 24 h production value. This fails
//! if the twin is dropped from `protocol_core.toml` or build.rs stops selecting it.
use axiom_core_logic::types::{PEER_AUDIT_BAN_TICKS, TICK_INTERVAL_SECS};

#[test]
fn peer_audit_ban_ticks_is_build_selected() {
    #[cfg(feature = "dev-mode")]
    assert_eq!(PEER_AUDIT_BAN_TICKS, 720, "dev-mode build must use peer_audit_ban_ticks_dev");
    #[cfg(not(feature = "dev-mode"))]
    assert_eq!(PEER_AUDIT_BAN_TICKS, 17_280, "production build must keep the 24 h ban");
}

#[test]
fn peer_audit_ban_window_is_the_stated_duration() {
    let secs = PEER_AUDIT_BAN_TICKS * TICK_INTERVAL_SECS;
    #[cfg(feature = "dev-mode")]
    assert_eq!(secs, 3_600);
    #[cfg(not(feature = "dev-mode"))]
    assert_eq!(secs, 86_400);
}
