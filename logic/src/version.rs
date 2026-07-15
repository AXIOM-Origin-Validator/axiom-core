//! AXIOM Core Version
//!
//! Protocol version identity — embedded in every Receipt as informational
//! metadata. The version tag is informational and can be faked. The REAL
//! proof of correct execution is the ELF hash (CoreID — BLAKE3 of
//! `axiom-core.elf`). The `is_compatible` check below is a fast pre-filter
//! to reject obviously incompatible transactions (e.g. a different era)
//! before doing any crypto work — it does NOT prove receipt interop.
//!
//! Format: "{name}/{build}/{phase}"
//!   - name:   Protocol era (e.g. "Kyoto")
//!   - build:  Release number (e.g. "1.1") — moving this is a real
//!             protocol break, ELF rebuild required
//!   - phase:  Network/historical phase marker (e.g. "GENESIS") —
//!             informational only, can roll forward over time without
//!             breaking interop between phases
//!
//! Core has no carrier suffix. `axiom-core.elf` is a single mode-agnostic
//! binary; whether it runs under the DMAP-VM (in-process AVM) or the
//! zk-VM (subprocess prover) is a property of the runtime around it, not
//! of Core itself.
//!
//! IMPORTANT — version tag is NOT a real interop gate. Two Cores at the
//! same `name/build` but built from different ELFs (different CoreIDs)
//! will produce non-byte-identical Receipts and will NOT interoperate
//! at the consensus level, regardless of what the version string claims.
//! Real interop is enforced by CoreID match — a network-level operator
//! concern, not a protocol gate.

/// Protocol era name
pub const CORE_VERSION_NAME: &str = "Kyoto";

/// Release build number
pub const CORE_VERSION_BUILD: &str = "1.1";

/// Phase marker — informational. Rolls forward over time without breaking
/// interop between phases (the build-level prefix is what compat checks).
/// Current: "GENESIS" — initial-distribution phase.
pub const CORE_VERSION_PHASE: &str = "GENESIS";

/// Full version string — embedded in every Receipt. The phase suffix is
/// forensic metadata; compat checks ignore it and prefix-match on
/// `name/build` only (see `is_compatible`).
pub const CORE_VERSION_TAG: &str = concat!("Kyoto", "/", "1.1", "/", "GENESIS");

/// The era+build prefix that `is_compatible` matches on.
const COMPAT_PREFIX: &str = "Kyoto/1.1";

/// Full version string — identical to `CORE_VERSION_TAG`. Kept as a
/// function for historical call-site compat.
pub const fn core_version_full() -> &'static str {
    CORE_VERSION_TAG
}

/// Canonical CoreID — BLAKE3 hash of the release `axiom-core.elf`.
///
/// Set via `AXIOM_CANONICAL_CORE_ID` env var at build time. Empty = dev
/// build (no enforcement). Release builds set this after running
/// `scripts/build-core-elf.sh` and `scripts/publish-core-id.sh`.
///
/// At Lambda startup, the loaded ELF's CoreID is compared against this
/// constant. Mismatch = startup error. This is the REAL compatibility
/// check that ensures all validators on a network run the same Core
/// binary; the version-tag check below is just a string sanity filter.
pub const CANONICAL_CORE_ID: &str = match option_env!("AXIOM_CANONICAL_CORE_ID") {
    Some(id) => id,
    None => "",
};

/// Quick pre-filter for obviously incompatible TXs. Matches the
/// `{name}/{build}` prefix only; the phase suffix is intentionally
/// ignored because phases roll forward and are informational.
///
/// NOTE: passing this check does NOT mean two validators can interop.
/// Real interop is via CoreID match. This is just a cheap "wrong era /
/// wrong build" reject before any crypto work.
pub fn is_compatible(version_tag: &str) -> bool {
    if !version_tag.starts_with(COMPAT_PREFIX) {
        return false;
    }
    // Accept either bare "Kyoto/1.1" (legacy / pre-phase-tag) or
    // "Kyoto/1.1/<phase>" with any phase suffix (phases are informational).
    let rest = &version_tag[COMPAT_PREFIX.len()..];
    rest.is_empty() || rest.starts_with('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_constants() {
        assert_eq!(CORE_VERSION_NAME, "Kyoto");
        assert_eq!(CORE_VERSION_BUILD, "1.1");
        assert_eq!(CORE_VERSION_PHASE, "GENESIS");
        assert_eq!(CORE_VERSION_TAG, "Kyoto/1.1/GENESIS");
    }

    #[test]
    fn test_version_full() {
        assert_eq!(core_version_full(), "Kyoto/1.1/GENESIS");
    }

    #[test]
    fn test_compatible_with_current_phase() {
        // Build matches + phase matches → compat
        assert!(is_compatible("Kyoto/1.1/GENESIS"));
    }

    #[test]
    fn test_compatible_with_bare_buildonly() {
        // Legacy / pre-phase-tag clients send bare "Kyoto/1.1" — still
        // compat (build prefix matches; missing phase is forensic loss
        // only, not a consensus error).
        assert!(is_compatible("Kyoto/1.1"));
    }

    #[test]
    fn test_compatible_with_future_phase() {
        // Phase rolls forward without breaking compat. A "Kyoto/1.1/WW3"
        // build CAN'T actually interop (CoreID differs) but the version
        // tag pre-filter doesn't pretend to check that — that's the
        // operator's job at deploy time.
        assert!(is_compatible("Kyoto/1.1/WW3"));
        assert!(is_compatible("Kyoto/1.1/POST-GENESIS"));
        assert!(is_compatible("Kyoto/1.1/MAINNET"));
    }

    #[test]
    fn test_incompatible_different_build() {
        assert!(!is_compatible("Kyoto/1.0"));
        assert!(!is_compatible("Kyoto/1.01"));
        assert!(!is_compatible("Kyoto/1.2"));
        assert!(!is_compatible("Kyoto/2.0"));
        assert!(!is_compatible("Kyoto/1.0/GENESIS"));
    }

    #[test]
    fn test_incompatible_different_name() {
        assert!(!is_compatible("Osaka/1.1"));
        assert!(!is_compatible("Osaka/1.1/GENESIS"));
        assert!(!is_compatible("Tokyo/1.1/GENESIS"));
    }

    #[test]
    fn test_incompatible_empty() {
        assert!(!is_compatible(""));
    }

    #[test]
    fn test_incompatible_partial() {
        assert!(!is_compatible("Kyoto"));
        assert!(!is_compatible("Kyoto/"));
        assert!(!is_compatible("Kyoto/1"));
    }

    #[test]
    fn test_no_carrier_suffix_misread_as_phase() {
        // Pre-rename builds emitted "Kyoto/1.01/DMAP" — different build,
        // rejected by the prefix check.
        assert!(!is_compatible("Kyoto/1.01/DMAP"));
        // But "Kyoto/1.1/DMAP" — though semantically wrong (DMAP is a
        // carrier, not a phase) — passes the version tag pre-filter.
        // It's the OPERATOR's job not to spin up a `/DMAP`-tagged
        // validator alongside a `/GENESIS`-tagged one; the version
        // string is informational and can't enforce that distinction.
        // Real correctness is CoreID match.
        assert!(is_compatible("Kyoto/1.1/DMAP"));
    }

    #[test]
    fn test_compat_prefix_must_have_separator() {
        // "Kyoto/1.10" must NOT match the "Kyoto/1.1" prefix as a build
        // — the separator check prevents that lexical-prefix accident.
        assert!(!is_compatible("Kyoto/1.10"));
        assert!(!is_compatible("Kyoto/1.11"));
        assert!(!is_compatible("Kyoto/1.1GENESIS"));
    }
}
