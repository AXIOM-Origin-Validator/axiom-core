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

/// Blessed PRIOR CoreIDs — the CoreID-lineage accept-set.
///
/// Comma-separated hex (each 64 hex chars = 32 bytes) of PRIOR canonical Cores
/// whose DMAP attestations remain acceptable across a **routine** rotation (a
/// commitment-formula-preserving ELF change). Set via
/// `AXIOM_BLESSED_PRIOR_CORE_IDS` at build time, right beside
/// `AXIOM_CANONICAL_CORE_ID`; empty on dev builds (⇒ current-CoreID-only, i.e.
/// byte-identical to the pre-accept-set behavior).
///
/// A prior CoreID is a fixed known hash (no self-reference, unlike the current
/// CoreID which cannot live inside its own ELF), so it is safe to bake in.
///
/// **CoreID-BOUND:** this const is compiled into the guest ELF (via
/// `axiom-core-logic`), so the blessed set is part of the Core's cryptographic
/// identity — changing it rotates the CoreID (blessing `{}` vs `{d0900069}` yields
/// different CoreIDs). That is deliberate and consensus-safe: validators run the same
/// committed ELF, so its baked-in blessed set is shared by construction, and a
/// divergent set is a divergent CoreID (can't co-exist). Change it only via a rotation
/// — you bless the retiring CoreID as part of rotating to the new one.
/// `scripts/build-core-elf.sh` reads the committed
/// `core/artifacts/BLESSED_PRIOR_CORE_IDS.txt`; the RISC-V build is not bit-reproducible,
/// so verify the CoreID by hashing the committed ELF, never by rebuilding.
/// **Revocation = omission:** a compromised prior is simply not listed on the
/// next build. Safe to accept only because an honest prior Core rejects mints
/// exactly like the current one — see
/// `docs/AXIOM_DESIGN_CoreUpgradeMigration.md` §11 and the machine-checked
/// `papers/continuity-without-consensus/model/AxiomRedeemMintSafety*.tla`.
pub const BLESSED_PRIOR_CORE_IDS: &str = match option_env!("AXIOM_BLESSED_PRIOR_CORE_IDS") {
    Some(ids) => ids,
    None => "",
};

/// Decode one ASCII hex nibble. `None` on any non-hex byte.
#[inline]
fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Parse a 64-char hex string into a 32-byte CoreID. `None` on any malformed
/// input (wrong length or non-hex). no_std / no-alloc.
fn parse_core_id_hex(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let hi = match hex_nibble(bytes[i * 2]) {
            Some(v) => v,
            None => return None,
        };
        let lo = match hex_nibble(bytes[i * 2 + 1]) {
            Some(v) => v,
            None => return None,
        };
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Some(out)
}

/// Injectable core of [`is_accepted_core_id`] — the `blessed` comma-separated-hex
/// string is a parameter instead of the build-time const, so integration tests (and
/// any caller wanting to check membership against an explicit set) can exercise the
/// lineage logic without an env var. `is_accepted_core_id` is exactly this with
/// `blessed = BLESSED_PRIOR_CORE_IDS`.
pub fn is_accepted_core_id_in(core_id: &[u8; 32], current_core_id: &[u8; 32], blessed: &str) -> bool {
    if core_id == current_core_id {
        return true;
    }
    for entry in blessed.split(',') {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(parsed) = parse_core_id_hex(trimmed) {
            if &parsed == core_id {
                return true;
            }
        }
    }
    false
}

/// Is `core_id` acceptable for DMAP attestation verification?
///
/// True iff it is the current canonical CoreID, or a blessed (non-revoked) prior
/// from [`BLESSED_PRIOR_CORE_IDS`]. `current_core_id` is the host's trusted CoreID
/// (the loaded ELF's, verified `== CANONICAL_CORE_ID` at startup) — passed in so
/// dev and release builds behave identically.
///
/// This is the single accept-set predicate the DMAP verify sites gate on (Lambda
/// redeem, Nabla register). With an empty accept-set it reduces to
/// `core_id == current_core_id`, byte-identical to the pre-change behavior. It
/// **never** accepts an arbitrary attestation-supplied CoreID — only the trusted,
/// baked-in lineage — preserving the SEC-3 invariant.
/// See `docs/AXIOM_DESIGN_CoreUpgradeMigration.md` §11.
pub fn is_accepted_core_id(core_id: &[u8; 32], current_core_id: &[u8; 32]) -> bool {
    is_accepted_core_id_in(core_id, current_core_id, BLESSED_PRIOR_CORE_IDS)
}

/// Injectable core of [`resolve_dmap_verify_core_id`] (see that fn) — `blessed` is a
/// parameter so tests exercise the EXACT resolution the verify sites use without a
/// build-time env var.
pub fn resolve_dmap_verify_core_id_in(
    attestation_core_id: &[u8; 32],
    current_core_id: &[u8; 32],
    blessed: &str,
) -> [u8; 32] {
    if is_accepted_core_id_in(attestation_core_id, current_core_id, blessed) {
        *attestation_core_id
    } else {
        *current_core_id
    }
}

/// Choose the CoreID a DMAP attestation must be verified against.
///
/// Returns the attestation's OWN CoreID iff it is in the accept-set — so
/// `verify_dmap_attestation` (including its challenge derivation, which is seeded by
/// the CoreID) runs against the CoreID the attestation was actually built with.
/// Otherwise returns `current_core_id`, which forces a `WrongCore` for any
/// non-blessed attestation.
///
/// This is the SINGLE decision shared by every DMAP verify site (Lambda redeem,
/// Nabla register) and by the accept-set composition test — one builder, no drift
/// (CLAUDE.md §12). See `docs/AXIOM_DESIGN_CoreUpgradeMigration.md` §11.
pub fn resolve_dmap_verify_core_id(
    attestation_core_id: &[u8; 32],
    current_core_id: &[u8; 32],
) -> [u8; 32] {
    resolve_dmap_verify_core_id_in(attestation_core_id, current_core_id, BLESSED_PRIOR_CORE_IDS)
}

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

    // ── CoreID lineage accept-set (§11) ─────────────────────────────────────

    const A: [u8; 32] = [0xAA; 32]; // "current" CoreID
    const B: [u8; 32] = [0xBB; 32]; // a blessed prior
    const C: [u8; 32] = [0xCC; 32]; // an unknown / revoked CoreID

    fn hex64(b: &[u8; 32]) -> alloc::string::String {
        use core::fmt::Write;
        let mut s = alloc::string::String::new();
        for byte in b {
            let _ = write!(s, "{:02x}", byte);
        }
        s
    }

    #[test]
    fn parse_core_id_hex_roundtrip() {
        assert_eq!(parse_core_id_hex(&hex64(&B)), Some(B));
        assert_eq!(parse_core_id_hex(&hex64(&A).to_uppercase()), Some(A)); // case-insensitive
    }

    #[test]
    fn parse_core_id_hex_rejects_malformed() {
        assert_eq!(parse_core_id_hex(""), None); // wrong length
        assert_eq!(parse_core_id_hex("abcd"), None); // too short
        let mut bad = hex64(&B);
        bad.push_str("zz"); // wrong length + non-hex
        assert_eq!(parse_core_id_hex(&bad), None);
        let mut nonhex = hex64(&B);
        nonhex.replace_range(0..1, "g"); // exactly 64 chars but non-hex
        assert_eq!(parse_core_id_hex(&nonhex), None);
    }

    #[test]
    fn accept_set_current_always_accepted() {
        // Current CoreID accepted regardless of the (here empty) blessed set.
        assert!(is_accepted_core_id_in(&A, &A, ""));
    }

    #[test]
    fn accept_set_empty_is_current_only() {
        // Empty blessed set ⇒ byte-identical to the old `== current` behavior.
        assert!(is_accepted_core_id_in(&A, &A, ""));
        assert!(!is_accepted_core_id_in(&B, &A, ""));
        assert!(!is_accepted_core_id_in(&C, &A, ""));
    }

    #[test]
    fn accept_set_blessed_prior_accepted() {
        let blessed = hex64(&B);
        assert!(is_accepted_core_id_in(&B, &A, &blessed)); // prior accepted
        assert!(is_accepted_core_id_in(&A, &A, &blessed)); // current still accepted
        assert!(!is_accepted_core_id_in(&C, &A, &blessed)); // unknown rejected
    }

    #[test]
    fn accept_set_multiple_priors_and_whitespace() {
        // Comma-separated, tolerant of surrounding whitespace.
        let blessed = alloc::format!(" {} , {} ", hex64(&B), hex64(&C));
        assert!(is_accepted_core_id_in(&B, &A, &blessed));
        assert!(is_accepted_core_id_in(&C, &A, &blessed));
        assert!(!is_accepted_core_id_in(&[0x11; 32], &A, &blessed));
    }

    #[test]
    fn accept_set_revocation_by_omission() {
        // B blessed then dropped (revoked) ⇒ no longer accepted; the same cheque
        // that redeemed under {B} fails under {} — revocation-by-omission (§11.5).
        let with_b = hex64(&B);
        assert!(is_accepted_core_id_in(&B, &A, &with_b));
        assert!(!is_accepted_core_id_in(&B, &A, "")); // rebuilt without B
    }

    #[test]
    fn accept_set_ignores_malformed_entries() {
        // A malformed entry is skipped, not fatal; valid entries still match.
        let blessed = alloc::format!("not-hex,{},also_bad", hex64(&B));
        assert!(is_accepted_core_id_in(&B, &A, &blessed));
        assert!(!is_accepted_core_id_in(&C, &A, &blessed));
    }

    #[test]
    fn accept_set_env_baked() {
        // Proves the BUILD-TIME wiring: `option_env!("AXIOM_BLESSED_PRIOR_CORE_IDS")`
        // -> BLESSED_PRIOR_CORE_IDS const -> the PUBLIC `is_accepted_core_id` (the exact
        // predicate the lambda/nabla verify sites call). This is what the env-level
        // ceremony would otherwise be needed to confirm; here it costs ONE build.
        //
        // Unset (normal build) => BLESSED_PRIOR_CORE_IDS is empty => accept-set is
        // current-only. To exercise the bake-in path, build with the var set:
        //   AXIOM_BLESSED_PRIOR_CORE_IDS=aaaa…aa (64 hex) \
        //     cargo test -p axiom-core-logic --features dev-mode version::accept_set_env_baked
        // build.rs's `rerun-if-env-changed=AXIOM_BLESSED_PRIOR_CORE_IDS` forces the
        // recompile so the new value is actually baked.
        let current = [0x01u8; 32];

        // (1) Every CoreID compiled into the const MUST be honored by the public fn.
        let mut baked = 0usize;
        for entry in BLESSED_PRIOR_CORE_IDS.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let cid = parse_core_id_hex(entry)
                .unwrap_or_else(|| panic!("AXIOM_BLESSED_PRIOR_CORE_IDS entry not 64-hex: {entry:?}"));
            assert_ne!(cid, current, "pick a `current` distinct from the blessed entry");
            assert!(
                is_accepted_core_id(&cid, &current),
                "compiled-in blessed CoreID {entry} must be accepted by is_accepted_core_id \
                 (option_env! -> const -> fn bake-in is broken)"
            );
            baked += 1;
        }

        // (2) The current CoreID is always accepted.
        assert!(is_accepted_core_id(&current, &current));

        // (3) A value that is neither current nor baked-in must be rejected.
        let bogus = [0xEEu8; 32];
        let bogus_baked = BLESSED_PRIOR_CORE_IDS
            .split(',')
            .filter_map(|e| parse_core_id_hex(e.trim()))
            .any(|c| c == bogus);
        if !bogus_baked {
            assert!(
                !is_accepted_core_id(&bogus, &current),
                "a non-blessed CoreID must be rejected by the build-time predicate"
            );
        }

        if baked == 0 {
            eprintln!(
                "note: AXIOM_BLESSED_PRIOR_CORE_IDS unset at build — bake-in path not exercised; \
                 set it to a 64-hex value to prove the const wiring."
            );
        } else {
            eprintln!("bake-in verified: {baked} blessed prior CoreID(s) honored via the build-time const");
        }
    }
}
