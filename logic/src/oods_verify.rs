//! OODS proof verification — the Core-side (integer, deterministic) kernel of
//! YPX-021 enforcement.
//!
//! Core verifies that each per-channel minimum a node claims is the REAL hash of
//! a genesis-chained identity for the CANONICAL epoch seed. It does **not**
//! compute the floating-point size estimate `N̂` — that is a *public* function of
//! the verified integers, derived off-Core (`nabla::oods`), which keeps this
//! module (and therefore the RISC-V ELF) **float-free and fully deterministic**.
//!
//! Trust model (CLAUDE.md §1): the value is trustworthy only because Core
//! recomputes it. A node cannot claim a bigger network (smaller min-draws =
//! larger `raw`s) than it can back with real identities that actually hash that
//! large for the epoch — that is the §5 pricing. Genesis-chain validity of each
//! identity is checked by the existing CL7 NBC path (wired in Phase 2); this
//! kernel checks the OODS-novel part: that the claimed raw equals the recompute.
//!
//! See `docs/AXIOM_YPX-021_OODS.md` §4 (estimator), §5.1.1 (canonical seed), §6
//! (Core-verify-by-recomputation). Phase 1: CoreID-neutral (not yet wired into a
//! consensus mode).

use core::convert::TryInto;

/// Number of extrema channels. MUST match `nabla::oods::CHANNELS`.
pub const CHANNELS: usize = 128;

/// Domain for the per-identity extrema draw. MUST byte-match `nabla::oods::draw`
/// (the estimator that produces the minima this verifies). YPX-021 §4.
const OODS_DRAW_DOMAIN: &[u8] = b"AXIOM_OODS_v1";

/// Domain for the canonical epoch seed. YPX-021 §5.1.1.
const OODS_EPOCH_DOMAIN: &[u8] = b"AXIOM_OODS_EPOCH_v1";

/// Canonical epoch seed (§5.1.1): a hash of the fixed-offset committed artifact
/// `A(n)` (the converged SMT root / commit-reveal value at tick `n*E - D`). One
/// valid seed per epoch (K=1). Core recomputes this from the committed artifact
/// it independently verifies and rejects any proof whose seed != this value —
/// closing seed-grinding, since there is no menu of candidate seeds to choose.
pub fn oods_epoch_seed(epoch: u64, artifact: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(OODS_EPOCH_DOMAIN);
    h.update(&epoch.to_le_bytes());
    h.update(artifact);
    *h.finalize().as_bytes()
}

/// The integer extrema "raw" for one identity on one channel — the top 64 bits
/// of the same BLAKE3 the estimator uses, BEFORE the float `-ln(u/2^64)` map.
/// A larger `raw` is a smaller min-draw is a larger claimed size, so this is the
/// exact integer an inflation attacker must forge — and cannot, without an
/// identity that genuinely produces it.
pub fn oods_raw(identity: &[u8], epoch_seed: &[u8], channel: u32) -> u64 {
    let mut h = blake3::Hasher::new();
    h.update(OODS_DRAW_DOMAIN);
    h.update(identity);
    h.update(epoch_seed);
    h.update(&channel.to_le_bytes());
    let d = h.finalize();
    u64::from_le_bytes(d.as_bytes()[0..8].try_into().unwrap())
}

/// One channel's claimed minimum: the channel index, the identity that achieves
/// it, and the raw value the claimant asserts for it.
pub struct OodsChannelClaim<'a> {
    pub channel: u32,
    pub identity: &'a [u8],
    pub claimed_raw: u64,
}

/// Why an OODS proof failed Core verification.
#[derive(Debug, PartialEq, Eq)]
pub enum OodsVerifyError {
    /// A claimed raw did not equal the recompute from (identity, seed, channel)
    /// — a forged/inflated minimum. The load-bearing rejection.
    RawMismatch { channel: u32 },
    /// The proof did not cover exactly `CHANNELS` channels, or covered a channel
    /// out of range / more than once.
    ChannelCoverage,
}

/// The forgery-rejection kernel (§6). Every claimed per-channel `raw` MUST equal
/// the recompute from its `identity` under the **canonical** `epoch_seed`, and
/// the proof MUST cover every channel `0..CHANNELS` exactly once. A fake-large
/// raw (fake-small min-draw = inflated size) is impossible unless the claimant
/// reveals a real identity that actually produces it — the §5 pricing.
///
/// NOTE: genesis-chain validity of each `claim.identity` is verified separately
/// by the CL7 NBC path at the Phase-2 call site; this kernel proves the
/// recompute, which is the OODS-novel half.
pub fn verify_oods_channel_raws(
    claims: &[OodsChannelClaim],
    epoch_seed: &[u8],
) -> Result<(), OodsVerifyError> {
    if claims.len() != CHANNELS {
        return Err(OodsVerifyError::ChannelCoverage);
    }
    // Every channel 0..CHANNELS must appear exactly once.
    let mut seen = [false; CHANNELS];
    for c in claims {
        let idx = c.channel as usize;
        if idx >= CHANNELS || seen[idx] {
            return Err(OodsVerifyError::ChannelCoverage);
        }
        seen[idx] = true;
        let recomputed = oods_raw(c.identity, epoch_seed, c.channel);
        if recomputed != c.claimed_raw {
            return Err(OodsVerifyError::RawMismatch { channel: c.channel });
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// OODS-tardis (YPX-021 §6, purpose-1): the STATELESS Core producer/merger.
//
// The existing kernel above VERIFIES a claimed accumulator. This half lets Core
// also PRODUCE its own contribution and FOLD a tick-carried accumulator — the
// piece that makes a second, Core-bound OODS possible (distinct from the Nabla
// gossip estimator). It is purely additive, integer-only, and STATELESS: the
// accumulator is the state and it rides the tick (Core stores nothing). The
// float estimate `N̂ = M/Σ(−ln(raw/2^64))` stays OFF-Core (public function of
// these verified integers), keeping the ELF float-free.
//
// Reusable by IDENTITY SET (§the multi-purpose point): feed node NBC/VBC pubkeys
// → network *node* count; feed wallet identities → active *wallet* count. Same
// math, different `identity` — a partition drops the observed count either way.
// ─────────────────────────────────────────────────────────────────────────────

use alloc::vec::Vec;

/// One channel's running network-wide extremum, carried on the tick as it
/// cascades: the identity currently achieving the maximum `raw` (= the smallest
/// min-draw = the largest size that channel can back) and that `raw`. The vector
/// of these — one per channel — IS the OODS accumulator; it lives on the wire, so
/// Core stays stateless.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OodsExtremum {
    pub channel: u32,
    pub identity: Vec<u8>,
    pub raw: u64,
}

/// Produce THIS node's extrema contribution for the canonical `epoch_seed`: its
/// `raw` on every channel, achieved by its own `identity`. Stateless + pure
/// (reuses `oods_raw`). `identity` is the node's NBC/VBC pubkey for a node count,
/// or a wallet identity for a wallet count — the primitive doesn't care which.
pub fn oods_produce(identity: &[u8], epoch_seed: &[u8]) -> Vec<OodsExtremum> {
    (0..CHANNELS as u32)
        .map(|channel| OodsExtremum {
            channel,
            identity: identity.into(),
            raw: oods_raw(identity, epoch_seed, channel),
        })
        .collect()
}

/// Fold a `contribution` into the tick-carried `acc`umulator: per channel, keep
/// the LARGER `raw` (smaller min-draw = the running network-wide extremum) and
/// the identity achieving it. This is a **max-semilattice join** — idempotent,
/// commutative, associative — so the tick cascade converges to the same
/// per-channel maxima regardless of path, duplication, or loss (the CRDT
/// argument). Stateless: `acc` is the whole state, and it rides the tick.
///
/// `acc` is indexed by channel; a fresh accumulator is `oods_produce(self, seed)`
/// (a node folds its own contribution first, then every child/parent tick's).
pub fn oods_fold(acc: &mut [OodsExtremum], contribution: &[OodsExtremum]) {
    for c in contribution {
        let idx = c.channel as usize;
        if idx >= acc.len() {
            continue;
        }
        // Tie-break on identity bytes keeps the fold deterministic across nodes
        // when two identities produce the same raw on a channel (vanishingly
        // rare, but the merge must still be a total function).
        let a = &acc[idx];
        let take = c.raw > a.raw || (c.raw == a.raw && c.identity > a.identity);
        if take {
            acc[idx].raw = c.raw;
            acc[idx].identity = c.identity.clone();
        }
    }
}

/// Verify a tick-carried accumulator the same way the wire kernel verifies a
/// proof: every extremum's `raw` must equal `oods_raw(identity, seed, channel)`
/// and the set must cover `0..CHANNELS` exactly once. (Genesis-chain validity of
/// each `identity` is the CL7 NBC path's job — see `verify_oods_channel_raws`.)
/// A verifier calls this on a received tick before trusting/merging it.
pub fn oods_verify_accumulator(
    acc: &[OodsExtremum],
    epoch_seed: &[u8],
) -> Result<(), OodsVerifyError> {
    let claims: Vec<OodsChannelClaim> = acc
        .iter()
        .map(|e| OodsChannelClaim {
            channel: e.channel,
            identity: &e.identity,
            claimed_raw: e.raw,
        })
        .collect();
    verify_oods_channel_raws(&claims, epoch_seed)
}

/// Q16 fixed-point ln(2).
const LN2_Q16: u64 = 45426; // round(ln(2) * 65536)

/// 17-entry LUT of `ln(1 + i/16)` in Q16, for i = 0..=16. Linear-interpolated
/// between entries. Keeps the estimate DETERMINISTIC (integer-only, no FPU) and
/// well inside OODS's tolerance — the reference point only has to be ballpark
/// (a partition is an order-of-magnitude drop), and this LUT is <0.5% per term.
const LN1P_Q16: [u64; 17] = [
    0, 3973, 7719, 11262, 14623, 17822, 20873, 23789, 26581, 29261, 31836,
    34313, 36701, 39006, 41233, 43386, 45426,
];

/// `−ln(raw / 2^64)` in Q16 fixed-point, integer-only and deterministic.
/// `raw ∈ (0, 2^64)`; a larger `raw` → smaller value (smaller min-draw).
fn neg_ln_ratio_q16(raw: u64) -> u64 {
    if raw == 0 {
        // raw=0 ⇒ ratio 0 ⇒ −ln→∞; clamp high (never happens for a real draw).
        return 64 * LN2_Q16;
    }
    // ln(raw) = msb·ln2 + ln(1 + mantissa), mantissa ∈ [0,1).
    let msb = 63 - raw.leading_zeros() as u64;
    // mantissa fraction in Q16: bits below the msb, scaled to [0, 65536).
    // u128 intermediate — `(raw - 2^msb) << 16` overflows u64 for large msb.
    let mant_q16 = if msb == 0 {
        0
    } else {
        ((((raw - (1u64 << msb)) as u128) << 16) >> msb) as u64
    };
    // LUT index + linear interpolation between the 16 buckets.
    let bucket = (mant_q16 >> 12) as usize; // 0..15
    let within = mant_q16 & 0xFFF; // 0..4095, position inside the bucket (Q12)
    let lo = LN1P_Q16[bucket];
    let hi = LN1P_Q16[bucket + 1];
    let ln1p = lo + ((hi - lo) * within >> 12);
    let ln_raw = msb * LN2_Q16 + ln1p;
    // −ln(raw/2^64) = 64·ln2 − ln(raw). ln_raw ≤ 64·ln2 always (raw < 2^64).
    (64 * LN2_Q16).saturating_sub(ln_raw)
}

/// Estimate the network size from a converged accumulator — **inside Core**,
/// deterministically (Q16 fixed-point, no floats), so the value is Core-bound
/// and every validator computes the same number. `N̂ = M / Σⱼ (−ln(rawⱼ/2^64))`.
/// Returned as a plain integer (rounded). Accuracy is ballpark by design — the
/// tardis/wallet OODS is a REFERENCE point cross-checked against the Nabla
/// gossip estimate, and a partition is an order-of-magnitude drop, not a few %.
pub fn oods_estimate(acc: &[OodsExtremum]) -> u64 {
    let mut sum_q16: u64 = 0;
    for e in acc {
        sum_q16 = sum_q16.saturating_add(neg_ln_ratio_q16(e.raw));
    }
    if sum_q16 == 0 {
        return 0;
    }
    // N̂ = M / (sum_q16 / 2^16) = (M << 16) / sum_q16, rounded.
    let m = acc.len() as u64;
    ((m << 16) + sum_q16 / 2) / sum_q16
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;

    fn pk(i: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0..8].copy_from_slice(&i.to_le_bytes());
        b
    }

    // A well-formed, honest proof: one claim per channel, raw = recompute.
    fn honest_claims<'a>(ids: &'a [[u8; 32]], seed: &[u8]) -> Vec<OodsChannelClaim<'a>> {
        (0..CHANNELS)
            .map(|ch| {
                let id = &ids[ch % ids.len()];
                OodsChannelClaim {
                    channel: ch as u32,
                    identity: id,
                    claimed_raw: oods_raw(id, seed, ch as u32),
                }
            })
            .collect()
    }

    #[test]
    fn epoch_seed_is_deterministic_and_sensitive() {
        let a = oods_epoch_seed(7, b"smt-root-abc");
        assert_eq!(a, oods_epoch_seed(7, b"smt-root-abc")); // deterministic
        assert_ne!(a, oods_epoch_seed(8, b"smt-root-abc")); // epoch matters
        assert_ne!(a, oods_epoch_seed(7, b"smt-root-xyz")); // artifact matters
    }

    #[test]
    fn oods_raw_matches_the_estimator_hash_layout() {
        // Independently replicate nabla::oods::draw's pre-float hash and confirm
        // Core's integer recompute is byte-consistent with the estimator.
        let id = pk(42);
        let seed = oods_epoch_seed(3, b"root");
        let mut h = blake3::Hasher::new();
        h.update(b"AXIOM_OODS_v1");
        h.update(&id);
        h.update(&seed);
        h.update(&5u32.to_le_bytes());
        let expect = u64::from_le_bytes(h.finalize().as_bytes()[0..8].try_into().unwrap());
        assert_eq!(oods_raw(&id, &seed, 5), expect);
    }

    #[test]
    fn verify_accepts_an_honest_proof() {
        let ids = [pk(1), pk(2), pk(3)];
        let seed = oods_epoch_seed(11, b"artifact");
        let claims = honest_claims(&ids, &seed);
        assert_eq!(verify_oods_channel_raws(&claims, &seed), Ok(()));
    }

    #[test]
    fn verify_rejects_a_single_forged_raw() {
        let ids = [pk(1), pk(2)];
        let seed = oods_epoch_seed(11, b"artifact");
        let mut claims = honest_claims(&ids, &seed);
        // Attacker inflates channel 63's minimum (claims a bigger raw than the
        // identity actually produces) to fake a larger network.
        claims[63].claimed_raw = claims[63].claimed_raw.wrapping_add(1);
        assert_eq!(
            verify_oods_channel_raws(&claims, &seed),
            Err(OodsVerifyError::RawMismatch { channel: 63 })
        );
    }

    #[test]
    fn verify_rejects_a_wrong_seed() {
        // A proof computed under one (grindable) seed must fail against the
        // canonical seed Core recomputes — closes seed-substitution.
        let ids = [pk(9)];
        let honest_seed = oods_epoch_seed(11, b"artifact");
        let claims = honest_claims(&ids, &honest_seed);
        let canonical_seed = oods_epoch_seed(11, b"DIFFERENT-artifact");
        assert!(matches!(
            verify_oods_channel_raws(&claims, &canonical_seed),
            Err(OodsVerifyError::RawMismatch { .. })
        ));
    }

    #[test]
    fn verify_rejects_incomplete_or_duplicated_coverage() {
        let ids = [pk(1)];
        let seed = oods_epoch_seed(1, b"a");
        let full = honest_claims(&ids, &seed);
        // too few channels
        assert_eq!(
            verify_oods_channel_raws(&full[..CHANNELS - 1], &seed),
            Err(OodsVerifyError::ChannelCoverage)
        );
        // right count but a duplicated channel (channel 0 twice, 1 missing)
        let mut dup: Vec<OodsChannelClaim> = honest_claims(&ids, &seed);
        dup[1].channel = 0;
        dup[1].claimed_raw = oods_raw(dup[1].identity, &seed, 0);
        assert_eq!(
            verify_oods_channel_raws(&dup, &seed),
            Err(OodsVerifyError::ChannelCoverage)
        );
    }

    // ── OODS-tardis producer/merger (§6 purpose-1) ──

    #[test]
    fn produce_is_deterministic_and_covers_all_channels() {
        let seed = oods_epoch_seed(9, b"artifact");
        let id = pk(0x11);
        let a = oods_produce(&id, &seed);
        let b = oods_produce(&id, &seed);
        assert_eq!(a, b, "produce is a pure function of (identity, seed)");
        assert_eq!(a.len(), CHANNELS);
        // Each extremum's raw is the canonical draw, and it verifies.
        for (ch, e) in a.iter().enumerate() {
            assert_eq!(e.channel, ch as u32);
            assert_eq!(e.raw, oods_raw(&id, &seed, ch as u32));
        }
        assert!(oods_verify_accumulator(&a, &seed).is_ok());
    }

    #[test]
    fn fold_is_max_semilattice_order_independent_and_idempotent() {
        let seed = oods_epoch_seed(3, b"root");
        let ids = [pk(1), pk(2), pk(3), pk(4)];

        // Global reference = per-channel max over ALL identities.
        let mut reference = oods_produce(&ids[0], &seed);
        for id in &ids[1..] {
            oods_fold(&mut reference, &oods_produce(id, &seed));
        }

        // Fold in a DIFFERENT order → identical accumulator (commutative/assoc).
        let mut other = oods_produce(&ids[3], &seed);
        for id in [&ids[1], &ids[0], &ids[2]] {
            oods_fold(&mut other, &oods_produce(id, &seed));
        }
        assert_eq!(reference, other, "fold is order-independent");

        // Re-folding an already-absorbed contribution changes nothing (idempotent).
        let before = reference.clone();
        oods_fold(&mut reference, &oods_produce(&ids[2], &seed));
        assert_eq!(reference, before, "fold is idempotent");

        // Each channel really holds the max raw across the identity set.
        for ch in 0..CHANNELS as u32 {
            let want = ids
                .iter()
                .map(|id| oods_raw(id, &seed, ch))
                .max()
                .unwrap();
            assert_eq!(reference[ch as usize].raw, want);
        }
        // And the converged accumulator verifies as a proof.
        assert!(oods_verify_accumulator(&reference, &seed).is_ok());
    }

    // Build a converged accumulator over `n` distinct identities (the per-channel
    // max — i.e. what a fully-propagated tick would hold for an n-node view).
    fn converged_acc(n: u64, seed: &[u8]) -> Vec<OodsExtremum> {
        let mut acc = oods_produce(&pk(0), seed);
        for i in 1..n {
            oods_fold(&mut acc, &oods_produce(&pk(i), seed));
        }
        acc
    }

    #[test]
    fn estimate_is_ballpark_and_deterministic() {
        let seed = oods_epoch_seed(5, b"net");
        // A fully-propagated view of 100 identities should read ~100. Ballpark is
        // the bar (Extrema has ~9% inherent error; the fixed-point ln adds <1%),
        // so a loose 2× window proves it isn't wildly off (the <30–40% concern).
        let e100 = oods_estimate(&converged_acc(100, &seed));
        assert!((50..=200).contains(&e100), "estimate(100)={e100} out of ballpark");
        // Deterministic: same accumulator → same integer, every time/validator.
        assert_eq!(e100, oods_estimate(&converged_acc(100, &seed)));
    }

    #[test]
    fn estimate_detects_the_partition_drop() {
        // THE point (adversary splits the net → active count collapses). A small
        // partition reads far below the full network — an order-of-magnitude gap
        // the reference cross-check trivially flags, regardless of fine accuracy.
        let seed = oods_epoch_seed(5, b"net");
        let full = oods_estimate(&converged_acc(200, &seed));
        let split = oods_estimate(&converged_acc(8, &seed));
        assert!(full > split * 5, "partition must show a large drop: full={full} split={split}");
        assert!((2..=32).contains(&split), "split estimate={split} still ballpark");
    }

    #[test]
    fn fold_keeps_the_larger_raw_with_its_identity() {
        let seed = oods_epoch_seed(1, b"x");
        // Find a channel where id_b's raw beats id_a's, and check the identity
        // travels with the winning raw.
        let (id_a, id_b) = (pk(0xAA), pk(0xBB));
        let a = oods_produce(&id_a, &seed);
        let b = oods_produce(&id_b, &seed);
        let mut acc = a.clone();
        oods_fold(&mut acc, &b);
        for ch in 0..CHANNELS {
            let (ra, rb) = (a[ch].raw, b[ch].raw);
            let winner_id: &[u8] = if rb > ra || (rb == ra && id_b[..] > id_a[..]) {
                &id_b
            } else {
                &id_a
            };
            assert_eq!(acc[ch].raw, ra.max(rb));
            assert_eq!(acc[ch].identity, winner_id);
        }
    }
}
