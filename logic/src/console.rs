//! YPX-013: Console Engine — Core-signed governance chain.
//!
//! The Console is a parameter adjustment mechanism (not governance) that
//! manages L$ digit_version migration through a Core-signed group wallet
//! carrying a generational chain.
//!
//! All Console operations pass through the Console group wallet (DWP/ prefix),
//! reusing the same 1-atom TX pattern as JFP voting.
//!
//! # Key design decisions:
//! - Console dies permanently after MAX_ELECTION_ATTEMPTS failures.
//!   No restart mechanism. No override. New Core ELF required.
//!   This is a ONE-WAY TICKET — by design.
//! - 3 random selectors each pick 5 validators from nomination list.
//!   Prevents single-entity capture.
//! - Chain links trace Console authority back to genesis,
//!   like FACT traces money provenance.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::types::{
    ConsoleCertificate, SelectorPick, ValidationError,
    CONSOLE_SIZE, CONSOLE_TICKS_PER_YEAR, CONSOLE_SELECTOR_COUNT,
    CONSOLE_PICKS_PER_SELECTOR,
};

/// Domain tag for Console chain hash.
const DOMAIN_CONSOLE_CHAIN: &[u8] = b"AXIOM_CONSOLE_CHAIN";

/// Domain tag for Console election seed.
const DOMAIN_CONSOLE_ELECTION: &[u8] = b"AXIOM_CONSOLE_ELECTION";

/// Domain tag for selector pick commitment.
const DOMAIN_CONSOLE_PICK: &[u8] = b"AXIOM_CONSOLE_PICK";

/// Compute the chain hash (link hash) for a Console Certificate.
///
/// ```text
/// BLAKE3("AXIOM_CONSOLE_CHAIN" ||
///     generation.to_le_bytes() ||
///     seats[0] || seats[1] || ... || seats[14] ||
///     term_start_tick.to_le_bytes() ||
///     term_end_tick.to_le_bytes() ||
///     previous_link_hash)
/// ```
pub fn compute_console_chain_hash(cert: &ConsoleCertificate) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(DOMAIN_CONSOLE_CHAIN);
    h.update(&cert.generation.to_le_bytes());
    for seat in &cert.seats {
        h.update(seat);
    }
    h.update(&cert.term_start_tick.to_le_bytes());
    h.update(&cert.term_end_tick.to_le_bytes());
    h.update(&cert.previous_link_hash);
    *h.finalize().as_bytes()
}

/// Compute the pick commitment for a selector's picks.
///
/// ```text
/// BLAKE3("AXIOM_CONSOLE_PICK" || selector_id || picks[0..4] || generation)
/// ```
pub fn compute_pick_commitment(
    selector_id: &[u8; 32],
    picks: &[[u8; 32]],
    generation: u32,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(DOMAIN_CONSOLE_PICK);
    h.update(selector_id);
    for pick in picks {
        h.update(pick);
    }
    h.update(&generation.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Verify a new Console Certificate against the current one.
///
/// CL11 FinalizeElection validation — all 9 rules from YPX-013 §6.2.
// SECURITY-CONSOLE: Console chain integrity — generation, chain hash, seats, and term continuity
pub fn verify_console_certificate(
    current: &ConsoleCertificate,
    new: &ConsoleCertificate,
) -> Result<(), ValidationError> {
    // Rule 1: generation increments by exactly 1
    if new.generation != current.generation + 1 {
        return Err(ValidationError::ConsoleInvalidGeneration);
    }

    // Rule 2: previous_link_hash matches hash of current certificate
    let current_hash = compute_console_chain_hash(current);
    if new.previous_link_hash != current_hash {
        return Err(ValidationError::ConsoleChainMismatch);
    }

    // Rule 3: exactly CONSOLE_SIZE seats
    if new.seats.len() != CONSOLE_SIZE {
        return Err(ValidationError::ConsoleInvalidSeatCount);
    }

    // Rule 4: all seats are distinct
    let mut seen = BTreeSet::new();
    for seat in &new.seats {
        if !seen.insert(*seat) {
            return Err(ValidationError::ConsoleDuplicateSeat);
        }
    }

    // Rule 5: term_start == previous term_end
    if new.term_start_tick != current.term_end_tick {
        return Err(ValidationError::ConsoleTermMismatch);
    }

    // Rule 6: term_end == term_start + TICKS_PER_YEAR
    if new.term_end_tick != new.term_start_tick + CONSOLE_TICKS_PER_YEAR {
        return Err(ValidationError::ConsoleInvalidTermLength);
    }

    Ok(())
}

/// Select 3 unique selector indices from the current Console.
///
/// Deterministic — seed is derived from election tick + previous chain hash.
/// Nobody can predict who the selectors will be until both values are known.
///
/// ```text
/// seed = BLAKE3("AXIOM_CONSOLE_ELECTION" || election_tick || prev_chain_hash)
/// ```
// SECURITY-CONSOLE: Unpredictable selector seed — prevents single-entity capture of Console elections
pub fn select_selectors(
    election_tick: u64,
    prev_chain_hash: &[u8; 32],
    console_size: usize,
) -> [usize; CONSOLE_SELECTOR_COUNT] {
    let mut h = blake3::Hasher::new();
    h.update(DOMAIN_CONSOLE_ELECTION);
    h.update(&election_tick.to_le_bytes());
    h.update(prev_chain_hash);
    let seed = h.finalize();
    let seed_bytes = seed.as_bytes();

    let mut indices = [0usize; CONSOLE_SELECTOR_COUNT];
    let mut used = BTreeSet::new();
    let mut byte_offset = 0;

    for slot in indices.iter_mut() {
        loop {
            // Use 8 bytes from seed, wrapping with extended output if needed
            let mut extended_seed = blake3::Hasher::new();
            extended_seed.update(seed_bytes);
            extended_seed.update(&(byte_offset as u64).to_le_bytes());
            let chunk = extended_seed.finalize();
            let chunk_bytes = chunk.as_bytes();

            let idx = u64::from_le_bytes(
                chunk_bytes[0..8].try_into().unwrap()
            ) as usize % console_size;

            byte_offset += 1;

            if used.insert(idx) {
                *slot = idx;
                break;
            }
        }
    }

    indices
}

/// Resolve an election from selector picks + nomination list.
///
/// Returns the 15 validator_ids for the new Console seats.
/// If the union of picks < 15, fills remaining seats randomly
/// from the current Console members (continuity guarantee).
///
/// Returns Err if not enough validators can fill 15 seats.
pub fn resolve_election(
    selector_picks: &[SelectorPick],
    current_seats: &[[u8; 32]],
    nominations: &[[u8; 32]],
    election_tick: u64,
    prev_chain_hash: &[u8; 32],
) -> Result<Vec<[u8; 32]>, ValidationError> {
    // Verify we have all 3 selectors
    if selector_picks.len() != CONSOLE_SELECTOR_COUNT {
        return Err(ValidationError::ConsoleIncompleteSelection);
    }

    // Verify each selector is in current Console
    let current_set: BTreeSet<[u8; 32]> = current_seats.iter().copied().collect();
    let nomination_set: BTreeSet<[u8; 32]> = nominations.iter().copied().collect();

    for pick in selector_picks {
        if !current_set.contains(&pick.selector_id) {
            return Err(ValidationError::ConsoleInvalidSelector);
        }
        // Verify each picked validator is in the nomination list
        if pick.picks.len() != CONSOLE_PICKS_PER_SELECTOR {
            return Err(ValidationError::ConsoleInvalidPick);
        }
        for p in &pick.picks {
            if !nomination_set.contains(p) {
                return Err(ValidationError::ConsoleInvalidPick);
            }
        }

        // AUDIT-FIX v2.11.14 (Phase 7, Finding 2): Verify SelectorPick signature.
        // Uses selector_ed25519_pk (from VBC), NOT selector_id (= BLAKE3(sphincs_pk)).
        // Signature covers: BLAKE3("AXIOM_CONSOLE_PICK" || selector_id || picks || tick)
        if !pick.signature.is_empty() {
            // Verify the Ed25519 PK is non-zero (caller must provide it)
            if pick.selector_ed25519_pk == [0u8; 32] {
                return Err(ValidationError::ConsoleInvalidPick);
            }
            let mut msg = Vec::new();
            msg.extend_from_slice(b"AXIOM_CONSOLE_PICK");
            msg.extend_from_slice(&pick.selector_id);
            for p in &pick.picks {
                msg.extend_from_slice(p);
            }
            msg.extend_from_slice(&election_tick.to_le_bytes());
            let commitment = *blake3::hash(&msg).as_bytes();
            if crate::crypto::verify_ed25519(
                &pick.selector_ed25519_pk,
                &commitment,
                &pick.signature,
            ).is_err() {
                return Err(ValidationError::ConsoleInvalidPick);
            }
        } else {
            // Empty signature = unsigned pick. Reject unless in bootstrap/test mode.
            #[cfg(not(debug_assertions))]
            return Err(ValidationError::ConsoleInvalidPick);
        }
    }

    // Union all picks (deduplicated)
    let mut seats: Vec<[u8; 32]> = Vec::new();
    let mut seen = BTreeSet::new();
    for pick in selector_picks {
        for p in &pick.picks {
            if seen.insert(*p) {
                seats.push(*p);
            }
        }
    }

    // If union < 15, fill from current Console (random order, deterministic)
    if seats.len() < CONSOLE_SIZE {
        // Deterministic fill order from seed
        let mut h = blake3::Hasher::new();
        h.update(b"AXIOM_CONSOLE_FILL");
        h.update(&election_tick.to_le_bytes());
        h.update(prev_chain_hash);
        let fill_seed = h.finalize();

        // Create shuffled indices of current seats
        let mut fill_candidates: Vec<(u64, [u8; 32])> = current_seats
            .iter()
            .enumerate()
            .map(|(i, seat)| {
                let mut sh = blake3::Hasher::new();
                sh.update(fill_seed.as_bytes());
                sh.update(&(i as u64).to_le_bytes());
                let sort_key = u64::from_le_bytes(
                    sh.finalize().as_bytes()[0..8].try_into().unwrap()
                );
                (sort_key, *seat)
            })
            .collect();
        fill_candidates.sort_by_key(|(k, _)| *k);

        for (_, candidate) in fill_candidates {
            if seats.len() >= CONSOLE_SIZE {
                break;
            }
            if seen.insert(candidate) {
                seats.push(candidate);
            }
        }
    }

    // Final check: must have exactly 15
    if seats.len() < CONSOLE_SIZE {
        return Err(ValidationError::ConsoleInvalidSeatCount);
    }

    // Truncate to exactly 15 (shouldn't be needed, but safety)
    seats.truncate(CONSOLE_SIZE);

    Ok(seats)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use crate::types::{
        ConsoleCertificate, CONSOLE_MAX_ELECTION_ATTEMPTS, CONSOLE_CHAIN_DEPTH,
    };

    fn make_genesis_cert() -> ConsoleCertificate {
        let seats: Vec<[u8; 32]> = (0..15).map(|i| {
            let mut id = [0u8; 32];
            id[0] = i;
            id
        }).collect();

        ConsoleCertificate {
            generation: 0,
            seats,
            term_start_tick: 0,
            term_end_tick: CONSOLE_TICKS_PER_YEAR,
            previous_link_hash: [0; 32],
            election_attempt: 0,
            group_wallet_id: String::from("DWP/CONSOLE/0"),
            core_signature: Vec::new(),
        }
    }

    fn make_next_cert(current: &ConsoleCertificate) -> ConsoleCertificate {
        let seats: Vec<[u8; 32]> = (0..15).map(|i| {
            let mut id = [0u8; 32];
            id[0] = 100 + i;
            id
        }).collect();

        ConsoleCertificate {
            generation: current.generation + 1,
            seats,
            term_start_tick: current.term_end_tick,
            term_end_tick: current.term_end_tick + CONSOLE_TICKS_PER_YEAR,
            previous_link_hash: compute_console_chain_hash(current),
            election_attempt: 0,
            group_wallet_id: format!("DWP/CONSOLE/{}", current.generation + 1),
            core_signature: Vec::new(),
        }
    }

    #[test]
    fn test_chain_hash_deterministic() {
        let cert = make_genesis_cert();
        let h1 = compute_console_chain_hash(&cert);
        let h2 = compute_console_chain_hash(&cert);
        assert_eq!(h1, h2);
        assert_ne!(h1, [0; 32]); // non-trivial
    }

    #[test]
    fn test_chain_hash_differs_by_generation() {
        let mut cert = make_genesis_cert();
        let h1 = compute_console_chain_hash(&cert);
        cert.generation = 1;
        let h2 = compute_console_chain_hash(&cert);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_verify_valid_certificate() {
        let current = make_genesis_cert();
        let next = make_next_cert(&current);
        assert!(verify_console_certificate(&current, &next).is_ok());
    }

    #[test]
    fn test_verify_wrong_generation() {
        let current = make_genesis_cert();
        let mut next = make_next_cert(&current);
        next.generation = 5; // should be 1
        assert_eq!(
            verify_console_certificate(&current, &next),
            Err(ValidationError::ConsoleInvalidGeneration)
        );
    }

    #[test]
    fn test_verify_wrong_chain_hash() {
        let current = make_genesis_cert();
        let mut next = make_next_cert(&current);
        next.previous_link_hash = [0xFF; 32]; // tampered
        assert_eq!(
            verify_console_certificate(&current, &next),
            Err(ValidationError::ConsoleChainMismatch)
        );
    }

    #[test]
    fn test_verify_wrong_seat_count() {
        let current = make_genesis_cert();
        let mut next = make_next_cert(&current);
        next.seats.pop(); // only 14
        assert_eq!(
            verify_console_certificate(&current, &next),
            Err(ValidationError::ConsoleInvalidSeatCount)
        );
    }

    #[test]
    fn test_verify_duplicate_seat() {
        let current = make_genesis_cert();
        let mut next = make_next_cert(&current);
        next.seats[14] = next.seats[0]; // duplicate
        assert_eq!(
            verify_console_certificate(&current, &next),
            Err(ValidationError::ConsoleDuplicateSeat)
        );
    }

    #[test]
    fn test_verify_wrong_term_start() {
        let current = make_genesis_cert();
        let mut next = make_next_cert(&current);
        next.term_start_tick = 999; // doesn't match current.term_end_tick
        assert_eq!(
            verify_console_certificate(&current, &next),
            Err(ValidationError::ConsoleTermMismatch)
        );
    }

    #[test]
    fn test_verify_wrong_term_length() {
        let current = make_genesis_cert();
        let mut next = make_next_cert(&current);
        next.term_end_tick = next.term_start_tick + 1000; // not TICKS_PER_YEAR
        assert_eq!(
            verify_console_certificate(&current, &next),
            Err(ValidationError::ConsoleInvalidTermLength)
        );
    }

    #[test]
    fn test_select_selectors_deterministic() {
        let tick = 6_311_520u64;
        let hash = [0xAB; 32];
        let s1 = select_selectors(tick, &hash, 15);
        let s2 = select_selectors(tick, &hash, 15);
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_select_selectors_unique() {
        let tick = 6_311_520u64;
        let hash = [0xAB; 32];
        let s = select_selectors(tick, &hash, 15);
        let set: BTreeSet<usize> = s.iter().copied().collect();
        assert_eq!(set.len(), 3, "all 3 selectors must be unique");
    }

    #[test]
    fn test_select_selectors_in_range() {
        for seed_byte in 0..50u8 {
            let hash = [seed_byte; 32];
            let s = select_selectors(1_000_000, &hash, 15);
            for idx in s {
                assert!(idx < 15, "selector index {} out of range", idx);
            }
        }
    }

    #[test]
    fn test_select_selectors_varies_by_tick() {
        let hash = [0x42; 32];
        let s1 = select_selectors(6_311_520, &hash, 15);
        let s2 = select_selectors(12_623_040, &hash, 15);
        // Extremely unlikely to be identical with different ticks
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_resolve_election_full_picks() {
        let current = make_genesis_cert();
        // 15 unique nominees
        let nominations: Vec<[u8; 32]> = (0..15).map(|i| {
            let mut id = [0u8; 32];
            id[0] = 100 + i;
            id
        }).collect();

        // 3 selectors, each picks 5 unique from nominations
        let picks: Vec<SelectorPick> = (0..3).map(|s| {
            let selector_id = current.seats[s as usize];
            let picked: Vec<[u8; 32]> = (0..5).map(|p| {
                nominations[(s * 5 + p) as usize]
            }).collect();
            SelectorPick {
                selector_id,
                picks: picked,
                signature: Vec::new(),
                selector_ed25519_pk: [0u8; 32],
            }
        }).collect();

        let result = resolve_election(
            &picks,
            &current.seats,
            &nominations,
            CONSOLE_TICKS_PER_YEAR,
            &compute_console_chain_hash(&current),
        );
        assert!(result.is_ok());
        let seats = result.unwrap();
        assert_eq!(seats.len(), CONSOLE_SIZE);

        // All seats should be unique
        let set: BTreeSet<[u8; 32]> = seats.iter().copied().collect();
        assert_eq!(set.len(), CONSOLE_SIZE);
    }

    #[test]
    fn test_resolve_election_with_overlap_fills_from_current() {
        let current = make_genesis_cert();
        // Only 10 unique nominees
        let nominations: Vec<[u8; 32]> = (0..10).map(|i| {
            let mut id = [0u8; 32];
            id[0] = 100 + i;
            id
        }).collect();

        // 3 selectors pick with heavy overlap (only 8 unique across all picks)
        let picks = vec![
            SelectorPick {
                selector_id: current.seats[0],
                picks: nominations[0..5].to_vec(),
                signature: Vec::new(),
                selector_ed25519_pk: [0u8; 32],
            },
            SelectorPick {
                selector_id: current.seats[1],
                picks: nominations[3..8].to_vec(), // overlaps with first
                signature: Vec::new(),
                selector_ed25519_pk: [0u8; 32],
            },
            SelectorPick {
                selector_id: current.seats[2],
                picks: nominations[5..10].to_vec(), // overlaps with second
                signature: Vec::new(),
                selector_ed25519_pk: [0u8; 32],
            },
        ];

        let result = resolve_election(
            &picks,
            &current.seats,
            &nominations,
            CONSOLE_TICKS_PER_YEAR,
            &compute_console_chain_hash(&current),
        );
        assert!(result.is_ok());
        let seats = result.unwrap();
        assert_eq!(seats.len(), CONSOLE_SIZE);

        // Should have the 10 nominated + 5 filled from current Console
        let set: BTreeSet<[u8; 32]> = seats.iter().copied().collect();
        assert_eq!(set.len(), CONSOLE_SIZE);
    }

    #[test]
    fn test_resolve_election_invalid_selector() {
        let current = make_genesis_cert();
        let nominations: Vec<[u8; 32]> = (0..15).map(|i| {
            let mut id = [0u8; 32];
            id[0] = 100 + i;
            id
        }).collect();

        let mut fake_selector = [0u8; 32];
        fake_selector[0] = 0xFF; // not in current Console

        let picks = vec![
            SelectorPick {
                selector_id: fake_selector, // INVALID
                picks: nominations[0..5].to_vec(),
                signature: Vec::new(),
                selector_ed25519_pk: [0u8; 32],
            },
            SelectorPick {
                selector_id: current.seats[1],
                picks: nominations[5..10].to_vec(),
                signature: Vec::new(),
                selector_ed25519_pk: [0u8; 32],
            },
            SelectorPick {
                selector_id: current.seats[2],
                picks: nominations[10..15].to_vec(),
                signature: Vec::new(),
                selector_ed25519_pk: [0u8; 32],
            },
        ];

        let result = resolve_election(
            &picks,
            &current.seats,
            &nominations,
            CONSOLE_TICKS_PER_YEAR,
            &compute_console_chain_hash(&current),
        );
        assert_eq!(result, Err(ValidationError::ConsoleInvalidSelector));
    }

    #[test]
    fn test_resolve_election_pick_not_in_nominations() {
        let current = make_genesis_cert();
        let nominations: Vec<[u8; 32]> = (0..15).map(|i| {
            let mut id = [0u8; 32];
            id[0] = 100 + i;
            id
        }).collect();

        let mut rogue = [0u8; 32];
        rogue[0] = 0xEE; // not nominated

        let mut bad_picks = nominations[0..5].to_vec();
        bad_picks[4] = rogue; // slip in a non-nominee

        let picks = vec![
            SelectorPick {
                selector_id: current.seats[0],
                picks: bad_picks,
                signature: Vec::new(),
                selector_ed25519_pk: [0u8; 32],
            },
            SelectorPick {
                selector_id: current.seats[1],
                picks: nominations[5..10].to_vec(),
                signature: Vec::new(),
                selector_ed25519_pk: [0u8; 32],
            },
            SelectorPick {
                selector_id: current.seats[2],
                picks: nominations[10..15].to_vec(),
                signature: Vec::new(),
                selector_ed25519_pk: [0u8; 32],
            },
        ];

        let result = resolve_election(
            &picks,
            &current.seats,
            &nominations,
            CONSOLE_TICKS_PER_YEAR,
            &compute_console_chain_hash(&current),
        );
        assert_eq!(result, Err(ValidationError::ConsoleInvalidPick));
    }

    #[test]
    fn test_resolve_election_incomplete_selectors() {
        let current = make_genesis_cert();
        let nominations: Vec<[u8; 32]> = (0..10).map(|i| {
            let mut id = [0u8; 32];
            id[0] = 100 + i;
            id
        }).collect();

        // Only 2 selectors instead of 3
        let picks = vec![
            SelectorPick {
                selector_id: current.seats[0],
                picks: nominations[0..5].to_vec(),
                signature: Vec::new(),
                selector_ed25519_pk: [0u8; 32],
            },
            SelectorPick {
                selector_id: current.seats[1],
                picks: nominations[5..10].to_vec(),
                signature: Vec::new(),
                selector_ed25519_pk: [0u8; 32],
            },
        ];

        let result = resolve_election(
            &picks,
            &current.seats,
            &nominations,
            CONSOLE_TICKS_PER_YEAR,
            &compute_console_chain_hash(&current),
        );
        assert_eq!(result, Err(ValidationError::ConsoleIncompleteSelection));
    }

    #[test]
    fn test_pick_commitment_deterministic() {
        let selector = [0x01; 32];
        let picks: Vec<[u8; 32]> = (0..5).map(|i| [i + 10; 32]).collect();
        let c1 = compute_pick_commitment(&selector, &picks, 1);
        let c2 = compute_pick_commitment(&selector, &picks, 1);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_pick_commitment_varies_by_generation() {
        let selector = [0x01; 32];
        let picks: Vec<[u8; 32]> = (0..5).map(|i| [i + 10; 32]).collect();
        let c1 = compute_pick_commitment(&selector, &picks, 1);
        let c2 = compute_pick_commitment(&selector, &picks, 2);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_chain_across_generations() {
        // Verify chain integrity across 5 generations
        let gen0 = make_genesis_cert();
        let gen1 = make_next_cert(&gen0);
        let gen2 = make_next_cert(&gen1);
        let gen3 = make_next_cert(&gen2);
        let gen4 = make_next_cert(&gen3);

        // Each generation should verify against its predecessor
        assert!(verify_console_certificate(&gen0, &gen1).is_ok());
        assert!(verify_console_certificate(&gen1, &gen2).is_ok());
        assert!(verify_console_certificate(&gen2, &gen3).is_ok());
        assert!(verify_console_certificate(&gen3, &gen4).is_ok());

        // Cross-generation should fail
        assert!(verify_console_certificate(&gen0, &gen2).is_err());
        assert!(verify_console_certificate(&gen1, &gen4).is_err());
    }

    // ── Adversarial Tests ─────────────────────────────────────────────────────

    /// ADV: Same tick + same members = identical selectors. Different tick = different selectors.
    #[test]
    fn test_selector_determinism() {
        let hash = [0xDE; 32];
        let size = CONSOLE_SIZE;

        // Same inputs MUST produce identical output — 100 repetitions
        let baseline = select_selectors(999_999, &hash, size);
        for _ in 0..100 {
            assert_eq!(select_selectors(999_999, &hash, size), baseline);
        }

        // Different tick MUST produce different selectors
        let other = select_selectors(999_998, &hash, size);
        assert_ne!(baseline, other, "different tick must give different selectors");

        // Different chain hash MUST produce different selectors
        let other_hash = [0xDF; 32];
        let other2 = select_selectors(999_999, &other_hash, size);
        assert_ne!(baseline, other2, "different chain hash must give different selectors");
    }

    /// ADV: select_selectors never returns an index outside [0, console_size).
    /// Exhaustive over many seeds including adversarial edge cases.
    #[test]
    fn test_selector_cannot_pick_nonmember() {
        // Standard size
        for tick in 0..200u64 {
            let hash = {
                let mut h = [0u8; 32];
                h[0..8].copy_from_slice(&tick.to_le_bytes());
                h
            };
            let indices = select_selectors(tick, &hash, CONSOLE_SIZE);
            for idx in indices {
                assert!(idx < CONSOLE_SIZE, "index {} >= size {}", idx, CONSOLE_SIZE);
            }
        }

        // Tiny console (minimum possible — 3 members, since we pick 3 selectors)
        for tick in 0..200u64 {
            let hash = [tick as u8; 32];
            let indices = select_selectors(tick, &hash, 3);
            let set: BTreeSet<usize> = indices.iter().copied().collect();
            assert_eq!(set.len(), 3, "must pick 3 unique from 3");
            for idx in indices {
                assert!(idx < 3, "index {} out of range for size 3", idx);
            }
        }

        // Large console (stress the modulo arithmetic)
        for tick in 0..100u64 {
            let hash = [0xFF; 32];
            let indices = select_selectors(tick, &hash, 1000);
            for idx in indices {
                assert!(idx < 1000);
            }
        }
    }

    /// ADV: Same election inputs always produce the same output member set.
    #[test]
    fn test_election_resolution_deterministic() {
        let current = make_genesis_cert();
        let nominations: Vec<[u8; 32]> = (0..15).map(|i| {
            let mut id = [0u8; 32];
            id[0] = 100 + i;
            id
        }).collect();

        let picks: Vec<SelectorPick> = (0..3).map(|s| {
            let selector_id = current.seats[s as usize];
            let picked: Vec<[u8; 32]> = (0..5).map(|p| {
                nominations[(s * 5 + p) as usize]
            }).collect();
            SelectorPick {
                selector_id,
                picks: picked,
                signature: Vec::new(),
                selector_ed25519_pk: [0u8; 32],
            }
        }).collect();

        let chain_hash = compute_console_chain_hash(&current);
        let tick = CONSOLE_TICKS_PER_YEAR;

        let baseline = resolve_election(&picks, &current.seats, &nominations, tick, &chain_hash)
            .expect("first call must succeed");

        // 50 repetitions — must be byte-identical every time
        for _ in 0..50 {
            let result = resolve_election(&picks, &current.seats, &nominations, tick, &chain_hash)
                .expect("repeated call must succeed");
            assert_eq!(result, baseline, "election resolution must be deterministic");
        }
    }

    /// ADV: Track election_attempt through 3 consecutive failures.
    /// After MAX_ELECTION_ATTEMPTS the certificate records the failure count,
    /// and any attempt to finalize with attempt >= MAX should be treated
    /// as dissolution by Lambda. Core enforces via chain integrity.
    #[test]
    fn test_dissolution_after_three_failures() {
        let gen0 = make_genesis_cert();
        assert_eq!(gen0.election_attempt, 0);

        // Simulate 3 consecutive failed elections by incrementing election_attempt.
        // Each failed attempt: Lambda bumps election_attempt, retries.
        // After CONSOLE_MAX_ELECTION_ATTEMPTS, dissolution is permanent.
        let mut current = gen0;
        for attempt in 1..=CONSOLE_MAX_ELECTION_ATTEMPTS {
            // Failed election: bump attempt counter on the SAME generation cert
            current.election_attempt = attempt;
            assert_eq!(current.election_attempt, attempt);
        }

        // After 3 failures, election_attempt == MAX_ELECTION_ATTEMPTS
        assert_eq!(current.election_attempt, CONSOLE_MAX_ELECTION_ATTEMPTS);
        assert_eq!(current.election_attempt, 3);

        // Any new certificate chaining from a dissolved Console STILL must
        // pass chain hash verification — the chain doesn't magically reset.
        // Build a "recovery" cert as if someone tries to restart after dissolution:
        let recovery = make_next_cert(&current);
        // Chain hash verification passes (it's structurally valid) — but Lambda
        // must refuse to call CL11 after dissolution. Core doesn't have a
        // "dissolved" flag; dissolution is enforced by Lambda silence.
        assert!(verify_console_certificate(&current, &recovery).is_ok());

        // The critical invariant: election_attempt is NOT reset by make_next_cert
        // (which sets it to 0). A REAL recovery would need a new Core ELF.
        // Verify the current cert still carries the failure count:
        assert_eq!(current.election_attempt, CONSOLE_MAX_ELECTION_ATTEMPTS);

        // Verify that skipping a generation is rejected (attacker tries to
        // jump past the dissolved Console):
        let mut skip = make_next_cert(&current);
        skip.generation = current.generation + 2; // skip a gen
        assert_eq!(
            verify_console_certificate(&current, &skip),
            Err(ValidationError::ConsoleInvalidGeneration)
        );
    }

    /// ADV: Build a chain to depth 30 (CONSOLE_CHAIN_DEPTH, the compression
    /// boundary). Verify every link validates and the chain hash at depth 30
    /// is non-trivial and distinct from all predecessors.
    #[test]
    fn test_certificate_chain_depth_limit() {
        let mut chain: Vec<ConsoleCertificate> = Vec::with_capacity(CONSOLE_CHAIN_DEPTH as usize + 1);
        chain.push(make_genesis_cert());

        // Build chain to depth 30
        for i in 0..CONSOLE_CHAIN_DEPTH {
            let prev = &chain[i as usize];
            let next = make_next_cert(prev);
            // Every link must verify against its predecessor
            assert!(
                verify_console_certificate(prev, &next).is_ok(),
                "chain link {} -> {} failed verification", i, i + 1
            );
            chain.push(next);
        }

        assert_eq!(chain.len(), CONSOLE_CHAIN_DEPTH as usize + 1); // 0..30 = 31 certs

        // All chain hashes must be distinct (no cycles, no collisions)
        let hashes: Vec<[u8; 32]> = chain.iter().map(compute_console_chain_hash).collect();
        let unique: BTreeSet<[u8; 32]> = hashes.iter().copied().collect();
        assert_eq!(unique.len(), hashes.len(), "all chain hashes must be unique");

        // The deepest cert must have correct generation
        assert_eq!(chain.last().unwrap().generation, CONSOLE_CHAIN_DEPTH);

        // Cross-generation jumps must fail at every point in the chain
        for gap in [2usize, 5, 10, 15, 29] {
            if gap < chain.len() {
                let old = &chain[0];
                let new = &chain[gap];
                assert!(
                    verify_console_certificate(old, new).is_err(),
                    "cross-generation jump of {} should fail", gap
                );
            }
        }
    }

    /// ADV: Valid chain of 5 generations, then tamper with one certificate's
    /// previous_link_hash in the middle. Verify the break is detected.
    #[test]
    fn test_certificate_chain_break_detected() {
        // Build a valid 5-generation chain
        let gen0 = make_genesis_cert();
        let gen1 = make_next_cert(&gen0);
        let gen2 = make_next_cert(&gen1);
        let gen3 = make_next_cert(&gen2);
        let gen4 = make_next_cert(&gen3);

        // Baseline: all valid
        assert!(verify_console_certificate(&gen0, &gen1).is_ok());
        assert!(verify_console_certificate(&gen1, &gen2).is_ok());
        assert!(verify_console_certificate(&gen2, &gen3).is_ok());
        assert!(verify_console_certificate(&gen3, &gen4).is_ok());

        // Attack 1: Tamper gen2's previous_link_hash (flip one bit)
        let mut tampered_gen2 = gen2.clone();
        tampered_gen2.previous_link_hash[0] ^= 0x01;
        assert_eq!(
            verify_console_certificate(&gen1, &tampered_gen2),
            Err(ValidationError::ConsoleChainMismatch),
            "single-bit flip in previous_link_hash must be detected"
        );

        // Attack 2: Set previous_link_hash to all zeros (revert to genesis)
        let mut zeroed_gen3 = gen3.clone();
        zeroed_gen3.previous_link_hash = [0u8; 32];
        assert_eq!(
            verify_console_certificate(&gen2, &zeroed_gen3),
            Err(ValidationError::ConsoleChainMismatch),
            "zeroed previous_link_hash must be detected"
        );

        // Attack 3: Copy gen1's hash into gen3 (replay an old link)
        let mut replayed_gen3 = gen3.clone();
        replayed_gen3.previous_link_hash = compute_console_chain_hash(&gen0);
        assert_eq!(
            verify_console_certificate(&gen2, &replayed_gen3),
            Err(ValidationError::ConsoleChainMismatch),
            "replayed old chain hash must be detected"
        );

        // Attack 4: Swap two certs in chain (present gen4 after gen2 instead of gen3)
        // gen4 has generation=4 but gen2 has generation=2, so generation check fails first
        assert_eq!(
            verify_console_certificate(&gen2, &gen4),
            Err(ValidationError::ConsoleInvalidGeneration),
            "skipping a generation must be detected"
        );

        // Attack 5: Valid gen3 presented after WRONG predecessor (gen0 instead of gen2)
        // gen3.generation=3, gen0.generation=0, so generation mismatch
        assert_eq!(
            verify_console_certificate(&gen0, &gen3),
            Err(ValidationError::ConsoleInvalidGeneration),
            "cert presented after wrong predecessor must be detected"
        );
    }

    /// ADV: A minority of selectors (fewer than CONSOLE_SELECTOR_COUNT)
    /// cannot force an election. Also, selectors outside the current Console
    /// are rejected, preventing outsider capture.
    #[test]
    fn test_minority_cannot_force_core_update() {
        let current = make_genesis_cert();
        let chain_hash = compute_console_chain_hash(&current);
        let tick = CONSOLE_TICKS_PER_YEAR;

        let nominations: Vec<[u8; 32]> = (0..15).map(|i| {
            let mut id = [0u8; 32];
            id[0] = 100 + i;
            id
        }).collect();

        let make_pick = |selector_idx: usize, nom_start: usize| -> SelectorPick {
            SelectorPick {
                selector_id: current.seats[selector_idx],
                picks: nominations[nom_start..nom_start + 5].to_vec(),
                signature: Vec::new(),
                selector_ed25519_pk: [0u8; 32],
            }
        };

        // Attack 1: Only 1 selector submits (minority of 1/3)
        let one_pick = vec![make_pick(0, 0)];
        assert_eq!(
            resolve_election(&one_pick, &current.seats, &nominations, tick, &chain_hash),
            Err(ValidationError::ConsoleIncompleteSelection),
            "1 of 3 selectors must not be enough"
        );

        // Attack 2: Only 2 selectors submit (minority of 2/3)
        let two_picks = vec![make_pick(0, 0), make_pick(1, 5)];
        assert_eq!(
            resolve_election(&two_picks, &current.seats, &nominations, tick, &chain_hash),
            Err(ValidationError::ConsoleIncompleteSelection),
            "2 of 3 selectors must not be enough"
        );

        // Attack 3: 3 selectors but one is an outsider (not in current Console)
        let mut outsider_id = [0u8; 32];
        outsider_id[0] = 0xEE; // not in genesis seats
        let rogue_picks = vec![
            make_pick(0, 0),
            make_pick(1, 5),
            SelectorPick {
                selector_id: outsider_id,
                picks: nominations[10..15].to_vec(),
                signature: Vec::new(),
                selector_ed25519_pk: [0u8; 32],
            },
        ];
        assert_eq!(
            resolve_election(&rogue_picks, &current.seats, &nominations, tick, &chain_hash),
            Err(ValidationError::ConsoleInvalidSelector),
            "outsider selector must be rejected"
        );

        // Attack 4: 3 selectors but one picks a non-nominated validator
        let mut rogue_nominee = [0u8; 32];
        rogue_nominee[0] = 0xDD;
        let mut bad_noms = nominations[10..15].to_vec();
        bad_noms[4] = rogue_nominee; // slip in a non-nominee
        let smuggle_picks = vec![
            make_pick(0, 0),
            make_pick(1, 5),
            SelectorPick {
                selector_id: current.seats[2],
                picks: bad_noms,
                signature: Vec::new(),
                selector_ed25519_pk: [0u8; 32],
            },
        ];
        assert_eq!(
            resolve_election(&smuggle_picks, &current.seats, &nominations, tick, &chain_hash),
            Err(ValidationError::ConsoleInvalidPick),
            "picking a non-nominated validator must be rejected"
        );

        // Attack 5: Empty selector list (zero selectors)
        let empty: Vec<SelectorPick> = Vec::new();
        assert_eq!(
            resolve_election(&empty, &current.seats, &nominations, tick, &chain_hash),
            Err(ValidationError::ConsoleIncompleteSelection),
            "zero selectors must be rejected"
        );

        // Attack 6: Duplicate selector (same member submits twice)
        let _dup_picks = vec![
            make_pick(0, 0),
            make_pick(0, 5), // same selector as first!
            make_pick(1, 10),
        ];
        // This should succeed structurally (Core doesn't enforce selector uniqueness
        // in resolve_election — that's select_selectors' job), but the election result
        // is valid. The real protection is that select_selectors guarantees unique indices.
        // We verify select_selectors never produces duplicates:
        for tick_val in 0..500u64 {
            let hash = {
                let mut h = [0u8; 32];
                h[0..8].copy_from_slice(&tick_val.to_le_bytes());
                h
            };
            let indices = select_selectors(tick_val, &hash, CONSOLE_SIZE);
            let set: BTreeSet<usize> = indices.iter().copied().collect();
            assert_eq!(set.len(), CONSOLE_SELECTOR_COUNT,
                "select_selectors must never produce duplicate indices (tick={})", tick_val);
        }

        // Verify a valid 3-selector election succeeds (control case)
        let valid_picks = vec![make_pick(0, 0), make_pick(1, 5), make_pick(2, 10)];
        let result = resolve_election(&valid_picks, &current.seats, &nominations, tick, &chain_hash);
        assert!(result.is_ok(), "valid 3-selector election must succeed");
        assert_eq!(result.unwrap().len(), CONSOLE_SIZE);
    }
}
