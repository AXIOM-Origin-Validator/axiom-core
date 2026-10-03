//! Genesis state handling
//!
//! Genesis wallets are the initial state before any funding.
//! Each genesis wallet has:
//! - wallet_seq = 0
//! - balance = 0 (no funds until first funded TX)
//! - A unique genesis_state_id = H("AXIOM_GENESIS" || pk || balance || k || proof_type)
//!
//! TIER-AWARE (2026-07-17, single-keypair convergence — YPX-010 §10.5): the
//! `(k, proof_type)` bytes make the k=3/4/5 and k=0 (Ark) tier addresses of ONE
//! keypair have DISTINCT genesis states. Tier-distinctness then propagates
//! through the whole state chain automatically, because every
//! `compute_produced_state_id` folds in `consumed_state_id`, which traces back
//! to this genesis — and `validate_transaction`'s `consumed_state_id ==
//! prev_receipt.produced_state_id` chain check (validation.rs, "Core independent
//! double-spend check") then rejects any cross-tier receipt. So `state_hash`
//! does NOT need the tier — the chain check already discriminates. Proven by
//! `genesis_tier_distinct_and_propagates` below.
//!
//! INVARIANTS (hardcoded in Core):
//! - seq=0: Genesis state. balance=0. No prev_receipts.
//! - seq=1: First funding TX. balance 0→X. No prev_receipts required
//!   (balance was 0, nothing to double-spend). No overlap check.
//!   Validators still witness the funding → receipt for seq=2.
//! - seq=2+: Normal TX. MUST have prev_receipts with 3 witnesses.
//!   Overlap check required.

use crate::crypto::sha3_256_hash;
use crate::types::GenesisWallet;
use alloc::vec::Vec;

/// Compute the genesis_state_id for a wallet
///
/// genesis_state_id = SHA3-256("AXIOM_GENESIS" || public_key || balance || k || proof_type)
///
/// This unique ID is consumed by the wallet's first transaction,
/// providing the same double-spend protection as regular state IDs.
///
/// `(k, proof_type)` are the wallet's YPX-007 tier (see
/// `wallet_id.rs::WALLET_ID_PARAMS`). They make one keypair's tier addresses —
/// e.g. its k=3 Standard and its k=0 Ark — have distinct genesis states, so
/// the two tiers' state chains never collide (module docs).
pub fn compute_genesis_state_id(
    public_key: &[u8; 32],
    balance: u64,
    k: u8,
    proof_type: u8,
) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(b"AXIOM_GENESIS");
    data.extend_from_slice(public_key);
    data.extend_from_slice(&balance.to_le_bytes());
    // Tier bytes (append-last edit convention; k then proof_type, matching
    // wallet_id.rs::compute_checksum's ordering). Pre-mainnet formula change →
    // clean --data this rotation.
    data.push(k);
    data.push(proof_type);
    sha3_256_hash(&data)
}

/// Create a genesis wallet (seq=0, balance=0) for a given tier.
pub fn create_genesis_wallet(
    public_key: [u8; 32],
    balance: u64,
    k: u8,
    proof_type: u8,
) -> GenesisWallet {
    let genesis_state_id = compute_genesis_state_id(&public_key, balance, k, proof_type);
    GenesisWallet {
        public_key,
        balance,
        genesis_state_id,
        wallet_seq: 0, // Always 0 for genesis — first funded TX will be seq=1
    }
}

// ── Hand-written §6c / naming items (NOT ceremony-generated). They sit ABOVE the
// AUTO-GENERATED marker on purpose: the genesis-ceremony tool replaces everything
// from the marker down, and the 2026-09-11 G1 rehearsal proved it wiped these six
// items and left Core uncompilable (handoff §18.9). Keep every hand-written item
// above the marker.

/// §6c — the ceremony-minted opening balance of a GENESIS STAKE WALLET, in
/// atoms: `GENESIS_VALIDATOR_GRANT_ATOMS` (1,000,000 AXC) iff `pk` IS one of
/// `GENESIS_STAKE_WALLET_PKS` — the compile-time list of the ten genesis stake
/// wallet Ed25519 keys, byte-exact; `0` for every other key.
///
/// ⚠ NEVER key this on the wallet-id STRING via `verify_pk_binding`. A wallet
/// id carries a ONE-BYTE `pk_bind` (`compute_pk_bind` → `hash[0..1]`) — a typo
/// guard, not an identity — so a random key matches a listed id about once in
/// 37 and a grinder finds one in seconds. The first draft of this function did
/// exactly that and the adversarial corpus caught it (a stranger's dust send
/// refused `GenesisStakeLocked`, 2026-09-08). Same discipline as
/// `is_genesis_validator`: compare KEYS.
///
/// ONE builder for every layer's view of a genesis opening state (Pattern 1):
/// the SDK bakes it at create, Lambda derives it on an S-ABR miss, Nabla
/// derives the head it stamps against (§6b.4 checks 1-2), and the genesis
/// lock's pk layer keys on it. The value is a function of compile-time
/// constants, so no layer trusts another for it. GenesisDistribution §2.3a:
/// "not transferred to the wallet — it IS the wallet's first state".
pub fn genesis_opening_balance(pk: &[u8]) -> u64 {
    if pk.len() != 32 {
        return 0;
    }
    let pk_array: [u8; 32] = match pk.try_into() { Ok(a) => a, Err(_) => return 0 };
    if pk_array == [0u8; 32] {
        return 0;
    }
    let bonded = crate::validation::protocol_gen::GENESIS_STAKE_WALLET_PKS
        .iter()
        .any(|k| k == &pk_array);
    if bonded { crate::types::GENESIS_VALIDATOR_GRANT_ATOMS } else { 0 }
}

/// §6c — the opening `state_id` of ANY wallet: the genesis formula over the
/// balance `genesis_opening_balance` assigns to its key (0 for every wallet
/// that is not a genesis stake wallet). Every layer that must recognise a
/// wallet's first state derives it from here.
pub fn opening_state_id_for(pk: &[u8; 32], k: u8, proof_type: u8) -> [u8; 32] {
    // YP §16.14.12 v2.19.0 — the fold takes the STATE CLASS, not the raw tier:
    // every online address of a key opens at the same state (KI#149).
    let (k_class, pt_class) = crate::wallet_id::state_class(k, proof_type);
    compute_genesis_state_id(pk, genesis_opening_balance(pk), k_class, pt_class)
}

/// ValidatorJoin §6b.13 / §6c — the `stake_floor_until` a GENESIS stake
/// wallet's DERIVED registration head carries: the presented certificate's own
/// `expires_at`, so Nabla's stamp check 5 (`floor >= expires_at`) holds
/// uniformly and nothing is special-cased. The genesis stake lock (3 years) is
/// stronger than the floor. ONE owner (RULE 1): Nabla derives the head with it
/// and the SDK declares it, so the two cannot drift.
pub fn derived_head_stake_floor_until(vbc: &crate::types::VBC) -> u64 {
    vbc.expires_at
}

/// The full Greek alphabet — the RESERVED validator-name namespace (24 names).
/// The first `GENESIS_VALIDATORS.len()` (10: alpha..kappa) are ASSIGNED to the
/// genesis validators, index-matched to `GENESIS_VALIDATORS` (order = the G1
/// ceremony + the `// axiom-first-penguin-<name>` comments). The remaining names
/// (lambda..omega) are reserved-but-UNASSIGNED — held for future genesis, usable
/// by no one yet.
///
/// Reservation (enforced in `vbc::enforce_genesis_name_reservation` for validator
/// VBCs, `enforce_nabla_name_reservation` for nabla NBCs), in either the short
/// ("alpha") or formal ("axiom-first-penguin-alpha") form:
///   - ASSIGNED name  → the cert may carry it ONLY if its pinned genesis key
///     matches. NOTE the two tables are in DIFFERENT representations: validator
///     side compares `subject_pubkey_sphincs == GENESIS_VALIDATORS[i]` (raw
///     SPHINCS+ pubkey — the post-quantum anchor), nabla side compares
///     `validator_id == NABLA_GENESIS_VALIDATORS[i]` (blake3 node id). Any other
///     key → reject.
///   - UNASSIGNED name → reject for EVERY key (no holder exists).
/// Rejection is `ValidationError::GenesisNameReserved`. Stateless — closes
/// root-authority mis-issuance / name-squatting with no uniqueness tracking, and
/// extends cleanly: assigning a key to slot i flips it from always-rejected to
/// must-match-key.
///
/// WHY — lineage, NOT privilege (YP §17.3.2.4). Genesis validators have EXACTLY
/// the same power and function as every other node; this reservation grants them
/// nothing. It exists only to keep a founding NAME attached to its founding KEY,
/// so the bootstrap lineage cannot be forged or squatted in rosters / dashboards /
/// audit trails. Genesis nodes are kick-start-only — replaceable, retireable, free
/// to disappear once the mesh is healthy — and retiring does NOT release the name
/// to anyone else. The name records who bootstrapped, not who holds power now.
pub const GREEK_NAMES: [&str; 24] = [
    "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta",
    "iota", "kappa", "lambda", "mu", "nu", "xi", "omicron", "pi",
    "rho", "sigma", "tau", "upsilon", "phi", "chi", "psi", "omega",
];

/// Prefix on the FORMAL validator name. Real VBCs carry the formal form
/// (verified: deployed `vbc.json` node_name = "axiom-first-penguin-alpha"); the
/// short form ("alpha") is the operator label. Both denote the same validator.
pub const GENESIS_NAME_PREFIX: &str = "axiom-first-penguin-";

/// If `name` is a reserved Greek validator name — in EITHER the short form
/// ("alpha") or the formal form ("axiom-first-penguin-alpha") — return its index
/// into `GREEK_NAMES`; else `None`. Strips the formal prefix (no alloc,
/// no_std-safe) so both forms collapse to the same slot. Index < 10 = an ASSIGNED
/// genesis slot (`GENESIS_VALIDATORS`); index >= 10 = reserved-but-unassigned.
pub fn reserved_name_index(name: &str) -> Option<usize> {
    let short = name.strip_prefix(GENESIS_NAME_PREFIX).unwrap_or(name);
    if let Some(i) = GREEK_NAMES.iter().position(|g| *g == short) {
        return Some(i);
    }
    // The SYMBOL impersonates exactly as well as the word — "α" reads as alpha
    // in any peer list, dashboard or audit trail, which is the whole thing the
    // reservation exists to prevent. Matching only the transliterations left
    // that door open (found 2026-08-26).
    // `ς` (final sigma) is the same letter as `σ`, word-final — a reader cannot
    // tell them apart, so it maps to sigma's slot. Handled HERE, in the one
    // owner, not in a sibling function: a second entry point for the same rule
    // is how one caller ends up enforcing it and another not (RULE 1).
    if short == "ς" {
        return GREEK_NAMES.iter().position(|g| *g == "sigma");
    }
    GREEK_SYMBOLS.iter().position(|(lo, up)| *lo == short || *up == short)
}

/// The Greek letters as SYMBOLS, `(lowercase, uppercase)`, in `GREEK_NAMES`
/// order so a hit maps to the same slot as its transliteration.
///
/// ⚠ THIS IS NOT A GENERAL HOMOGLYPH DEFENCE, and must not be described as one.
/// Cyrillic `а` and Latin `a` are equally confusable; closing that class is
/// Unicode TR39 confusables, not a fixed list. This table closes the exact
/// impersonation the reservation names — a node calling itself by a genesis
/// letter — and nothing wider. Treating it as the general fix would be RULE 3
/// shape 6: a mitigation dressed as a solution.
///
/// Final sigma `ς` maps to sigma: it is the same letter, word-final, and a
/// reader cannot tell the difference at a glance.
pub const GREEK_SYMBOLS: [(&str, &str); 24] = [
    ("α", "Α"), ("β", "Β"), ("γ", "Γ"), ("δ", "Δ"), ("ε", "Ε"), ("ζ", "Ζ"),
    ("η", "Η"), ("θ", "Θ"), ("ι", "Ι"), ("κ", "Κ"), ("λ", "Λ"), ("μ", "Μ"),
    ("ν", "Ν"), ("ξ", "Ξ"), ("ο", "Ο"), ("π", "Π"), ("ρ", "Ρ"), ("σ", "Σ"),
    ("τ", "Τ"), ("υ", "Υ"), ("φ", "Φ"), ("χ", "Χ"), ("ψ", "Ψ"), ("ω", "Ω"),
];

// ============================================================================
// AUTO-GENERATED by genesis-ceremony tool — DO NOT EDIT
// Generated: 2026-04-28
// CA: AXIOM Origin (PGP: 4A18 9E40 F20F 5A34 B7D6  9F19 D596 AB09 93DF F9D2)
// ============================================================================
/// Genesis validators - hardcoded in Core.bin
///
/// These are the SPHINCS+ public keys of the 10 Genesis validators (First Penguins).
/// ⚠ These are NOT the VBC trust anchor. VBC chain verification terminates at
/// `ROOT_AUTHORITY_PKS` (`vbc.rs::verify_chain_recursive`, `root_check`); this
/// table is used for reserved-name enforcement
/// (`vbc.rs::enforce_genesis_name_reservation`, which compares
/// `subject_pubkey_sphincs`) and for backward-compatible overlap detection.
/// An earlier version of this comment called it "the root of trust for all
/// VBCs" and said chains terminate here — that was wrong, and is corrected in
/// `genesis_ceremony.rs` so regeneration does not reintroduce it.
pub const GENESIS_VALIDATORS: [[u8; 32]; 10] = [
    // axiom-first-penguin-alpha
    [
        0x2B, 0xA3, 0xCE, 0xCC, 0x50, 0x47, 0xF8, 0x99,
        0x69, 0x9F, 0xAA, 0xE0, 0xE5, 0x60, 0x3A, 0x9D,
        0x81, 0xF1, 0x77, 0x3C, 0x6A, 0x06, 0x95, 0x67,
        0xE9, 0x22, 0x4C, 0x68, 0xF0, 0xB5, 0x08, 0xF6,
    ],
    // axiom-first-penguin-beta
    [
        0x62, 0x54, 0x50, 0xB3, 0x9B, 0xCD, 0x43, 0x0B,
        0xD8, 0xFD, 0x5A, 0xB3, 0xBC, 0x84, 0xC6, 0x3B,
        0x8A, 0x67, 0x2B, 0xF8, 0x77, 0x78, 0xE0, 0x3C,
        0xBD, 0xA0, 0xBC, 0xF5, 0x53, 0x5C, 0x3A, 0xFF,
    ],
    // axiom-first-penguin-gamma
    [
        0x62, 0x8E, 0x97, 0x2D, 0xDF, 0x10, 0xC5, 0x54,
        0x38, 0x7C, 0xEA, 0x5E, 0xEC, 0x32, 0x9E, 0x04,
        0x36, 0x61, 0x09, 0x32, 0x9E, 0x26, 0x6B, 0xCD,
        0xB5, 0xE8, 0x6F, 0xF4, 0xC7, 0xA3, 0x31, 0x31,
    ],
    // axiom-first-penguin-delta
    [
        0xA1, 0x4A, 0x3C, 0xCB, 0x7F, 0x65, 0x48, 0x53,
        0x41, 0xC8, 0xD3, 0x46, 0x47, 0x89, 0xB7, 0x16,
        0xB9, 0x19, 0x74, 0xC4, 0xA3, 0xA8, 0x9B, 0xFF,
        0x32, 0xDA, 0xFA, 0x6C, 0x6F, 0x88, 0x7D, 0xD1,
    ],
    // axiom-first-penguin-epsilon
    [
        0x6D, 0x6B, 0x83, 0x76, 0xC5, 0x07, 0x21, 0x4E,
        0x37, 0x50, 0x51, 0xD3, 0xEA, 0x30, 0x82, 0x4D,
        0x68, 0xC5, 0x83, 0x0A, 0xD0, 0x8E, 0x24, 0xF1,
        0xE0, 0x7A, 0x72, 0x6E, 0x1A, 0x95, 0x68, 0xE7,
    ],
    // axiom-first-penguin-zeta
    [
        0x92, 0x44, 0x9F, 0xE6, 0xE5, 0x40, 0x48, 0xC7,
        0xD0, 0xF5, 0x75, 0x86, 0xDA, 0x66, 0xB2, 0xBA,
        0x68, 0xD8, 0x73, 0x4E, 0x9C, 0x5E, 0x23, 0x2D,
        0x11, 0xF8, 0x56, 0x80, 0xA5, 0x3A, 0x1C, 0x8B,
    ],
    // axiom-first-penguin-eta
    [
        0x40, 0x9F, 0x2C, 0xAE, 0xA3, 0x15, 0xC7, 0xF1,
        0xDB, 0xBD, 0xD4, 0x7E, 0xA5, 0xE5, 0xB6, 0xF0,
        0x1F, 0x5E, 0x1D, 0x4A, 0xAC, 0x04, 0xF7, 0x78,
        0xA8, 0x93, 0xA2, 0x7D, 0x8A, 0x26, 0x27, 0x20,
    ],
    // axiom-first-penguin-theta
    [
        0x93, 0xE6, 0xFB, 0x6A, 0xD0, 0x17, 0x2E, 0xB5,
        0x58, 0xFF, 0x10, 0x46, 0xAB, 0x65, 0x2F, 0x0A,
        0xAC, 0x75, 0xCF, 0x46, 0x3D, 0x2C, 0x22, 0xD6,
        0x77, 0x2E, 0xDA, 0xE9, 0x6C, 0x2A, 0xBF, 0xD9,
    ],
    // axiom-first-penguin-iota
    [
        0xB5, 0x2B, 0x40, 0x50, 0xD3, 0x29, 0xC6, 0x4C,
        0x1E, 0xFB, 0x29, 0x7A, 0x1E, 0x1C, 0xCB, 0x57,
        0xB0, 0xFB, 0xD1, 0x07, 0xB7, 0x31, 0xDC, 0x3E,
        0x36, 0x68, 0xD8, 0x07, 0xE7, 0xD4, 0xB0, 0x8E,
    ],
    // axiom-first-penguin-kappa
    [
        0xBD, 0x6A, 0x58, 0x9F, 0xF5, 0x78, 0x1C, 0x34,
        0x23, 0xA6, 0x22, 0xE6, 0xA1, 0x27, 0x09, 0x99,
        0x71, 0x64, 0xD5, 0xEB, 0x0E, 0xD4, 0x8C, 0x96,
        0x99, 0xBB, 0x88, 0x32, 0x69, 0x2F, 0xC8, 0xB5,
    ],
];

/// Root Authority SPHINCS+ public keys — the trust anchor of AXIOM.
/// Chain verification stops when it hits one of these.
/// Certificate Authority: AXIOM Origin
/// PGP: 4A18 9E40 F20F 5A34 B7D6  9F19 D596 AB09 93DF F9D2
pub const ROOT_AUTHORITY_PKS: [[u8; 32]; 3] = [
    // ROOT_1
    [
        0x3E, 0x4F, 0x50, 0x98, 0xEC, 0x82, 0x77, 0x93,
        0xC7, 0xB0, 0xF7, 0x2E, 0xC7, 0x9E, 0x46, 0x2C,
        0xD5, 0x3F, 0x73, 0x37, 0x6B, 0xB4, 0xF3, 0x8D,
        0x98, 0x32, 0x92, 0x7E, 0xFD, 0x4A, 0x1A, 0xEF,
    ],
    // ROOT_2
    [
        0x60, 0xAF, 0x6E, 0x17, 0x4A, 0x3B, 0x35, 0x17,
        0x7B, 0x93, 0xB5, 0x15, 0x95, 0x46, 0x5E, 0xE9,
        0xC5, 0x40, 0x28, 0x68, 0x05, 0xD1, 0x49, 0x68,
        0x9B, 0x2F, 0xA2, 0x89, 0x19, 0x89, 0x57, 0x14,
    ],
    // ROOT_3
    [
        0x54, 0x9A, 0x72, 0x77, 0x57, 0xC9, 0xE0, 0x3F,
        0x05, 0x52, 0x87, 0xF5, 0xF2, 0xDA, 0x46, 0x43,
        0x30, 0xEF, 0x24, 0x04, 0xCA, 0xE0, 0x88, 0xE5,
        0xCA, 0xF2, 0xEC, 0xDC, 0x12, 0x6C, 0x00, 0x5D,
    ],
];

/// Certificate Authority PGP fingerprint (20 bytes)
/// 4A18 9E40 F20F 5A34 B7D6  9F19 D596 AB09 93DF F9D2
pub const CA_PGP_FINGERPRINT: [u8; 20] = [
    0x4A, 0x18, 0x9E, 0x40, 0xF2, 0x0F, 0x5A, 0x34, 0xB7, 0xD6, 0x9F, 0x19, 0xD5, 0x96, 0xAB, 0x09, 0x93, 0xDF, 0xF9, 0xD2
];

/// Check if a public key is a root authority key
pub fn is_root_authority(pk: &[u8]) -> bool {
    if pk.len() != 32 {
        return false;
    }
    let pk_array: [u8; 32] = pk.try_into().unwrap_or([0; 32]);
    // Skip all-zero placeholder keys
    if pk_array == [0u8; 32] {
        return false;
    }
    ROOT_AUTHORITY_PKS.iter().any(|r| r == &pk_array)
}



/// Check if a public key is a genesis validator
pub fn is_genesis_validator(pk: &[u8]) -> bool {
    if pk.len() != 32 {
        return false;
    }
    
    let pk_array: [u8; 32] = pk.try_into().unwrap_or([0; 32]);
    GENESIS_VALIDATORS.iter().any(|g| g == &pk_array)
}





#[cfg(test)]
mod tests {

    /// §6c — the opening balance is a function of the compile-time list and
    /// nothing else: a key pk-bound to a listed id opens at GENESIS_VALIDATOR_GRANT_ATOMS,
    /// any other key at 0, and the state id follows from that balance through
    /// the one genesis formula. Uses the REAL compiled list (never a fixture),
    /// so it fails if the list and the deployed keys drift apart.
    #[test]
    fn genesis_opening_balance_is_keyed_on_the_compiled_list() {
        use crate::validation::protocol_gen::{GENESIS_LOCKUP_WALLET_IDS, GENESIS_STAKE_WALLET_PKS};
        use crate::wallet_id::{K_DEFAULT, PROOF_TYPE_DMAP};
        // A stranger's key: never bonded. [0x11; 32] is the key whose one-byte
        // pk_bind COLLIDED with eta's listed id under the first draft — it must
        // stay a stranger forever.
        for stranger in [[0x5Au8; 32], [0x11u8; 32]] {
            assert_eq!(genesis_opening_balance(&stranger), 0, "a stranger key must never open funded");
        }
        let stranger = [0x5Au8; 32];
        assert_eq!(genesis_opening_balance(&stranger), 0);
        assert_eq!(opening_state_id_for(&stranger, K_DEFAULT, PROOF_TYPE_DMAP),
                   compute_genesis_state_id(&stranger, 0, K_DEFAULT, PROOF_TYPE_DMAP));
        assert_eq!(genesis_opening_balance(&[0u8; 32]), 0, "the zero key must never be bonded");
        assert_eq!(genesis_opening_balance(&[1u8; 31]), 0, "a malformed key must never be bonded");
        // Every listed id must be pk-bound to SOME key the fleet holds; here we
        // can only assert the list's shape and that a listed id binds to the key
        // the deployed alpha certificate names, when the list is populated.
        if !GENESIS_LOCKUP_WALLET_IDS.is_empty() {
            assert_eq!(GENESIS_LOCKUP_WALLET_IDS.len(), GENESIS_VALIDATORS.len(),
                "one stake wallet id per genesis validator — a list of any other length is a ceremony error");
            // The FIRST listed key (alpha's on the dev fleet). It used to be the
            // dev certificate key as a hex literal — which made this test fail by
            // construction after ANY real ceremony (2026-09-11 G1 rehearsal, handoff
            // §18.9). "Listed key == the deployed certificate's key" is a DEPLOYMENT
            // check (verify_deploy.sh), not a unit test of the §6c derivation.
            assert_eq!(GENESIS_STAKE_WALLET_PKS.len(), GENESIS_LOCKUP_WALLET_IDS.len(),
                "every listed id must carry its key — a bare id is an address, not an identity");
            let alpha_pk: [u8; 32] = GENESIS_STAKE_WALLET_PKS[0];
            assert_ne!(alpha_pk, [0u8; 32], "a listed key must be a real key");
            assert_eq!(genesis_opening_balance(&alpha_pk), crate::types::GENESIS_VALIDATOR_GRANT_ATOMS);
            assert_eq!(opening_state_id_for(&alpha_pk, K_DEFAULT, PROOF_TYPE_DMAP),
                       compute_genesis_state_id(&alpha_pk, crate::types::GENESIS_VALIDATOR_GRANT_ATOMS, K_DEFAULT, PROOF_TYPE_DMAP));
        }
    }

    fn hex_literal_to_arr(h: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }
    use super::*;
    
    use crate::wallet_id::{K_ARK, PROOF_TYPE_ARK, PROOF_TYPE_DMAP};

    // Standard (k=3, DMAP) is the everyday tier used as the "normal" counterpart
    // to Ark in the collision proof.
    const K_STD: u8 = 3;

    /// A Greek SYMBOL must be as reserved as its transliteration — "α" reads as
    /// alpha in any peer list, which is precisely what the reservation exists to
    /// stop. Mutation: delete the GREEK_SYMBOLS branch in reserved_name_index
    /// and every symbol assertion below goes red.
    #[test]
    fn greek_symbols_are_reserved_like_their_names() {
        // lower, upper, and the formal prefix form
        assert_eq!(reserved_name_index("α"), Some(0));
        assert_eq!(reserved_name_index("Α"), Some(0));
        assert_eq!(reserved_name_index("ω"), Some(23));
        assert_eq!(reserved_name_index("Ω"), Some(23));
        assert_eq!(reserved_name_index("axiom-first-penguin-α"), Some(0));

        // a symbol lands on the SAME slot as its word
        assert_eq!(reserved_name_index("ζ"), reserved_name_index("zeta"));

        // final sigma is sigma — same letter, word-final
        assert_eq!(reserved_name_index("ς"), reserved_name_index("sigma"));
        assert_eq!(reserved_name_index("σ"), reserved_name_index("sigma"));

        // and the negative side: ordinary names stay free, including one that
        // merely CONTAINS a reserved word.
        assert_eq!(reserved_name_index("焼き鳥"), None);
        assert_eq!(reserved_name_index("alpha-centauri"), None);
        assert_eq!(reserved_name_index("α-centauri"), None);
        assert_eq!(reserved_name_index(""), None);
    }

    #[test]
    fn test_compute_genesis_state_id() {
        let pk = [0x42u8; 32];
        let balance = 1_000_000_000_000u64; // 1 trillion atoms

        let state_id = compute_genesis_state_id(&pk, balance, K_STD, PROOF_TYPE_DMAP);

        // Should be deterministic
        let state_id_2 = compute_genesis_state_id(&pk, balance, K_STD, PROOF_TYPE_DMAP);
        assert_eq!(state_id, state_id_2);

        // Different balance should give different state_id
        let state_id_3 = compute_genesis_state_id(&pk, balance + 1, K_STD, PROOF_TYPE_DMAP);
        assert_ne!(state_id, state_id_3);

        // Different pk should give different state_id
        let pk2 = [0x43u8; 32];
        let state_id_4 = compute_genesis_state_id(&pk2, balance, K_STD, PROOF_TYPE_DMAP);
        assert_ne!(state_id, state_id_4);
    }

    #[test]
    fn test_create_genesis_wallet() {
        let pk = [0x42u8; 32];
        let balance = 1_000_000_000_000u64;

        let wallet = create_genesis_wallet(pk, balance, K_STD, PROOF_TYPE_DMAP);

        assert_eq!(wallet.public_key, pk);
        assert_eq!(wallet.balance, balance);
        assert_eq!(wallet.wallet_seq, 0);
        assert_eq!(
            wallet.genesis_state_id,
            compute_genesis_state_id(&pk, balance, K_STD, PROOF_TYPE_DMAP)
        );
    }

    /// SINGLE-KEYPAIR CONVERGENCE PROOF (YPX-010 §10.5). One keypair backs both
    /// a normal (k=3) and an Ark (k=0) wallet_id. This proves that the tier
    /// bytes make their state IDENTITIES distinct at genesis, and — the load-
    /// bearing part — that the distinctness PROPAGATES through the produced-state
    /// chain even when every other input (balance, seq, nonce) is identical.
    /// That propagation is why `state_hash` does NOT also need the tier: the
    /// `consumed_state_id == prev_receipt.produced_state_id` chain check
    /// (validation.rs) rejects a cross-tier receipt before `state_hash` matters.
    #[test]
    fn genesis_tier_distinct_and_propagates() {
        use crate::crypto::compute_produced_state_id;

        // SAME keypair, SAME genesis balance — only the tier differs.
        let pk = [0x7fu8; 32];
        let bal = 0u64; // genesis balance is 0 in the normal flow

        let g_normal = compute_genesis_state_id(&pk, bal, 3, PROOF_TYPE_DMAP); // k=3 Standard
        let g_ark = compute_genesis_state_id(&pk, bal, K_ARK, PROOF_TYPE_ARK); // k=0 Ark

        // (1) Genesis states are distinct across tiers for the SAME pk.
        assert_ne!(
            g_normal, g_ark,
            "k=3 and k=0 tiers of one keypair must have distinct genesis states"
        );
        // Determinism sanity: same tier reproduces.
        assert_eq!(g_ark, compute_genesis_state_id(&pk, bal, K_ARK, PROOF_TYPE_ARK));

        // (2) PROPAGATION: build the FIRST produced state (seq=1 funding) on each
        // genesis with byte-for-byte identical (balance, seq, nonce). The only
        // difference is the consumed_state_id (the tier-distinct genesis).
        let (fund_bal, seq1, nonce) = (500_000u64, 1u64, 0u64);
        let p_normal = compute_produced_state_id(&pk, fund_bal, seq1, &g_normal, nonce);
        let p_ark = compute_produced_state_id(&pk, fund_bal, seq1, &g_ark, nonce);
        assert_ne!(
            p_normal, p_ark,
            "first produced state must stay tier-distinct via consumed_state_id (genesis)"
        );

        // (3) PROPAGATION holds two levels deep: chain each once more, again with
        // identical (balance, seq, nonce). A tier-agnostic state_hash would
        // collide here; the produced_state_id chain does not.
        let (bal2, seq2) = (400_000u64, 2u64);
        let p_normal_2 = compute_produced_state_id(&pk, bal2, seq2, &p_normal, nonce);
        let p_ark_2 = compute_produced_state_id(&pk, bal2, seq2, &p_ark, nonce);
        assert_ne!(
            p_normal_2, p_ark_2,
            "tier-distinctness must persist down the whole state chain"
        );
    }
    
    #[test]
    fn test_is_genesis_validator() {
        // All 10 genesis validators should be recognized
        for gv in &GENESIS_VALIDATORS {
            assert!(is_genesis_validator(gv));
        }

        // Non-genesis key
        let other = [0xFFu8; 32];
        assert!(!is_genesis_validator(&other));

        // Wrong length
        let short = [0x01u8; 16];
        assert!(!is_genesis_validator(&short));
    }

    // Nabla root authority and genesis validator tests moved to nabla_genesis.rs
}

/// TEST-ONLY (`cfg(test)`, never in a shipped Core) — the `nabla_genesis::test_roots`
/// shape for the validator roots: a unit test authorizes SPHINCS+ root keys it
/// generated so its fixtures can carry REAL certificates verified through the
/// production path (YP §26.17.6.5 B2). Consulted by `vbc::root_authority_check`,
/// the predicate the certificate verifier uses — NOT by `is_root_authority`
/// below, which the genesis-ceremony tool regenerates verbatim (rehearsal
/// finding F20, 2026-09-12: a `#[cfg(test)]` inside that generated function was
/// taken by the tool as the start of the preserved test section and left a
/// dangling brace). Appended at the END of the file, inside the tool-preserved test section, so no
/// line of production code moves (a line shift alone moves the CoreID — measured
/// 2026-09-12: `66eb6dae` → `00cfad22` in the same worktree).
#[cfg(test)]
pub(crate) mod test_roots {
    extern crate std;
    use std::sync::Mutex;
    static ROOTS: Mutex<alloc::vec::Vec<[u8; 32]>> = Mutex::new(alloc::vec::Vec::new());
    pub(crate) fn authorize(pk: [u8; 32]) { ROOTS.lock().unwrap().push(pk); }
    pub(crate) fn is_authorized(pk: &[u8; 32]) -> bool { ROOTS.lock().unwrap().contains(pk) }
}
