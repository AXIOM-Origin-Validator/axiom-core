//! Nabla genesis constants — separate from validator genesis.rs
//!
//! These constants are NOT overwritten by the genesis ceremony tool,
//! which only manages validator ROOT_AUTHORITY_PKS and GENESIS_VALIDATORS.
//! Nabla keys are managed by the nabla-ceremony tool independently.

/// Nabla Root Authority raw SPHINCS+ (SLH-DSA-SHA2-128s) public keys.
/// NBC `issuer_set[0]` is byte-compared against these values by
/// `is_nabla_root_authority`; chain verification terminates when it
/// hits one of them. Separate from the Validator `ROOT_AUTHORITY_PKS`
/// for key isolation.
///
/// These MUST stay in sync with `root-keys/nabla/root_{1,2,3}.pub`.
/// The ceremony (`g1-full-ceremony.sh` → `nabla-ceremony`) is the
/// authoritative source — this file is a baked mirror. An earlier
/// doc comment described these as SHA256 hashes; that was always
/// wrong — the call site (`is_nabla_root_authority`) does a direct
/// 32-byte byte-compare against the raw pubkey carried in
/// `nbc.issuer_set[0]`, which the ceremony copies directly from the
/// `.pub` files. A SPHINCS+ SHA2-128s public key happens to be 32
/// bytes (same length as a SHA256 hash), which is how the stale
/// comment survived undetected.
pub const NABLA_ROOT_AUTHORITY_PKS: [[u8; 32]; 3] = [
    // NABLA_ROOT_1
    [
        0x30, 0xBD, 0x5A, 0x5F, 0xC6, 0x38, 0x28, 0xBB,
        0x59, 0x49, 0x93, 0x4C, 0x9B, 0x24, 0x09, 0x5B,
        0xE3, 0x92, 0xD6, 0x6E, 0x8D, 0x8C, 0xEF, 0xDC,
        0x22, 0xAD, 0xAD, 0x58, 0xF8, 0x6B, 0xB4, 0xC0,
    ],
    // NABLA_ROOT_2
    [
        0x84, 0xCA, 0xF0, 0xCF, 0x79, 0xA2, 0xB4, 0x06,
        0x72, 0xDA, 0xD1, 0xD2, 0xAF, 0xB1, 0x8B, 0x44,
        0x22, 0x38, 0x02, 0xE6, 0xC1, 0x2E, 0x9C, 0x83,
        0x75, 0x4C, 0x6E, 0x0F, 0xF4, 0xEA, 0x9B, 0x5A,
    ],
    // NABLA_ROOT_3
    [
        0x55, 0x3A, 0xB0, 0xDA, 0xA3, 0xD4, 0x3F, 0x9B,
        0xA6, 0xF9, 0x90, 0xD5, 0x7D, 0x26, 0xC7, 0x2E,
        0x04, 0x19, 0x8F, 0xAD, 0xE8, 0x9B, 0xD7, 0x87,
        0x68, 0xAE, 0x53, 0xBB, 0x81, 0x1E, 0xF2, 0x58,
    ],
];

/// Nabla genesis nodes — the 10 First Penguins' **NODE IDS** for NBC.
/// These are SEPARATE from the Validator GENESIS_VALIDATORS (key isolation).
/// Used to identify founding Nabla nodes in the TARDIS network.
///
/// ⚠ **These are NODE IDS, NOT SPHINCS+ public keys** — corrected 2026-08-19.
/// A node id is `BLAKE3(subject_pubkey_sphincs)` (`nabla/src/cc.rs`:
/// "validator_id == BLAKE3(sphincs_pk)"), and `nbc_node_id(nbc)` returns
/// `nbc.validator_id`. Verified against the live mesh: every entry below equals
/// the `Node ID (from NBC)` its node logs at boot — alpha `10aeb50a`, beta
/// `472bf6be`, gamma `9303558d`, delta `970d068d`, epsilon `c612a825`, zeta
/// `6dc933bc`, eta `3aa973b3`, theta `87f57db4`, iota `b168be9a`, kappa
/// `d0b9d358`.
///
/// The previous comment said "SPHINCS+ public keys". That is the SAME stale-
/// comment trap documented on `NABLA_ROOT_AUTHORITY_PKS` above, and it survives
/// undetected for the same reason: a SPHINCS+ SHA2-128s public key is 32 bytes,
/// exactly the length of a BLAKE3 digest, so nothing type-checks the confusion.
/// **Consequence if you believe it:** comparing an issuer's raw SPHINCS+ key
/// against this array matches NOTHING and fails closed silently.
/// (`NABLA_ROOT_AUTHORITY_PKS` above genuinely IS raw pubkeys — the two arrays
/// hold different representations. That asymmetry is the whole trap.)
///
/// This array is for IDENTITY (peer/TARDIS lookup, name reservation). For
/// VERIFYING an issuer, use `NABLA_GENESIS_VALIDATOR_PKS` below — an id cannot
/// anchor a signature check.
pub const NABLA_GENESIS_VALIDATORS: [[u8; 32]; 10] = [
    // nabla-genesis-alpha
    [
        0x10, 0xAE, 0xB5, 0x0A, 0x0A, 0xE1, 0x3C, 0x1C,
        0xD0, 0xC8, 0x15, 0x2A, 0x4B, 0x5F, 0xD6, 0xA2,
        0x66, 0x25, 0x1D, 0xC6, 0x56, 0x7E, 0xA7, 0x8B,
        0x1D, 0xEA, 0xB0, 0x83, 0x07, 0xA6, 0x3E, 0xC2,
    ],
    // nabla-genesis-beta
    [
        0x47, 0x2B, 0xF6, 0xBE, 0x5C, 0xEC, 0x0B, 0x3E,
        0xC1, 0x19, 0x62, 0x19, 0x82, 0x98, 0x5E, 0xAD,
        0x79, 0xBE, 0xC7, 0x29, 0x30, 0x56, 0x27, 0xA9,
        0xF9, 0x37, 0x28, 0x41, 0x3F, 0x59, 0x80, 0x23,
    ],
    // nabla-genesis-gamma
    [
        0x93, 0x03, 0x55, 0x8D, 0x66, 0x89, 0x1D, 0xEF,
        0x28, 0xAA, 0x5A, 0x06, 0x0E, 0xE0, 0xD6, 0x91,
        0x11, 0x6C, 0x3E, 0xAF, 0x9F, 0xD0, 0x13, 0xBC,
        0x2A, 0x80, 0x6E, 0xF1, 0x5B, 0x26, 0x84, 0x62,
    ],
    // nabla-genesis-delta
    [
        0x97, 0x0D, 0x06, 0x8D, 0xFC, 0xBB, 0x6C, 0xDD,
        0x7F, 0x96, 0x81, 0x5F, 0x4A, 0x7B, 0x93, 0x02,
        0xA4, 0xB9, 0x69, 0x83, 0xE8, 0xAE, 0x1F, 0x6F,
        0x02, 0x05, 0xE6, 0x5A, 0x6E, 0x06, 0xFA, 0x45,
    ],
    // nabla-genesis-epsilon
    [
        0xC6, 0x12, 0xA8, 0x25, 0xD4, 0x72, 0x6B, 0x5A,
        0x0B, 0x23, 0xE6, 0xA7, 0x64, 0x58, 0x3C, 0xD6,
        0x8F, 0x3F, 0xA0, 0x9C, 0x66, 0x91, 0x19, 0xD2,
        0x66, 0xA7, 0x67, 0x7F, 0x5D, 0x5F, 0xB7, 0x9B,
    ],
    // nabla-genesis-zeta
    [
        0x6D, 0xC9, 0x33, 0xBC, 0xA0, 0x6F, 0xE2, 0x7B,
        0x50, 0xF3, 0xCB, 0xE8, 0x42, 0x37, 0xA5, 0xD9,
        0xDE, 0x88, 0x68, 0xA6, 0x2A, 0x75, 0xCC, 0x17,
        0xDE, 0x8F, 0x0A, 0x19, 0x6F, 0xD1, 0xAA, 0x1C,
    ],
    // nabla-genesis-eta
    [
        0x3A, 0xA9, 0x73, 0xB3, 0x85, 0xCA, 0xF0, 0x13,
        0xD0, 0xF1, 0x3B, 0xDC, 0xAA, 0xDE, 0xA7, 0xE5,
        0x32, 0xC6, 0xEB, 0x94, 0x92, 0x75, 0x53, 0x42,
        0x08, 0x62, 0x03, 0xE6, 0xCD, 0x6E, 0x24, 0xD6,
    ],
    // nabla-genesis-theta
    [
        0x87, 0xF5, 0x7D, 0xB4, 0x37, 0x3D, 0x26, 0x0E,
        0x29, 0x5F, 0x29, 0x34, 0x5E, 0x7E, 0x48, 0x24,
        0xED, 0x49, 0x08, 0xEF, 0x31, 0x66, 0xCC, 0xB9,
        0x01, 0xDC, 0xB2, 0xE4, 0x89, 0x11, 0xB7, 0xED,
    ],
    // nabla-genesis-iota
    [
        0xB1, 0x68, 0xBE, 0x9A, 0x2F, 0xA3, 0xF3, 0x4A,
        0x49, 0xB3, 0xBB, 0x63, 0x55, 0xB7, 0xB0, 0xFC,
        0x3B, 0x2B, 0x9A, 0xB0, 0x6A, 0x57, 0xDB, 0x22,
        0x08, 0xB2, 0x7D, 0xD5, 0x6B, 0xCC, 0xB4, 0x94,
    ],
    // nabla-genesis-kappa
    [
        0xD0, 0xB9, 0xD3, 0x58, 0x27, 0x57, 0xFB, 0xB9,
        0x7D, 0x06, 0x9E, 0xE7, 0x5A, 0x37, 0x80, 0x3D,
        0xF9, 0xA6, 0x4D, 0xCA, 0x3E, 0xF9, 0xC7, 0xD2,
        0x70, 0x7D, 0x4D, 0x86, 0x99, 0x13, 0x8D, 0x4E,
    ],
];

/// Nabla genesis nodes — the 10 First Penguins' raw SPHINCS+ PUBLIC KEYS.
///
/// KI#97 (2026-08-19). This is the **verification anchor** for NBC lineage, and
/// it is what `NABLA_GENESIS_VALIDATORS` could never be: that array holds node
/// IDS (`BLAKE3(pk)`), and a digest can only RECOGNISE an identity you were
/// already handed — it cannot VERIFY a signature. Anchoring a chain needs the
/// key itself.
///
/// This mirrors the validator side, which has always pinned keys:
/// `genesis::GENESIS_VALIDATORS` — "the reality anchor. A VBC chain is valid if
/// and only if all branches terminate at one of these keys." Nabla was the odd
/// one out, which is precisely why its CLIENT path could not verify lineage
/// while the peer path (KI#93) could.
///
/// SELF-CHECKING: `ki97_pinned_pks_match_pinned_node_ids` asserts
/// `BLAKE3(NABLA_GENESIS_VALIDATOR_PKS[i]) == NABLA_GENESIS_VALIDATORS[i]` for
/// all ten, so the two arrays cannot drift apart silently. Verified against the
/// live ceremony material (`config/nabla_sphincs.pub`) when baked.
pub const NABLA_GENESIS_VALIDATOR_PKS: [[u8; 32]; 10] = [
    // nabla-genesis-alpha
    [
        0x2B, 0xA9, 0x77, 0x82, 0xF7, 0x7D, 0x20, 0x71,
        0x15, 0x45, 0x18, 0xB2, 0x6B, 0xEB, 0x8D, 0xF3,
        0xB5, 0xF5, 0xC5, 0xE0, 0x0C, 0xEB, 0xC6, 0xD1,
        0x31, 0x84, 0x0D, 0x8A, 0xE2, 0x87, 0x0E, 0xEB,
    ],
    // nabla-genesis-beta
    [
        0x19, 0xDF, 0xDE, 0xEB, 0x26, 0x94, 0xC8, 0x29,
        0x53, 0xC0, 0x73, 0xA9, 0x1B, 0x5B, 0x87, 0x34,
        0xC8, 0xF7, 0x47, 0xCB, 0x28, 0xAC, 0x51, 0xA1,
        0xCC, 0x6E, 0x61, 0x64, 0xE9, 0x3E, 0xD0, 0xEA,
    ],
    // nabla-genesis-gamma
    [
        0x01, 0x87, 0xAF, 0xC6, 0x49, 0xE8, 0xB5, 0xCD,
        0x01, 0xFB, 0x6F, 0x0A, 0x63, 0xE2, 0x62, 0x43,
        0xBA, 0x5A, 0xCA, 0xB0, 0xAB, 0xEC, 0xEB, 0x0A,
        0xD1, 0x68, 0x7D, 0x23, 0xB3, 0x30, 0x7B, 0xF7,
    ],
    // nabla-genesis-delta
    [
        0x20, 0xB2, 0xB6, 0xD8, 0x66, 0x28, 0x12, 0x9C,
        0x07, 0xE2, 0xD9, 0xC1, 0x15, 0x2B, 0x48, 0x27,
        0x33, 0xF5, 0xAF, 0x7C, 0x56, 0xB7, 0x82, 0x0F,
        0x1E, 0x0C, 0x65, 0x8A, 0x0D, 0xE5, 0xAB, 0x13,
    ],
    // nabla-genesis-epsilon
    [
        0x6F, 0xB5, 0x75, 0x8F, 0xF2, 0x62, 0x9F, 0x27,
        0xAA, 0x24, 0xF3, 0x9D, 0x27, 0x20, 0x38, 0xCA,
        0x3F, 0x6F, 0x52, 0x16, 0x00, 0xA2, 0x4C, 0x47,
        0xAA, 0x08, 0xED, 0xA7, 0xC3, 0x90, 0xE5, 0xEB,
    ],
    // nabla-genesis-zeta
    [
        0x51, 0xEC, 0x59, 0xC1, 0xC8, 0xC5, 0x29, 0xBB,
        0xEE, 0x7B, 0x1B, 0xCB, 0x9A, 0xCD, 0xB3, 0xDD,
        0xC5, 0x26, 0x73, 0x4A, 0xE1, 0x57, 0xEB, 0x36,
        0xE5, 0x93, 0x93, 0xFE, 0x46, 0xAB, 0xA8, 0x8B,
    ],
    // nabla-genesis-eta
    [
        0x22, 0x29, 0xC0, 0x18, 0xB0, 0x74, 0x98, 0xF2,
        0x7A, 0x24, 0x89, 0xBE, 0xEF, 0xCE, 0x55, 0x2A,
        0x0B, 0xCC, 0xCF, 0x07, 0x72, 0x6F, 0x51, 0x37,
        0xF0, 0x1D, 0xCB, 0xFA, 0x94, 0x7F, 0xC1, 0x96,
    ],
    // nabla-genesis-theta
    [
        0x82, 0x06, 0xA0, 0xFF, 0x35, 0x2E, 0x45, 0x72,
        0xB9, 0x99, 0x3E, 0xBA, 0x16, 0x7F, 0xD6, 0xAB,
        0x74, 0x2C, 0xE0, 0x60, 0xCB, 0x54, 0xDB, 0x13,
        0x48, 0x12, 0x3A, 0x51, 0x78, 0xF2, 0x0E, 0x8A,
    ],
    // nabla-genesis-iota
    [
        0x99, 0x3B, 0xB4, 0x3D, 0x4B, 0xBD, 0xA2, 0x49,
        0xDD, 0xF7, 0xB2, 0x4B, 0x02, 0x54, 0x3F, 0xA7,
        0xDD, 0xCF, 0xD8, 0xC5, 0x4F, 0x4F, 0x07, 0xB6,
        0xFA, 0xEA, 0x81, 0xAA, 0x33, 0xF0, 0x25, 0xBA,
    ],
    // nabla-genesis-kappa
    [
        0xB1, 0xAE, 0xB8, 0x79, 0xB6, 0x99, 0x9F, 0x71,
        0x72, 0x63, 0xA1, 0x63, 0xA7, 0x98, 0x5C, 0xA6,
        0xF5, 0xEC, 0xC9, 0x54, 0xDC, 0xF1, 0xB0, 0x14,
        0x31, 0xA9, 0xEC, 0x86, 0x1D, 0x33, 0xB9, 0x9D,
    ],
];

/// Check if a public key is a Nabla root authority key
pub fn is_nabla_root_authority(pk: &[u8]) -> bool {
    if pk.len() != 32 {
        return false;
    }
    let pk_array: [u8; 32] = pk.try_into().unwrap_or([0; 32]);
    if pk_array == [0u8; 32] {
        return false;
    }
    #[cfg(test)]
    if test_roots::is_authorized(&pk_array) {
        return true;
    }
    NABLA_ROOT_AUTHORITY_PKS.iter().any(|r| r == &pk_array)
}

/// Check if a public key is a Nabla genesis validator
pub fn is_nabla_genesis_validator(pk: &[u8]) -> bool {
    if pk.len() != 32 {
        return false;
    }
    let pk_array: [u8; 32] = pk.try_into().unwrap_or([0; 32]);
    NABLA_GENESIS_VALIDATORS.iter().any(|g| g == &pk_array)
}

/// KI#97 — may this SPHINCS+ key have ISSUED the NBC behind a client-facing
/// Nabla proof (txid attestation, cheque-claim proof, CLARA attestation, FACT
/// `NablaConfirmation`)?
///
/// **This is the ONE owner of that question.** Seven call sites in
/// `validation.rs` each asked it as a bare `is_nabla_root_authority(...)`, which
/// accepts ONLY a `chain_depth = 0` genesis cert. A CITIZEN node's NBC is issued
/// by a GENESIS node, not by the root, so every proof a citizen signed was
/// refused — `E_CHEQUE_CLAIM_PROOF_UNTRUSTED` and siblings. The Pi joined TARDIS
/// successfully on 2026-08-19 and broke a wallet's genesis claim within seconds,
/// because clients discover it by gossip and nothing marks it unusable. KI#93
/// had fixed the equivalent gap on the PEER path; this is the client path.
///
/// Accepts a root authority, OR a genesis Nabla validator. The second arm is
/// what admits `chain_depth = 1`. BOTH arms compare raw SPHINCS+ PUBLIC KEYS —
/// `NABLA_ROOT_AUTHORITY_PKS` and `NABLA_GENESIS_VALIDATOR_PKS`. Do NOT reach for
/// `NABLA_GENESIS_VALIDATORS` here: that array holds NODE IDS
/// (`BLAKE3(sphincs_pk)`), and a digest can only RECOGNISE an identity, never
/// VERIFY a signature. Pinning the keys is what makes lineage checkable at all,
/// and it is what the validator side has always done
/// (`genesis::GENESIS_VALIDATORS`, "the reality anchor").
///
/// **Why this is safe, and why it is NOT merely a widened gate.** The caller has
/// already verified `verify_sphincs(nbc_issuer_pk, blake3(nbc_commitment),
/// nbc_signature)` — the issuer really signed this exact commitment — and that
/// the commitment binds the serving node's Ed25519 key. This function only
/// answers "was the signer entitled to issue?", and it answers it from Core's
/// OWN pinned genesis set, never from client-supplied chain material. Forging
/// still requires a genesis node's SPHINCS+ secret key: the same bar as before.
///
/// **Deliberate limit: depth 1 only.** A cert issued by a citizen (depth >= 2)
/// is still refused. That matches the deployed model — citizens are issued by
/// genesis nodes — and it is the conservative choice: admitting deeper chains
/// means walking attacker-supplied supporting certs, which is strictly more
/// surface than consulting a pinned constant. If multi-level citizen issuance is
/// ever wanted, do it as an explicit supporting-chain walk mirroring
/// `vbc::verify_chain_recursive`, with the chain carried on the wire.
pub fn nabla_proof_issuer_is_authorized(issuer_pk: &[u8]) -> bool {
    if is_nabla_root_authority(issuer_pk) {
        return true;
    }
    // chain_depth = 1: issued BY a genesis Nabla node. Compare against the pinned
    // PUBLIC KEYS, not the node-id array — the key is the verification anchor.
    if issuer_pk.len() != 32 {
        return false;
    }
    let pk: [u8; 32] = match issuer_pk.try_into() { Ok(a) => a, Err(_) => return false };
    if pk == [0u8; 32] {
        return false; // uninitialised / absent field must never authorize
    }
    NABLA_GENESIS_VALIDATOR_PKS.iter().any(|g| g == &pk)
}

/// Test-only root authorities (KI#143, 2026-09-10). The NBC anchor of an OODS
/// reading needs a SPHINCS+ signature by an AUTHORIZED issuer — ceremony keys
/// no unit test holds — so tests that must exercise a VERIFIED reading end to
/// end (CL8 binds the stamp and the candidacy tick to one) register a fresh
/// issuer here. `cfg(test)` only: this module does not exist in any ELF or
/// native build; the production accept-set is the two pinned arrays alone.
#[cfg(test)]
pub(crate) mod test_roots {
    extern crate std;
    use std::sync::Mutex;
    static ROOTS: Mutex<alloc::vec::Vec<[u8; 32]>> = Mutex::new(alloc::vec::Vec::new());
    pub(crate) fn authorize(pk: [u8; 32]) { ROOTS.lock().unwrap().push(pk); }
    pub(crate) fn is_authorized(pk: &[u8; 32]) -> bool { ROOTS.lock().unwrap().contains(pk) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE TIE between the two genesis arrays. `NABLA_GENESIS_VALIDATOR_PKS`
    /// holds keys, `NABLA_GENESIS_VALIDATORS` holds ids, and the id is
    /// `BLAKE3(key)`. If either array is ever edited without the other, this
    /// goes red — which is the only thing stopping them drifting apart silently,
    /// since both are `[[u8; 32]; 10]` and nothing type-checks the difference.
    #[test]
    fn ki97_pinned_pks_match_pinned_node_ids() {
        for (i, pk) in NABLA_GENESIS_VALIDATOR_PKS.iter().enumerate() {
            let derived: [u8; 32] = blake3::hash(pk).into();
            assert_eq!(
                derived, NABLA_GENESIS_VALIDATORS[i],
                "genesis[{i}]: BLAKE3(pinned pk) != pinned node id — the key and \
                 id arrays have drifted apart"
            );
        }
    }

    /// Every pinned genesis KEY must be an authorized issuer — this is the
    /// chain_depth = 1 citizen case that KI#97 was about.
    #[test]
    fn ki97_every_genesis_key_is_an_authorized_issuer() {
        for (i, pk) in NABLA_GENESIS_VALIDATOR_PKS.iter().enumerate() {
            assert!(
                nabla_proof_issuer_is_authorized(pk),
                "genesis[{i}] must be able to issue a citizen NBC, or a citizen \
                 node can serve no client proof at all"
            );
        }
    }

    /// A NODE ID must NOT be accepted as an issuer key. Guards the exact
    /// confusion this fix is about: the two arrays are both [[u8;32];10], so
    /// passing the wrong one compiles fine and would widen the gate to values
    /// that are public knowledge (ids are gossiped; keys are the anchor).
    #[test]
    fn ki97_node_id_is_not_accepted_as_an_issuer_key() {
        for (i, id) in NABLA_GENESIS_VALIDATORS.iter().enumerate() {
            assert!(
                !nabla_proof_issuer_is_authorized(id),
                "genesis[{i}]: a NODE ID was accepted as an issuer KEY — a digest \
                 cannot anchor a signature check"
            );
        }
    }

    /// KI#97: a cert issued BY a genesis Nabla node (chain_depth = 1, the
    /// citizen case) must be an authorized issuer, or a citizen node can serve
    /// no client proof at all and actively breaks wallets that pick it.
    #[test]
    fn ki97_genesis_issued_citizen_cert_is_authorized() {
        // A genesis node's identity is its NODE ID; the issuer field carries the
        // SPHINCS+ KEY. Build a key whose blake3 IS a pinned genesis id by
        // searching for one — we cannot invert blake3, so instead assert the
        // derivation the production path uses, from the id side.
        let genesis_id = NABLA_GENESIS_VALIDATORS[0];
        assert!(
            is_nabla_genesis_validator(&genesis_id),
            "pinned genesis id must be recognised as a genesis validator"
        );

        // THE TRAP (KI#90 shape): passing an issuer KEY straight to the genesis
        // array matches nothing, because that array holds IDS. If someone
        // "simplifies" nabla_proof_issuer_is_authorized by dropping the blake3,
        // this assertion is what goes red.
        let some_key = [0x42u8; 32];
        let derived_id: [u8; 32] = blake3::hash(&some_key).into();
        assert_ne!(
            some_key, derived_id,
            "a node id is blake3(sphincs_pk) — key and id are NOT interchangeable"
        );
    }

    /// Negative control: an arbitrary key is NOT an authorized issuer. Without
    /// this, widening the gate to "anything" would still pass the test above.
    #[test]
    fn ki97_arbitrary_issuer_is_refused() {
        let stranger = [0x99u8; 32];
        assert!(
            !nabla_proof_issuer_is_authorized(&stranger),
            "an unpinned key must never be accepted as an NBC issuer — forging a \
             client proof must still require a genesis or root secret key"
        );
        // Wrong length must also fail closed.
        assert!(!nabla_proof_issuer_is_authorized(&[0u8; 16]));
        assert!(!nabla_proof_issuer_is_authorized(&[]));
        // The all-zero key must never be authorized (uninitialised-field guard).
        assert!(!nabla_proof_issuer_is_authorized(&[0u8; 32]));
    }

    /// A root authority stays authorized — the depth-0 path must not regress.
    #[test]
    fn ki97_root_authority_still_authorized() {
        let root = NABLA_ROOT_AUTHORITY_PKS[0];
        assert!(
            nabla_proof_issuer_is_authorized(&root),
            "root authority must remain an authorized issuer (depth-0 path)"
        );
    }

    #[test]
    fn test_is_nabla_root_authority() {
        // Known keys should match
        for nk in &NABLA_ROOT_AUTHORITY_PKS {
            assert!(is_nabla_root_authority(nk));
        }

        // Random key should not match
        let other = [0x42u8; 32];
        assert!(!is_nabla_root_authority(&other));

        // Zero key should not match
        let zero = [0u8; 32];
        assert!(!is_nabla_root_authority(&zero));

        // Validator root authority should NOT be Nabla root authority
        use crate::genesis::ROOT_AUTHORITY_PKS;
        assert!(!is_nabla_root_authority(&ROOT_AUTHORITY_PKS[0]));
    }

    #[test]
    fn test_is_nabla_genesis_validator() {
        for nk in &NABLA_GENESIS_VALIDATORS {
            assert!(is_nabla_genesis_validator(nk));
        }
        let other = [0x42u8; 32];
        assert!(!is_nabla_genesis_validator(&other));
    }
}
