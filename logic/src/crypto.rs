//! Cryptographic primitives for AXIOM Core
//!
//! Hash functions:
//! - BLAKE3: txid, wallet_id checksum (fast)
//! - SHA3-256: state_hash, genesis_state_id (cryptographic integrity)
//!
//! This module is private (`mod crypto`) — external crates access only
//! verification functions via `axiom_core_logic::verify::*`.
#![allow(dead_code)]
//! - CRC32C: CB corruption detection
//!
//! Signatures (3-tier operational):
//! - Ed25519: Standard operational signing (fast, 64-byte sigs)
//! - Dilithium (ML-DSA-65): Quantum-resistant operational signing (3,309-byte sigs)
//! - SPHINCS+ (SLH-DSA-SHA2-128s): Maximum security operational signing (7,856-byte sigs)
//!
//! VBC signatures (mandatory):
//! - SPHINCS+ only — hash-only security assumption for long-lived trust anchors

// CONSENSUS_CRITICAL

use alloc::vec::Vec;
use crate::errors::CoreResult;
use crate::types::ValidationError;
use tiny_keccak::{Hasher, Sha3};

/// BLAKE3 hash - used for txid and wallet_id checksum
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// SHA3-256 hash - used for state_hash and genesis_state_id
pub fn sha3_256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3::v256();
    hasher.update(data);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

// ============================================================================
// AXIOM Domain-Specific Commitments
// ============================================================================
// ALL hash computations for AXIOM protocol MUST live here in Core.
// Lambda MUST NOT compute any of these directly.
// "Core is the bible" — no bypasses, no fallbacks.

/// Compute validator_id from SPHINCS+ public key
/// validator_id = BLAKE3(sphincs_pk)
pub fn compute_validator_id(sphincs_pk: &[u8]) -> [u8; 32] {
    *blake3::hash(sphincs_pk).as_bytes()
}

/// Compute receipt commitment — binds the receipt SKELETON into a single
/// hash that k validators sign. The skeleton is invariant across every
/// hop of the serial witness round, so every validator signs the same
/// commitment.
///
/// The skeleton is the set of fields each validator can independently
/// observe at its own witness-sign time without needing the OTHER
/// validators' contributions:
///   - `txid` (cheque-bound)
///   - `state_hash` (cheque-bound)
///   - `new_wallet_seq` (deterministic from receiver's prev_receipt)
///   - `commitment_hash` (cheque-bound)
///   - `epoch` (cheque-bound)
///
/// `produced_state_id` and `fee_breakdown` are NOT bound here. Both
/// depend on aggregate fee math (`new_balance = current + amount −
/// sum(slots)`) which is only fully known after all k WitnessSigs are
/// collected. Binding them would force hop 1 to know hops 2..k's
/// slots — structurally impossible in a serial round.
///
/// Defense in depth (each piece is signed by the validator it pays,
/// stronger than the prior single-aggregate-signature design):
///   - Each `WitnessSig` self-attests `(rate_bps, slot_amount)` via
///     `verify_slot_math` in that validator's own Core at sign time.
///   - `verify_receipt_fee_breakdown` confirms `receipt.fee_breakdown[i]`
///     matches `witness_sigs[i].slot_amount` in parallel order.
///   - Downstream CL2 recomputes `produced_state_id` from
///     `receipt.new_balance + ...` and asserts equality — tampering
///     with the SDK-assembled new_balance is detected at the
///     consumer-side recomputation.
///   - CL5's `ConservationViolation` check binds `total_fee +
///     net_to_receiver == amount`.
///
/// Domain tag "AXIOM_RECEIPT_v1" ensures no cross-protocol confusion.
pub fn compute_receipt_commitment(
    txid: &[u8; 32],
    state_hash: &[u8; 32],
    new_wallet_seq: u64,
    commitment_hash: &[u8; 32],
    epoch: u64,
    is_dev_class: bool,
    oods_flag: Option<&crate::types::OodsFlag>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_RECEIPT_v1");
    hasher.update(txid);
    hasher.update(state_hash);
    hasher.update(&new_wallet_seq.to_le_bytes());
    hasher.update(commitment_hash);
    hasher.update(&epoch.to_le_bytes());
    // `is_dev_class` — dev-class isolation flag
    // (`AXIOM_DESIGN_FactClassIsolation.md` + dev-pool routing,
    // landed 2026-06-05). Folded into the commitment so k=3 sigs
    // cryptographically attest to the class — a forged or
    // post-hoc-edited flag invalidates every witness sig.
    // No version bump per CLAUDE.md §13 (pre-mainnet, every
    // format is "current"); old data dirs are wiped at deploy
    // time, the soak start sequence already wipes per CoreID
    // rotation.
    hasher.update(&[is_dev_class as u8]);
    // YPX-021 §8.2 — the OODS health flag. PRESENCE and values are both
    // bound: a receipt stamped under an eclipse (`healthy = false`)
    // cannot have its flag stripped or flipped after the k witnesses
    // signed, and a flag cannot be forged onto a flagless receipt.
    // Landed 2026-07-03; rotates the CoreID (inherent — the value must
    // be Core-attested, YPX-021 §8.1).
    match oods_flag {
        Some(f) => {
            hasher.update(&[1u8]);
            hasher.update(&f.tick.to_le_bytes());
            hasher.update(&f.oods_size.to_le_bytes());
            hasher.update(&[f.healthy as u8]);
        }
        None => {
            hasher.update(&[0u8]);
        }
    }
    *hasher.finalize().as_bytes()
}

/// YPX-021 §8.2 — canonical signing payload for a `NablaOodsAttestation`.
///
/// The attesting Nabla's Ed25519 key signs this hash. Bound fields: the
/// live reading (`oods_size`, `tick`) and the node's NBC baseline
/// (`baseline_size`, `baseline_tick`) — so a relayer cannot re-pair a
/// healthy live reading with someone else's baseline.
pub fn compute_oods_attestation_payload(
    oods_size: u32,
    tick: u64,
    baseline_size: u32,
    baseline_tick: u64,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_OODS_ATTEST");
    h.update(&oods_size.to_le_bytes());
    h.update(&tick.to_le_bytes());
    h.update(&baseline_size.to_le_bytes());
    h.update(&baseline_tick.to_le_bytes());
    *h.finalize().as_bytes()
}

/// YPX-022 RECALL attestation signing payload (§2.2). Binds the recalled txid + tick.
pub fn compute_recall_attestation_payload(
    txid: &[u8; 32],
    presend_state_hash: &[u8; 32],
    amount: u64,
    recall_tick: u64,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_RECALL_ATTEST");
    h.update(txid);
    h.update(presend_state_hash);
    h.update(&amount.to_le_bytes());
    h.update(&recall_tick.to_le_bytes());
    *h.finalize().as_bytes()
}

/// YP §19.6 — canonical signing payload for
/// `MarkValidatorEarningsClaimedRequest`.
///
/// k Lambda witnesses sign this hash to attest that they ran the
/// withdrawal round for `validator_id` and the claim is final through
/// `claimed_through_tick`. Nabla verifies ≥3 distinct valid signatures
/// before advancing `last_claimed_tick`. Bound fields: validator_id +
/// claimed_through_tick (so an old attestation can't be replayed as a
/// new claim).
pub fn compute_validator_claim_payload(
    validator_id: &[u8; 32],
    claimed_through_tick: u64,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_VALIDATOR_CLAIM_v1");
    h.update(validator_id);
    h.update(&claimed_through_tick.to_le_bytes());
    *h.finalize().as_bytes()
}

/// YP §20.10 — canonical signing payload for
/// `ValidatorWithdrawalRequest`.
///
/// The validator's SPHINCS+ key signs this hash to authorise the
/// specific (validator_id, attestation, witnesses) tuple. Lambda's
/// withdrawal handler verifies the sig before initiating the witness
/// round. Binding `chosen_witnesses` means the operator commits to
/// the specific k validators they picked — Lambda can't quietly
/// substitute, and a replayed sig can't pick different witnesses.
///
/// `attestation_hash` is the BLAKE3 of the canonical earnings payload
/// (`compute_earnings_attestation_payload`). Folding the hash (not the
/// whole response) keeps the payload small while still binding the
/// withdrawal to the specific signed earnings.
pub fn compute_validator_withdrawal_payload(
    validator_id: &[u8; 32],
    attestation_hash: &[u8; 32],
    chosen_witnesses: &[[u8; 32]],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_VALIDATOR_WITHDRAWAL_v1");
    h.update(validator_id);
    h.update(attestation_hash);
    h.update(&(chosen_witnesses.len() as u32).to_le_bytes());
    for wid in chosen_witnesses {
        h.update(wid);
    }
    *h.finalize().as_bytes()
}

/// YP §20.10 / fee ledger Step 9B.3 — canonical signing payload for the
/// chosen-witness mint approval. Each chosen-witness Lambda signs this
/// hash with its Ed25519 key after Core CL13 accepts the proof. Operator
/// collects k=3 of these and persists them on the mint receipt.
///
/// Binds the four fields the mint result determines:
/// - `validator_id` — whose pool is being drained;
/// - `linked_wallet_id` — where the atoms land;
/// - `net_amount` — exactly how many atoms;
/// - `claimed_through_tick` — Nabla's `last_claimed_tick` advances here.
///
/// Domain tag `AXIOM_WITHDRAWAL_MINT_v1`. A consumer that sees the same
/// tag with a different field layout (future v2) rejects — no
/// `serde(default)` fallback.
pub fn compute_withdrawal_mint_commitment(
    validator_id: &[u8; 32],
    linked_wallet_id: &[u8; 32],
    net_amount: u64,
    claimed_through_tick: u64,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_WITHDRAWAL_MINT_v1");
    h.update(validator_id);
    h.update(linked_wallet_id);
    h.update(&net_amount.to_le_bytes());
    h.update(&claimed_through_tick.to_le_bytes());
    *h.finalize().as_bytes()
}

/// YP §20.10 — primitive: check the conflict-of-interest exclusion.
///
/// Given an earnings response's `entries` (each entry carries the full
/// fee_breakdown of every witnessing validator on that TX), and a set
/// of `chosen_witnesses` the withdrawing operator picked for this
/// withdrawal round, returns `true` if the choice satisfies §20.10:
/// no chosen witness appears in any entry's fee_breakdown.
///
/// Equivalent to:
///   `chosen ∩ ⋃ᵢ {entries[i].full_fee_breakdown[j].validator_id} = ∅`
///
/// Lambda's withdrawal handler rejects when this returns false.
pub fn check_validator_withdrawal_conflict(
    entries: &[crate::wire_client::EarningsEntry],
    chosen_witnesses: &[[u8; 32]],
) -> bool {
    use alloc::collections::BTreeSet;
    let mut excluded: BTreeSet<[u8; 32]> = BTreeSet::new();
    for e in entries {
        for share in &e.full_fee_breakdown {
            excluded.insert(share.validator_id);
        }
    }
    for w in chosen_witnesses {
        if excluded.contains(w) {
            return false;
        }
    }
    true
}

/// YP §19.6 — canonical signing payload for `RegisterValidatorPoolRequest`.
///
/// The validator's SPHINCS+ key signs this hash to authorise binding
/// `validator_id`'s fee pool to `linked_wallet_id` at `linkage_epoch`.
/// Binding includes `linkage_epoch` so a re-link signature can't be
/// replayed to revert to an earlier linkage; and `tick` for freshness so
/// an attacker can't bank an old signature for future use.
///
/// Domain tag "AXIOM_VALIDATOR_POOL_LINK_v1" prevents cross-protocol
/// confusion (the same SPHINCS+ key signs other artifacts — VBC,
/// possibly future ones).
pub fn compute_validator_pool_link_payload(
    validator_id: &[u8; 32],
    linked_wallet_id: &[u8; 32],
    linkage_epoch: u64,
    tick: u64,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_VALIDATOR_POOL_LINK_v1");
    h.update(validator_id);
    h.update(linked_wallet_id);
    h.update(&linkage_epoch.to_le_bytes());
    h.update(&tick.to_le_bytes());
    *h.finalize().as_bytes()
}

/// YP §19.6 — canonical signing payload for a Nabla-node-attested
/// `QueryValidatorEarningsResponse`. Sign with the Nabla node's Ed25519
/// key; consumers verify with `nabla_node_pk` (chained back to a Nabla
/// root authority via NBC). Binds every field a malicious responder could
/// shift: node identity, validator identity, window bounds, total, the
/// authoritative flag, and every per-tx entry (including the FULL
/// fee_breakdown per entry — required for §20.10 enforcement) in
/// declared (deterministic) order.
///
/// `entries` MUST be sorted by tick ascending then tx_hash lex — the
/// `SparseMerkleTree::validator_earnings` accessor already returns this
/// order, so two honest hashmap nodes produce byte-identical payloads
/// for the same query.
///
/// Step 8.3.A extension: each entry now carries its full fee_breakdown,
/// hashed in declared order (validator_id || amount). The domain tag
/// is updated to v2 since the binding shape changed — `v1` is gone.
pub fn compute_earnings_attestation_payload(
    nabla_node_id: &[u8; 32],
    validator_id: &[u8; 32],
    since_tick: u64,
    until_tick: u64,
    total_amount: u64,
    entries: &[crate::wire_client::EarningsEntry],
    is_authoritative: bool,
    net_balance: u64,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_NABLA_EARNINGS_ATTEST_v2");
    h.update(nabla_node_id);
    h.update(validator_id);
    h.update(&since_tick.to_le_bytes());
    h.update(&until_tick.to_le_bytes());
    h.update(&total_amount.to_le_bytes());
    h.update(&[is_authoritative as u8]);
    h.update(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        h.update(&e.tx_hash);
        h.update(&e.amount.to_le_bytes());
        h.update(&e.tick.to_le_bytes());
        h.update(&(e.full_fee_breakdown.len() as u32).to_le_bytes());
        for share in &e.full_fee_breakdown {
            h.update(&share.validator_id);
            h.update(&share.amount.to_le_bytes());
        }
    }
    // PR4 (DEED Step 9B) — authoritative NET cap from Nabla's
    // ValidatorNetLedger. Bound at the END of the payload so older
    // pre-PR4 attestations (which signed with net_balance=0 implicitly)
    // round-trip cleanly — verifying a fresh attestation with
    // net_balance=0 against this function reproduces the byte sequence
    // a pre-PR4 signer would have produced.
    h.update(&net_balance.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Compute produced_state_id for witness (send) operation
/// SHA3-256("AXIOM_STATE" || pk || new_balance || new_seq || consumed_state_id || nonce)
pub fn compute_produced_state_id(
    pk: &[u8],
    new_balance: u64,
    new_seq: u64,
    consumed_state_id: &[u8],
    nonce: u64,
) -> [u8; 32] {
    let mut hasher = Sha3::v256();
    hasher.update(b"AXIOM_STATE");
    hasher.update(pk);
    hasher.update(&new_balance.to_le_bytes());
    hasher.update(&new_seq.to_le_bytes());
    hasher.update(consumed_state_id);
    hasher.update(&nonce.to_le_bytes());
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

/// Compute produced_state_id from transaction and current balance.
/// Core does all balance math. Lambda MUST NOT compute balance.
///
/// Returns (produced_state_id, new_balance) — Lambda stores new_balance
/// in tx_record for future S-ABR lookups but never computes it.
// SECURITY-BAL: Balance subtraction — checked_sub prevents underflow/fund destruction
pub fn compute_produced_state_from_tx(
    pk: &[u8],
    current_balance: u64,
    amount: u64,
    wallet_seq: u64,
    consumed_state_id: &[u8],
    nonce: u64,
) -> ([u8; 32], u64) {
    // HIGH-4 fix: checked_sub instead of saturating_sub (YP §17.2 spec compliance).
    // Both produce 0 on underflow, but checked_sub makes the intent explicit:
    // "we checked, it underflowed, we default to 0" vs saturating_sub's silent clamp.
    // Validation catches underflow before this point (InsufficientBalance); this is defense-in-depth.
    #[allow(clippy::manual_saturating_arithmetic)]
    let new_balance = current_balance.checked_sub(amount).unwrap_or(0);
    let state_id = compute_produced_state_id(pk, new_balance, wallet_seq, consumed_state_id, nonce);
    (state_id, new_balance)
}

/// Compute state hash after transaction
/// BLAKE3(pk || new_balance || new_seq)
pub fn compute_state_hash(pk: &[u8], new_balance: u64, new_seq: u64, hibernation_until: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(pk);
    hasher.update(&new_balance.to_le_bytes());
    hasher.update(&new_seq.to_le_bytes());
    // YPX-020 — bind hibernation into the witnessed state commitment so Core CL2
    // can enforce it tamper-evidently. Appended last (edit-in-place convention);
    // `0` for a non-hibernating wallet. Formula change → clean --data this rotation.
    hasher.update(&hibernation_until.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Compute cheque commitment — the canonical function. No version tag in
/// the domain string. AXIOM is pre-mainnet (CLAUDE.md §13): every wire
/// format is "current"; the only legacy is bugs. A new field gets added
/// to this commitment by editing it in place — no `_v2` next to a `_v3`,
/// no domain-string `_VN` suffix, no migration layer.
///
/// `BLAKE3("AXIOM_CHEQUE" || txid || state_hash || produced_state_id ||
///         receiver_wallet_id || amount || epoch || rate_bps_le ||
///         dmap_input_hash || dmap_output_hash || optional ORACLE block)`
///
/// `rate_bps` was added 2026-06-05 PM — the validator signs its own
/// rate at cheque-issuance time so Core CL5 can read it authoritatively
/// at redeem time and compute `total_fee` without trusting any
/// client-supplied proposal. Closes the `E_RECEIPT_COMMITMENT_MISMATCH`
/// class.
///
/// Design note (H2): The commitment does NOT include validator_id or signing
/// timestamp. This is intentional: the commitment binds to transaction DATA
/// (what was witnessed), not to validator SESSION (who witnessed it). A
/// cheque signed by a validator whose VBC later expires is still valid —
/// the data it attests is correct. The VBC bundle carried alongside
/// provides auditability but is not part of the signed message.
#[allow(clippy::too_many_arguments)] // Architectural: cheque commitment binds 9 distinct fields
pub fn compute_cheque_commitment(
    txid: &[u8; 32],
    state_hash: &[u8; 32],
    produced_state_id: &[u8; 32],
    receiver_wallet_id: &str,
    amount: u64,
    epoch: u64,
    rate_bps: u32,
    dmap_input_hash: &[u8; 32],
    dmap_output_hash: &[u8; 32],
    oracle_claim: Option<&crate::types::OracleClaimData>,
    recall_target_tx_id: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_CHEQUE");
    hasher.update(txid);
    hasher.update(state_hash);
    hasher.update(produced_state_id);
    hasher.update(receiver_wallet_id.as_bytes());
    hasher.update(&amount.to_le_bytes());
    hasher.update(&epoch.to_le_bytes());
    hasher.update(&rate_bps.to_le_bytes());
    hasher.update(dmap_input_hash);
    hasher.update(dmap_output_hash);
    // GAP-O1: Oracle fields bound to commitment — prevents payout_amount tampering.
    if let Some(claim) = oracle_claim {
        hasher.update(b"ORACLE");
        hasher.update(&claim.payout_amount.to_le_bytes());
        hasher.update(&claim.credit_delta.to_le_bytes());
        hasher.update(claim.platform_url.as_bytes());
    }
    // YPX-022 RECALL: bind the recalled txid so a client cannot forge the recall
    // linkage the genesis-guard exemption keys on. Non-zero suffix ONLY — a normal
    // (non-recall) cheque appends nothing, so its commitment is byte-identical.
    if let Some(t) = recall_target_tx_id {
        hasher.update(b"RECALL");
        hasher.update(t);
    }
    // Note on dev-class isolation: `is_dev_class` lives on `Receipt`
    // (folded into `compute_receipt_commitment`), NOT on the cheque.
    // The cheque already carries `sender_wallet_id` (line 1076 of
    // types.rs) which is implicitly bound via the txid the
    // commitment covers; receiver's Core CL5 derives the class via
    // `is_dev_wallet(cheque.sender_wallet_id)` per cheque, asserts
    // all cheques in the bundle agree, and bakes the result into
    // the redeem-receipt commitment. The Nabla credit-routing
    // gate is therefore at receipt-level, not cheque-level —
    // a strictly smaller surface than threading the field everywhere.
    *hasher.finalize().as_bytes()
}


/// Derive DEED wallet ID from genesis ceremony SPHINCS+ public key.
///
/// BLAKE3("AXIOM_DEED_WALLET_V1" || genesis_sphincs_pk) → 32 bytes.
/// The first 8 hex chars of this hash are the DEED address suffix:
/// "DEED/<hex8>". Set `AXIOM_DEED_ADDRESS` env var at build time to
/// this value for production builds.
///
/// # Example
/// ```ignore
/// let pk = /* genesis SPHINCS+ public key from ceremony */;
/// let wallet_id = compute_deed_wallet_id(&pk);
/// // Then set AXIOM_DEED_ADDRESS="DEED/<hex8>" in .cargo/config.toml
/// ```
pub fn compute_deed_wallet_id(genesis_sphincs_pk: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_DEED_WALLET_V1");
    hasher.update(genesis_sphincs_pk);
    *hasher.finalize().as_bytes()
}

/// Format DEED wallet ID hash as a human-readable DEED address string.
/// Returns "DEED/<first 8 hex chars of hash>".
pub fn format_deed_address(deed_hash: &[u8; 32]) -> alloc::string::String {
    let hex_str = hex::encode(&deed_hash[..4]);
    alloc::format!("DEED/{}", hex_str)
}

/// Compute transaction ID from Transaction struct
/// BLAKE3("AXIOM_TXID" || consumed_state_id || client_pk || wallet_seq || receiver_wallet_id || amount || nonce || epoch)
///
/// Uses canonical field ordering — NOT JSON serialization.
/// This is the authoritative txid computation. Lambda MUST use this.
// SECURITY-HASH: Domain-tagged BLAKE3 txid — "AXIOM_TXID" prefix prevents cross-protocol replay
pub fn compute_txid(tx: &crate::types::Transaction) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_TXID");
    hasher.update(&tx.consumed_state_id);
    hasher.update(&tx.client_pk);
    hasher.update(&tx.wallet_seq.to_le_bytes());
    hasher.update(tx.receiver_wallet_id.as_bytes());
    hasher.update(&tx.amount.to_le_bytes());
    hasher.update(&tx.nonce.to_le_bytes());
    hasher.update(&tx.epoch.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// YPX-001 §1.5.1 — scar-consent voucher signing payload.
/// BLAKE3("AXIOM_SCAR_CONSENT_OK" || txid). Signed (Ed25519, witness key)
/// by the validator that verified the receiver's passcode; verified by the
/// round's other overlapped validators against the prev-receipt witness
/// set. Domain-tagged so the signature can never be confused with a
/// witness/receipt signature over the same txid.
pub fn compute_scar_consent_voucher_payload(txid: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_SCAR_CONSENT_OK");
    hasher.update(txid);
    *hasher.finalize().as_bytes()
}

/// Compute redeem request commitment for receiver signature verification
/// BLAKE3("AXIOM_REDEEM" || txid || receiver_pk)
pub fn compute_redeem_request_commitment(
    txid: &[u8; 32],
    receiver_pk: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_REDEEM");
    hasher.update(txid);
    hasher.update(receiver_pk);
    *hasher.finalize().as_bytes()
}

/// Compute ACK commitment for client signature verification.
/// v3.x (YP §20.8): no fee_amount in the commitment.
/// BLAKE3("AXIOM_ACK_v3" || txid || validator_pk)
pub fn compute_ack_fee_commitment(
    txid: &[u8; 32],
    validator_pk: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_ACK_v3");
    hasher.update(txid);
    hasher.update(validator_pk);
    *hasher.finalize().as_bytes()
}

/// CRC32C checksum - used for CB corruption detection
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x82F63B78;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Compute VBC signing payload hash (v0.9)
///
/// This is what issuers sign when creating a VBC:
///   BLAKE3("AXIOM_VBC_V09" || version || validator_id || sphincs_pk || dilithium_pk ||
///          ed25519_pk || pgp_fingerprint || node_name || issued_at || expires_at || chain_depth || issuer_pks...)
///
/// ALL fields are covered by the signature — nothing can be tampered with.
pub fn compute_vbc_signing_payload(
    vbc: &crate::types::VBC,
) -> [u8; 32] {
    let bytes = compute_vbc_signing_payload_bytes(vbc);
    *blake3::hash(&bytes).as_bytes()
}

/// YPX-018 Phase 5f — return the canonical pre-image bytes that
/// `compute_vbc_signing_payload` hashes. Used in attestation NBC trust
/// anchor verification: the verifier needs the full pre-image (which
/// contains the ed25519_pk literally) to bind the attestation's
/// `nabla_node_pk` to the NBC. The window check
/// `nbc_commitment.windows(32).any(|w| w == nabla_node_pk)` only works
/// when `nbc_commitment` is the pre-image, not the hash output.
///
/// Reference: PHASE 5f security fix to `verify_nbc_for_*_attestation`
/// in `core/logic/src/validation.rs`.
pub fn compute_vbc_signing_payload_bytes(
    vbc: &crate::types::VBC,
) -> alloc::vec::Vec<u8> {
    let mut buf = alloc::vec::Vec::new();
    buf.extend_from_slice(b"AXIOM_VBC_V09");
    buf.push(vbc.version);
    buf.extend_from_slice(&vbc.validator_id);
    buf.extend_from_slice(&vbc.subject_pubkey_sphincs);
    buf.extend_from_slice(&vbc.subject_pubkey_dilithium);
    buf.extend_from_slice(&vbc.subject_pubkey_ed25519);  // ← bound to attestation.nabla_node_pk
    buf.extend_from_slice(&vbc.pgp_fingerprint);
    buf.extend_from_slice(vbc.node_name.as_bytes());
    buf.extend_from_slice(vbc.proof_cap.as_bytes());
    buf.extend_from_slice(&vbc.issued_at.to_le_bytes());
    buf.extend_from_slice(&vbc.expires_at.to_le_bytes());
    buf.push(vbc.chain_depth);
    buf.extend_from_slice(&vbc.max_tx.to_le_bytes());
    for issuer_pk in &vbc.issuer_set {
        buf.extend_from_slice(issuer_pk);
    }
    // YPX-021 §7 — OODS baseline, appended LAST and ONLY when non-zero.
    // Two load-bearing properties of this encoding:
    //   1. Genesis + pre-baseline certs (baseline == 0) keep a
    //      byte-identical pre-image, so their existing issuer signatures
    //      stay valid — the genesis exemption in §7.
    //   2. For baselined certs the 12-byte suffix sits at a FIXED position
    //      (the end), so Core can bind an attestation's claimed baseline
    //      to the issuer-signed cert with a suffix check
    //      (`validation::verify_oods_attestation`) without parsing the
    //      variable-length pre-image.
    if vbc.network_size_baseline != 0 {
        buf.extend_from_slice(&vbc.network_size_baseline.to_le_bytes());
        buf.extend_from_slice(&vbc.baseline_tick.to_le_bytes());
    }
    buf
}

// ============================================================================
// Ed25519 (Standard operational signing)
// ============================================================================

/// Verify an Ed25519 signature
// SECURITY-SIG: Ed25519 signature verification — rejects forged operational signatures
pub fn verify_ed25519(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CoreResult<()> {
    use ed25519_dalek::{Signature, VerifyingKey};
    
    if public_key.len() != 32 {
        return Err(ValidationError::InvalidClientSignature);
    }
    if signature.len() != 64 {
        return Err(ValidationError::InvalidClientSignature);
    }
    
    let pk_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| ValidationError::InvalidClientSignature)?;
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| ValidationError::InvalidClientSignature)?;
    
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| ValidationError::InvalidClientSignature)?;
    let sig = Signature::from_bytes(&sig_bytes);

    // SEC-12a: verify_strict rejects malleable signatures (non-canonical R
    // and small-order public keys) that the permissive `verify` accepts.
    // Honestly-generated Ed25519 signatures pass verify_strict unchanged;
    // this only closes the malleability surface (two distinct sig encodings
    // for one message) for free. No protocol path treats signature bytes as
    // an identity/dedup token today, but strict verification removes the
    // smell at the sole authority.
    verifying_key
        .verify_strict(message, &sig)
        .map_err(|_| ValidationError::InvalidClientSignature)
}

// ============================================================================
// YPX-018 — CLARA attestation message + signature verification
// ============================================================================

/// Compute the canonical message hash for a `ClaraAttestation` (YPX-018 §2.2).
///
/// This is what the Nabla node signs and what validators verify against:
///
/// ```text
/// BLAKE3(
///     "AXIOM_CLARA_ATTEST" ||
///     wallet_pk ||
///     healed_from_state_id ||
///     healed_to_state_id ||
///     healed_at_seq.to_le_bytes() ||
///     heal_txid ||
///     garbage_count.to_le_bytes() ||
///     garbage_state_ids[0..n] ||
///     bloom_era_id.to_le_bytes() ||
///     bloom_era_root ||
///     nabla_tick.to_le_bytes()
/// )
/// ```
///
/// All fields are flat. No serialization needed. Works in both host (AVM
/// interpreter) and RISC-V guest (zkVM). The `wallet_pk` is bound into the
/// message, so a CLARA attestation cannot be replayed across wallets.
pub fn compute_clara_message(
    att: &crate::types::ClaraAttestation,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_CLARA_ATTEST");
    hasher.update(&att.wallet_pk);
    hasher.update(&att.healed_from_state_id);
    hasher.update(&att.healed_to_state_id);
    hasher.update(&att.healed_at_seq.to_le_bytes());
    hasher.update(&att.heal_txid);
    let garbage_count = att.garbage_state_ids.len() as u64;
    hasher.update(&garbage_count.to_le_bytes());
    for gs in &att.garbage_state_ids {
        hasher.update(gs);
    }
    hasher.update(&att.bloom_era_id.to_le_bytes());
    hasher.update(&att.bloom_era_root);
    hasher.update(&att.nabla_tick.to_le_bytes());
    // YPX-018 Phase 5f Finding 4: bind healed_balance into the signed message
    // so a previously poisoned validator can trust it during roll-forward.
    // Old attestations (pre-Phase-5f) used `healed_balance: 0` via serde
    // default — those still verify because the same default is hashed.
    // The cryptographic provenance of healed_balance comes from the heal
    // cheque's state_hash binding, verified by Nabla in register_clara
    // before the signed attestation is produced.
    hasher.update(&att.healed_balance.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Verify a `ClaraAttestation`'s Nabla Ed25519 signature.
///
/// This verifies the signature only. The caller is responsible for:
/// - Verifying the NBC trust anchor (`verify_nbc_for_clara_attestation`)
/// - Checking `wallet_pk` matches the witness request's wallet
/// - Performing the roll-forward eligibility check (stored state must be
///   in `garbage_state_ids`)
///
/// Reference: YPX-018 §2.3.
pub fn verify_clara_signature(
    att: &crate::types::ClaraAttestation,
) -> CoreResult<()> {
    if att.garbage_state_ids.is_empty() {
        return Err(ValidationError::ClaraEmptyGarbage);
    }
    let msg = compute_clara_message(att);
    verify_ed25519(&att.nabla_node_pk, &msg, &att.nabla_signature)
        .map_err(|_| ValidationError::ClaraInvalidSignature)
}

// ============================================================================
// Dilithium / ML-DSA-65 (Quantum-resistant operational signing)
// ============================================================================

/// ML-DSA-65 public key size in bytes
pub const ML_DSA_65_PK_SIZE: usize = 1952;

/// ML-DSA-65 secret key size in bytes
pub const ML_DSA_65_SK_SIZE: usize = 4032;

/// ML-DSA-65 signature size in bytes  
pub const ML_DSA_65_SIG_SIZE: usize = 3309;

/// Sign any message with a Dilithium (ML-DSA-65) private key.
///
/// Core is the ONLY component that performs cryptographic operations.
/// Used for: FACT link signing, checkpoint signing (operational quantum-resistant).
/// Dilithium is faster than SPHINCS+ (~1ms vs ~100ms) — suitable for per-TX signing.
///
/// Returns the ML-DSA-65 signature bytes (3,309 bytes).
pub fn sign_dilithium(
    private_key: &[u8],
    message: &[u8],
) -> CoreResult<Vec<u8>> {
    use fips204::ml_dsa_65;
    use fips204::traits::{SerDes, Signer};
    
    if private_key.len() != ML_DSA_65_SK_SIZE {
        return Err(ValidationError::InvalidWitnessSignature);
    }
    
    let sk_array: [u8; ML_DSA_65_SK_SIZE] = private_key
        .try_into()
        .map_err(|_| ValidationError::InvalidWitnessSignature)?;
    
    let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_array)
        .map_err(|_| ValidationError::InvalidWitnessSignature)?;
    
    // Deterministic signing: derive nonce from BLAKE3(sk || message).
    // No getrandom needed — safe inside RISC-V AVM guest.
    let seed = {
        let mut hasher = blake3::Hasher::new();
        hasher.update(private_key);
        hasher.update(message);
        *hasher.finalize().as_bytes()
    };
    let signature = sk.try_sign_with_seed(&seed, message, &[])
        .map_err(|_| ValidationError::InvalidWitnessSignature)?;
    
    Ok(signature.to_vec())
}

/// Verify a Dilithium (ML-DSA-65) signature
// SECURITY-SIG: Dilithium ML-DSA-65 quantum-resistant signature verification
pub fn verify_dilithium(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CoreResult<()> {
    use fips204::ml_dsa_65;
    use fips204::traits::{SerDes, Verifier};
    
    if public_key.len() != ML_DSA_65_PK_SIZE {
        return Err(ValidationError::InvalidWitnessSignature);
    }
    if signature.len() != ML_DSA_65_SIG_SIZE {
        return Err(ValidationError::InvalidWitnessSignature);
    }
    
    let pk_array: [u8; ML_DSA_65_PK_SIZE] = public_key
        .try_into()
        .map_err(|_| ValidationError::InvalidWitnessSignature)?;
    
    let verifying_key = ml_dsa_65::PublicKey::try_from_bytes(pk_array)
        .map_err(|_| ValidationError::InvalidWitnessSignature)?;
    
    let sig_array: [u8; ML_DSA_65_SIG_SIZE] = signature
        .try_into()
        .map_err(|_| ValidationError::InvalidWitnessSignature)?;
    
    let is_valid = verifying_key.verify(message, &sig_array, &[]);
    
    if is_valid {
        Ok(())
    } else {
        Err(ValidationError::InvalidWitnessSignature)
    }
}

// ============================================================================
// SPHINCS+ / SLH-DSA-SHA2-128s (Maximum security, mandatory for VBC)
// ============================================================================

/// SPHINCS+ public key size in bytes (SLH-DSA-SHA2-128s)
pub const SPHINCS_PK_SIZE: usize = 32;

/// SPHINCS+ secret key size in bytes (SLH-DSA-SHA2-128s)
#[allow(dead_code)]
pub const SPHINCS_SK_SIZE: usize = 64;

/// SPHINCS+ signature size in bytes (SLH-DSA-SHA2-128s)
pub const SPHINCS_SIG_SIZE: usize = 7856;

/// Verify a SPHINCS+ (SLH-DSA-SHA2-128s) signature
///
/// Used for VBC signatures (mandatory) and optionally for operational signing.
/// Security relies only on hash function collision resistance.
// SECURITY-SIG: SPHINCS+ maximum-security signature verification (hash-only assumption)
pub fn verify_sphincs(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CoreResult<()> {
    use fips205::slh_dsa_sha2_128s;
    use fips205::traits::{SerDes, Verifier};
    
    if public_key.len() != SPHINCS_PK_SIZE {
        return Err(ValidationError::InvalidVBC);
    }
    if signature.len() != SPHINCS_SIG_SIZE {
        return Err(ValidationError::InvalidVBC);
    }
    
    let pk_array: [u8; SPHINCS_PK_SIZE] = public_key
        .try_into()
        .map_err(|_| ValidationError::InvalidVBC)?;
    
    // fips205 try_from_bytes takes a reference
    let verifying_key = slh_dsa_sha2_128s::PublicKey::try_from_bytes(&pk_array)
        .map_err(|_| ValidationError::InvalidVBC)?;
    
    // fips205 verify expects &[u8; SPHINCS_SIG_SIZE]
    let sig_array: &[u8; SPHINCS_SIG_SIZE] = signature
        .try_into()
        .map_err(|_| ValidationError::InvalidVBC)?;
    
    let is_valid = verifying_key.verify(message, sig_array, b"");
    
    if is_valid {
        Ok(())
    } else {
        Err(ValidationError::InvalidVBC)
    }
}

/// Sign any message with a SPHINCS+ private key.
/// 
/// Core is the ONLY component that performs cryptographic operations.
/// Used for: VBC signing, FACT link signing, checkpoint signing.
/// 
/// Returns the SPHINCS+ signature bytes (7,856 bytes).
pub fn sign_sphincs(
    private_key: &[u8],
    message: &[u8],
) -> CoreResult<Vec<u8>> {
    use fips205::slh_dsa_sha2_128s;
    use fips205::traits::{SerDes, Signer};
    
    if private_key.len() != SPHINCS_SK_SIZE {
        return Err(ValidationError::InvalidVBC);
    }
    
    let sk_array: [u8; SPHINCS_SK_SIZE] = private_key
        .try_into()
        .map_err(|_| ValidationError::InvalidVBC)?;
    
    let sk = slh_dsa_sha2_128s::PrivateKey::try_from_bytes(&sk_array)
        .map_err(|_| ValidationError::InvalidVBC)?;
    
    // fips205 0.4.x: try_sign(message, context, deterministic)
    // Deterministic signing for reproducibility (VBC + FACT checkpoint signatures)
    let signature = sk.try_sign(message, b"", true)
        .map_err(|_| ValidationError::InvalidVBC)?;
    
    Ok(signature.to_vec())
}

/// Sign a VBC commitment with a SPHINCS+ private key (convenience wrapper)
#[allow(dead_code)]
pub fn sign_vbc_commitment(
    private_key: &[u8],
    commitment: &[u8; 32],
) -> CoreResult<Vec<u8>> {
    sign_sphincs(private_key, commitment)
}

// ============================================================================
// Algorithm detection (3-tier)
// ============================================================================

/// Signature algorithm tier
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SignatureAlgorithm {
    /// Standard: Ed25519 (32-byte PK, 64-byte sig)
    Ed25519,
    /// Quantum-Resistant: Dilithium ML-DSA-65 (1952-byte PK, 3309-byte sig)
    Dilithium,
    /// Maximum Security: SPHINCS+ SLH-DSA-SHA2-128s (32-byte PK, 7856-byte sig)
    Sphincs,
}

impl SignatureAlgorithm {
    /// Detect algorithm from public key length
    ///
    /// Note: Ed25519 and SPHINCS+ both have 32-byte public keys.
    /// Ambiguity resolved by context or by checking signature length.
    #[allow(dead_code)]
    pub fn from_public_key(pk: &[u8]) -> Option<Self> {
        match pk.len() {
            32 => Some(Self::Ed25519), // Default for 32-byte PK
            ML_DSA_65_PK_SIZE => Some(Self::Dilithium),
            _ => None,
        }
    }
    
    /// Detect algorithm from signature length (unambiguous)
    pub fn from_signature(sig: &[u8]) -> Option<Self> {
        match sig.len() {
            64 => Some(Self::Ed25519),
            ML_DSA_65_SIG_SIZE => Some(Self::Dilithium),
            SPHINCS_SIG_SIZE => Some(Self::Sphincs),
            _ => None,
        }
    }
}

/// Verify a signature using auto-detection from signature length
// SECURITY-SIG: Auto-detect Ed25519/Dilithium/SPHINCS+ and verify — universal signature gate
pub fn verify_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CoreResult<()> {
    // AUDIT-FIX v2.11.13 (finding 3.6): Empty sig returns E_INVALID_CLIENT_SIG
    // (was E_UNSUPPORTED_SIG_ALG — wrong error code for monitoring tools)
    if signature.is_empty() {
        return Err(ValidationError::InvalidClientSignature);
    }
    match SignatureAlgorithm::from_signature(signature) {
        Some(SignatureAlgorithm::Ed25519) => verify_ed25519(public_key, message, signature),
        Some(SignatureAlgorithm::Dilithium) => verify_dilithium(public_key, message, signature),
        Some(SignatureAlgorithm::Sphincs) => verify_sphincs(public_key, message, signature),
        None => Err(ValidationError::UnsupportedSignatureAlgorithm),
    }
}

/// Verify a VBC signature (SPHINCS+ only — protocol mandate)
pub fn verify_vbc_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CoreResult<()> {
    verify_sphincs(public_key, message, signature)
}

/// Compute burn commitment for signing/verification (YPX-001 §1.5.4).
/// BLAKE3("AXIOM_BURN" || scarred_tx_id || wallet_pk || amount)
///
/// This is signed by k=3 validators when a scarred FACT link is burned.
pub fn compute_burn_commitment(
    scarred_tx_id: &[u8; 32],
    wallet_pk: &[u8],
    amount: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_BURN");
    hasher.update(scarred_tx_id);
    hasher.update(wallet_pk);
    hasher.update(&amount.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Constant-time byte slice comparison.
/// Returns true if slices are equal, without leaking timing information
/// about which bytes differ. Uses XOR accumulation — same technique as
/// the `subtle` crate's ConstantTimeEq.
///
/// Defense-in-depth for AXIOM: email transport has high latency that masks
/// timing, but socket gateways (COUSIN) would be vulnerable without this.
// SECURITY-CT (Constant-Time Comparison):
// XOR-accumulation equality check — always examines every byte, no early exit.
// Prevents timing side-channel attacks on consumed_state_id, produced_state_id,
// validator_pk, and all other security-critical comparisons.
// Ref: Yellow Paper §26.17.1 (constant-time comparisons).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GUARDRAIL — consensus commitments MUST stay core-INDEPENDENT.
    ///
    /// This is the invariant that makes a *routine* Core upgrade transparent:
    /// a receipt/cheque witnessed under Core A must re-verify byte-identically
    /// under Core B, so a healthy wallet carries forward with ZERO migration
    /// code (proven end-to-end by `tests/upgrade_survival.py`; rationale in
    /// `docs/AXIOM_DESIGN_CoreUpgradeMigration.md` "Linux evaluation").
    ///
    /// None of these functions takes a `core_id`/`core_version`, and none folds
    /// one into the hash. If you are here because this test failed, you almost
    /// certainly added a field to one of these commitments. STOP and ask:
    ///   - Did you bind `core_id`/`core_version`? → DON'T. That re-creates the
    ///     self-inflicted "canonical-encoding drift" the migration design feared
    ///     and breaks every wallet on every ELF rebuild (the reverted P1 mistake).
    ///   - Added a legitimate new consensus field (like `is_dev_class` was)?
    ///     → update the golden value below in the SAME commit, regenerate
    ///     `tests/consensus_vectors.json`, and confirm the field is core-
    ///     independent (derivable from tx/receipt data, not from which ELF ran).
    ///
    /// The golden values are fixed byte vectors; they do not depend on the build.
    #[test]
    fn commitments_are_core_independent_golden() {
        // compute_state_hash(pk, balance, seq, hibernation_until)
        let state = compute_state_hash(&[1u8; 32], 1000, 2, 0);
        assert_eq!(
            hex::encode(state),
            // Regenerated 2026-06-19: YPX-020 bound `hibernation_until` into the
            // state commitment (formula change, clean --data this rotation).
            "3a6ae40d255db6f278fa25fdfef80992df08ad3eab9c0a06c4242ce262c50e8e",
            "compute_state_hash changed — see GUARDRAIL doc above"
        );
        // compute_receipt_commitment(txid, state_hash, seq, commitment_hash, epoch, is_dev_class, oods_flag)
        // Golden regenerated 2026-07-03: YPX-021 §8.2 bound the OODS health
        // flag (presence + values) into the receipt commitment — a
        // deliberate formula change (CoreID rotation), NOT core-identity
        // binding. Still takes no core_id/core_version — the core-
        // independence invariant this guardrail protects is intact.
        let receipt = compute_receipt_commitment(&[2u8; 32], &[3u8; 32], 4, &[5u8; 32], 6, false, None);
        assert_eq!(
            hex::encode(receipt),
            "3155997c80aa24d2c2ea4609190a4be19312b95c7178479378165bae80fa94c0",
            "compute_receipt_commitment changed — see GUARDRAIL doc above"
        );
        // With a present flag the commitment must move (presence is bound).
        let flag = crate::types::OodsFlag { tick: 77, oods_size: 1000, healthy: true };
        let receipt_flagged = compute_receipt_commitment(&[2u8; 32], &[3u8; 32], 4, &[5u8; 32], 6, false, Some(&flag));
        assert_ne!(receipt, receipt_flagged, "oods_flag presence must be bound into receipt_commitment");
        // compute_cheque_commitment(txid, state_hash, produced, receiver, amount, epoch, rate_bps, in, out, oracle=None)
        let cheque = compute_cheque_commitment(
            &[7u8; 32], &[8u8; 32], &[9u8; 32], "rcv", 11, 12, 13, &[14u8; 32], &[15u8; 32], None,
            None,
        );
        assert_eq!(
            hex::encode(cheque),
            "15bd55e60d52eeffea69232aced67097660f02fc479c2b9faadb8dac4bcd7863",
            "compute_cheque_commitment changed — see GUARDRAIL doc above"
        );
    }

    #[test]
    fn test_blake3_known_vector() {
        let hash = blake3_hash(b"AXIOM");
        assert_eq!(hash.len(), 32);
    }
    
    #[test]
    fn test_sha3_256_known_vector() {
        let hash = sha3_256_hash(b"AXIOM");
        assert_eq!(hash.len(), 32);
    }
    
    #[test]
    fn test_crc32c() {
        let crc = crc32c(b"LAMB");
        assert_eq!(crc, crc32c(b"LAMB"));
        assert_ne!(crc, crc32c(b"LAMBB"));
    }
    
    /// SEC-12a: verify_ed25519 now uses verify_strict. Confirm an honestly
    /// generated signature still verifies (verify_strict must NOT reject
    /// valid sigs — the regression risk the ticket flags) and a tampered
    /// signature is rejected.
    #[test]
    fn test_ed25519_strict_accepts_honest_rejects_tampered() {
        use ed25519_dalek::{SigningKey, Signer};
        let sk = SigningKey::from_bytes(&[0x37; 32]);
        let pk = sk.verifying_key().to_bytes();
        let msg = b"AXIOM strict verification";
        let sig = sk.sign(msg).to_bytes();

        // Honest signature passes the now-strict verifier.
        assert!(verify_ed25519(&pk, msg, &sig).is_ok());

        // Flip a signature byte → rejected.
        let mut bad = sig;
        bad[10] ^= 0x01;
        assert!(verify_ed25519(&pk, msg, &bad).is_err());

        // Wrong message → rejected.
        assert!(verify_ed25519(&pk, b"different message", &sig).is_err());
    }

    /// SEC-12a — non-canonical-S rejection + a documented dalek-2.1 finding.
    ///
    /// Constructs a malleable, non-canonical-S signature (S + L, L = group
    /// order) and asserts `verify_ed25519` (verify_strict) rejects it.
    ///
    /// FINDING (for the verifier): the verifier suggested a "plain verify()
    /// accepts, verify_strict() rejects" non-canonical-S vector. In
    /// ed25519-dalek **2.1** that premise does NOT hold — the cofactored
    /// `verify` ALSO rejects non-canonical-S (measured: `lenient_accepts=false`
    /// below). So a non-canonical-S vector cannot be a fails-without-fix test in
    /// this dalek version; reverting verify_strict→verify would NOT change the
    /// rejection of this vector. The residual surface verify_strict uniquely
    /// closes over verify in 2.1 is **small-order / torsion-point** signatures,
    /// which require a vetted torsion vector (e.g. "Taming the many EdDSAs"
    /// §5) — deliberately not hand-crafted here to avoid shipping a wrong
    /// crypto vector. The SEC-12a change remains correct, free hardening; no
    /// AXIOM path treats signature bytes as an identity/dedup token, so there is
    /// no reachable behavioral difference on honestly-generated signatures.
    /// This test therefore stands as a regression guard (non-canonical-S stays
    /// rejected) + the printed `lenient_accepts` documents the dalek-2.1 reality.
    #[test]
    fn test_ed25519_strict_rejects_non_canonical_s() {
        use ed25519_dalek::{SigningKey, Signer, Signature, Verifier};
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let vk = sk.verifying_key();
        let pk = vk.to_bytes();
        let msg = b"AXIOM malleability vector";
        let sig = sk.sign(msg).to_bytes(); // R(32) || S(32), S canonical

        // ed25519 group order L, little-endian.
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let mut mal = sig; // R || (S + L)
        let mut carry = 0u16;
        for i in 0..32 {
            let v = mal[32 + i] as u16 + L[i] as u16 + carry;
            mal[32 + i] = (v & 0xff) as u8;
            carry = v >> 8;
        }
        assert_eq!(carry, 0, "S+L must fit in 32 bytes");

        let lenient_accepts = vk.verify(msg, &Signature::from_bytes(&mal)).is_ok();
        eprintln!("[SEC-12a] dalek 2.1 non-canonical-S: lenient verify accepts={lenient_accepts} (false ⇒ verify already rejects it)");

        // The strict path must reject the non-canonical-S variant...
        assert!(verify_ed25519(&pk, msg, &mal).is_err(),
            "verify_strict must reject non-canonical-S");
        // ...and still accept the canonical signature.
        assert!(verify_ed25519(&pk, msg, &sig).is_ok());
    }

    #[test]
    fn test_algorithm_detection_from_sig() {
        assert_eq!(
            SignatureAlgorithm::from_signature(&[0u8; 64]),
            Some(SignatureAlgorithm::Ed25519)
        );
        assert_eq!(
            SignatureAlgorithm::from_signature(&vec![0u8; ML_DSA_65_SIG_SIZE]),
            Some(SignatureAlgorithm::Dilithium)
        );
        assert_eq!(
            SignatureAlgorithm::from_signature(&vec![0u8; SPHINCS_SIG_SIZE]),
            Some(SignatureAlgorithm::Sphincs)
        );
        assert_eq!(
            SignatureAlgorithm::from_signature(&[0u8; 100]),
            None
        );
    }
    
    #[test]
    fn test_dilithium_wrong_pk_size() {
        let result = verify_dilithium(&[0u8; 100], b"test", &vec![0u8; ML_DSA_65_SIG_SIZE]);
        assert!(matches!(result, Err(ValidationError::InvalidWitnessSignature)));
    }

    #[test]
    fn test_sphincs_wrong_pk_size() {
        let result = verify_sphincs(&[0u8; 100], b"test", &vec![0u8; SPHINCS_SIG_SIZE]);
        assert!(matches!(result, Err(ValidationError::InvalidVBC)));
    }
    
    #[test]
    fn test_sphincs_wrong_sig_size() {
        let result = verify_sphincs(&[0u8; SPHINCS_PK_SIZE], b"test", &[0u8; 100]);
        assert!(matches!(result, Err(ValidationError::InvalidVBC)));
    }
    
    #[test]
    fn test_vbc_signing_payload_deterministic() {
        use crate::types::VBC;
        
        let sphincs_pk = vec![0x42u8; 32];
        let validator_id = *blake3::hash(&sphincs_pk).as_bytes();
        
        let vbc1 = VBC {
            network_size_baseline: 0,
            baseline_tick: 0,
            version: 0x09,
            validator_id,
            subject_pubkey_sphincs: sphincs_pk.clone(),
            subject_pubkey_dilithium: vec![0x55u8; 1952],
            subject_pubkey_ed25519: vec![0xAAu8; 32],
            pgp_fingerprint: vec![],
            node_name: String::new(),
            proof_cap: String::new(),
            issued_at: 1000,
            expires_at: 2000,
            chain_depth: 0,
            issuer_set: vec![vec![0x01; 32], vec![0x02; 32], vec![0x03; 32]],
            signatures: vec![],
            max_tx: 0,
            founding_vbc_hash: [0u8; 32],
        };

        // Same VBC → same payload
        let payload1 = compute_vbc_signing_payload(&vbc1);
        let payload2 = compute_vbc_signing_payload(&vbc1);
        assert_eq!(payload1, payload2);
        
        // Different sphincs_pk → different validator_id → different payload
        let different_pk = vec![0x99u8; 32];
        let vbc2 = VBC {
            validator_id: *blake3::hash(&different_pk).as_bytes(),
            subject_pubkey_sphincs: different_pk,
            ..vbc1.clone()
        };
        let payload3 = compute_vbc_signing_payload(&vbc2);
        assert_ne!(payload1, payload3);
        
        // Different Dilithium PK → different payload
        let vbc3 = VBC {
            subject_pubkey_dilithium: vec![0x66u8; 1952],
            ..vbc1.clone()
        };
        let payload4 = compute_vbc_signing_payload(&vbc3);
        assert_ne!(payload1, payload4);
    }
    
    #[test]
    fn test_sign_vbc_commitment_round_trip() {
        use fips205::slh_dsa_sha2_128s;
        use fips205::traits::SerDes;
        
        // Generate a SPHINCS+ keypair
        let (pk, sk) = slh_dsa_sha2_128s::try_keygen()
            .expect("keygen failed");
        
        let sk_bytes = sk.into_bytes();
        let pk_bytes = pk.into_bytes();
        
        assert_eq!(sk_bytes.len(), SPHINCS_SK_SIZE, "SK size mismatch");
        assert_eq!(pk_bytes.len(), SPHINCS_PK_SIZE, "PK size mismatch");
        
        // Create a commitment (32-byte hash)
        let commitment: [u8; 32] = *blake3::hash(b"test VBC commitment").as_bytes();
        
        // Sign it
        let signature = sign_vbc_commitment(&sk_bytes, &commitment)
            .expect("signing failed");
        
        assert_eq!(signature.len(), SPHINCS_SIG_SIZE, 
            "Signature should be {} bytes, got {}", SPHINCS_SIG_SIZE, signature.len());
        
        // Verify it
        verify_sphincs(&pk_bytes, &commitment, &signature)
            .expect("verification failed — round-trip broken");
        
        // Wrong message should fail
        let wrong_commitment: [u8; 32] = *blake3::hash(b"wrong commitment").as_bytes();
        let result = verify_sphincs(&pk_bytes, &wrong_commitment, &signature);
        assert!(result.is_err(), "Should reject wrong message");
        
        // Wrong key should fail
        let (pk2, _sk2) = slh_dsa_sha2_128s::try_keygen()
            .expect("keygen2 failed");
        let pk2_bytes = pk2.into_bytes();
        let result = verify_sphincs(&pk2_bytes, &commitment, &signature);
        assert!(result.is_err(), "Should reject wrong public key");
    }
    
    #[test]
    fn test_sign_vbc_rejects_wrong_key_size() {
        let commitment: [u8; 32] = [0xAA; 32];
        
        // Too short
        let short_sk = vec![0u8; 32];
        assert!(sign_vbc_commitment(&short_sk, &commitment).is_err());
        
        // Too long
        let long_sk = vec![0u8; 128];
        assert!(sign_vbc_commitment(&long_sk, &commitment).is_err());
        
        // Empty
        assert!(sign_vbc_commitment(&[], &commitment).is_err());
    }

    #[test]
    fn test_compute_deed_wallet_id_deterministic() {
        let pk = vec![0x42u8; 64]; // Fake genesis PK
        let hash1 = compute_deed_wallet_id(&pk);
        let hash2 = compute_deed_wallet_id(&pk);
        assert_eq!(hash1, hash2, "same key must produce same ID");
    }

    #[test]
    fn test_compute_deed_wallet_id_different_keys() {
        let pk1 = vec![0x42u8; 64];
        let pk2 = vec![0x43u8; 64];
        assert_ne!(compute_deed_wallet_id(&pk1), compute_deed_wallet_id(&pk2));
    }

    #[test]
    fn test_format_deed_address() {
        let pk = vec![0x42u8; 64];
        let hash = compute_deed_wallet_id(&pk);
        let addr = format_deed_address(&hash);
        assert!(addr.starts_with("DEED/"), "must start with DEED/");
        assert_eq!(addr.len(), 13, "DEED/ + 8 hex chars = 13");
    }

    #[test]
    fn test_sign_with_the_power_of_the_ancients_is_rejected() {
        let pk = [0u8; 32];
        let message = b"I demand to spend these funds";

        // 64 bytes of pure culinary hex
        let mut ancient_sig = [0u8; 64];
        for chunk in ancient_sig.chunks_exact_mut(4) {
            chunk.copy_from_slice(b"\xDE\xAD\xBE\xEF");
        }

        let result = super::verify_ed25519(&pk, message, &ancient_sig);
        assert_eq!(
            result.err(),
            Some(crate::types::ValidationError::InvalidClientSignature),
            "Delicious, but cryptographically invalid."
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // YPX-018 — CLARA attestation tests (Phase 1)
    // ═══════════════════════════════════════════════════════════════════

    use ed25519_dalek::{SigningKey, Signer};
    use crate::types::ClaraAttestation;

    /// Build a `ClaraAttestation` with a valid Nabla signature for testing.
    fn make_clara(
        wallet_pk: [u8; 32],
        from: [u8; 32],
        to: [u8; 32],
        garbage: Vec<[u8; 32]>,
        nabla_sk: &SigningKey,
    ) -> ClaraAttestation {
        let nabla_pk = nabla_sk.verifying_key().to_bytes();
        let mut att = ClaraAttestation {
            wallet_pk,
            healed_from_state_id: from,
            healed_to_state_id: to,
            healed_at_seq: 7,
            healed_balance: 0,            heal_txid: [0xAA; 32],
            garbage_state_ids: garbage,
            bloom_era_id: 12,
            bloom_era_root: [0xBB; 32],
            nabla_tick: 1_777_000_000,
            nabla_node_pk: nabla_pk,
            nabla_signature: vec![],
            nbc_issuer_pk: vec![],
            nbc_signature: vec![],
            nbc_commitment: vec![],
        };
        let msg = compute_clara_message(&att);
        att.nabla_signature = nabla_sk.sign(&msg).to_bytes().to_vec();
        att
    }

    #[test]
    fn test_clara_message_is_deterministic() {
        let sk = SigningKey::from_bytes(&[0x11; 32]);
        let att = make_clara(
            [0xC1; 32],
            [0xC2; 32],
            [0xC3; 32],
            vec![[0xC4; 32]],
            &sk,
        );
        let m1 = compute_clara_message(&att);
        let m2 = compute_clara_message(&att);
        assert_eq!(m1, m2, "compute_clara_message must be deterministic");
    }

    #[test]
    fn test_clara_message_changes_when_wallet_pk_changes() {
        let sk = SigningKey::from_bytes(&[0x11; 32]);
        let att1 = make_clara([0x01; 32], [0xC2; 32], [0xC3; 32], vec![[0xC4; 32]], &sk);
        let mut att2 = att1.clone();
        att2.wallet_pk = [0x02; 32];
        assert_ne!(
            compute_clara_message(&att1),
            compute_clara_message(&att2),
            "wallet_pk MUST be bound into the signed message (replay protection)"
        );
    }

    #[test]
    fn test_clara_message_changes_when_garbage_changes() {
        let sk = SigningKey::from_bytes(&[0x11; 32]);
        let att1 = make_clara(
            [0xC1; 32], [0xC2; 32], [0xC3; 32], vec![[0xC4; 32]], &sk,
        );
        let mut att2 = att1.clone();
        att2.garbage_state_ids.push([0xC5; 32]);
        assert_ne!(
            compute_clara_message(&att1),
            compute_clara_message(&att2),
            "garbage_state_ids MUST be bound into the message"
        );
    }

    #[test]
    fn test_verify_clara_signature_accepts_valid() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let att = make_clara(
            [0xC1; 32], [0xC2; 32], [0xC3; 32], vec![[0xC4; 32]], &sk,
        );
        verify_clara_signature(&att).expect("valid CLARA must verify");
    }

    #[test]
    fn test_verify_clara_signature_rejects_tampered_garbage() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let mut att = make_clara(
            [0xC1; 32], [0xC2; 32], [0xC3; 32], vec![[0xC4; 32]], &sk,
        );
        // Tamper after signing — adding a garbage entry the Nabla node didn't authorize
        att.garbage_state_ids.push([0xFF; 32]);
        let err = verify_clara_signature(&att).expect_err("tampered must reject");
        assert_eq!(err, ValidationError::ClaraInvalidSignature);
    }

    #[test]
    fn test_verify_clara_signature_rejects_wrong_wallet_pk() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let mut att = make_clara(
            [0xC1; 32], [0xC2; 32], [0xC3; 32], vec![[0xC4; 32]], &sk,
        );
        att.wallet_pk = [0xFE; 32]; // tamper after signing
        let err = verify_clara_signature(&att).expect_err("must reject");
        assert_eq!(err, ValidationError::ClaraInvalidSignature);
    }

    #[test]
    fn test_verify_clara_signature_rejects_empty_garbage() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let mut att = make_clara(
            [0xC1; 32], [0xC2; 32], [0xC3; 32], vec![[0xC4; 32]], &sk,
        );
        att.garbage_state_ids.clear();
        // Recompute and re-sign so we test the empty-check, not a sig mismatch
        let msg = compute_clara_message(&att);
        att.nabla_signature = sk.sign(&msg).to_bytes().to_vec();
        let err = verify_clara_signature(&att).expect_err("empty garbage must reject");
        assert_eq!(err, ValidationError::ClaraEmptyGarbage);
    }

    #[test]
    fn test_verify_clara_signature_rejects_wrong_signer() {
        let real_sk = SigningKey::from_bytes(&[0x42; 32]);
        let evil_sk = SigningKey::from_bytes(&[0x99; 32]);
        let mut att = make_clara(
            [0xC1; 32], [0xC2; 32], [0xC3; 32], vec![[0xC4; 32]], &real_sk,
        );
        // Re-sign with the wrong key (but keep the real Nabla pk in the struct)
        let msg = compute_clara_message(&att);
        att.nabla_signature = evil_sk.sign(&msg).to_bytes().to_vec();
        let err = verify_clara_signature(&att).expect_err("forged sig must reject");
        assert_eq!(err, ValidationError::ClaraInvalidSignature);
    }

    // ═══════════════════════════════════════════════════════════════════
    // YPX-018 — Constitutional limits (Phase 1)
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_constitutional_limits_combined_floor_is_55_years() {
        use crate::types::{
            CONSOLE_TICKS_PER_YEAR, MIN_PHASE_OUT_AGE_TICKS, MIN_PHASE_OUT_GRACE_TICKS,
        };
        // 50 years + 5 years = 55 years
        let combined = MIN_PHASE_OUT_AGE_TICKS + MIN_PHASE_OUT_GRACE_TICKS;
        assert_eq!(combined, 55 * CONSOLE_TICKS_PER_YEAR);
        // Sanity: 55 * 6_311_520 = 347_133_600
        assert_eq!(combined, 347_133_600);
    }

    #[test]
    fn test_min_phase_out_age_is_50_years() {
        use crate::types::{CONSOLE_TICKS_PER_YEAR, MIN_PHASE_OUT_AGE_TICKS};
        assert_eq!(MIN_PHASE_OUT_AGE_TICKS, 50 * CONSOLE_TICKS_PER_YEAR);
        assert_eq!(MIN_PHASE_OUT_AGE_TICKS, 315_576_000);
    }

    #[test]
    fn test_min_phase_out_grace_is_5_years() {
        use crate::types::{CONSOLE_TICKS_PER_YEAR, MIN_PHASE_OUT_GRACE_TICKS};
        assert_eq!(MIN_PHASE_OUT_GRACE_TICKS, 5 * CONSOLE_TICKS_PER_YEAR);
        assert_eq!(MIN_PHASE_OUT_GRACE_TICKS, 31_557_600);
    }

    #[test]
    fn test_txid_status_byte_round_trip() {
        use crate::types::TxidStatus;
        for s in [TxidStatus::NotRedeemed, TxidStatus::Redeemed, TxidStatus::PhasedOut] {
            assert_eq!(TxidStatus::from_byte(s.as_byte()), Some(s));
        }
        // Out-of-range bytes return None
        assert_eq!(TxidStatus::from_byte(3), None);
        assert_eq!(TxidStatus::from_byte(255), None);
    }
}
