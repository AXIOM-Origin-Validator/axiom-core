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
///   - Downstream CL2 recomputes `produced_state_id` from
///     `receipt.new_balance + ...` and asserts equality — tampering
///     with the SDK-assembled new_balance is detected at the
///     consumer-side recomputation.
///   - CL5's `ConservationViolation` check binds `total_fee +
///     net_to_receiver == amount`.
///
/// Domain tag "AXIOM_RECEIPT_v1" ensures no cross-protocol confusion.
/// YPX-009 client state-authorship payload — **the single definition**.
///
/// `BLAKE3("AXIOM_WALLET_STATE" || smt_bucket || new_state || tx_hash)`, signed
/// by the wallet's Ed25519 key. It is what proves a state update was authored
/// by the wallet that owns it, and it gates BOTH replication paths (gossip
/// flood and anti-entropy) since the KI#46 zero-pk flip.
///
/// **Why it lives in Core (2026-08-02, KI#53).** It previously existed TWICE —
/// signer side in `sdk/core/src/state_sig.rs`, verifier side in
/// `nabla/src/gossip.rs` — with no Core-owned definition. They agreed by
/// coincidence of review, not by construction. CLAUDE.md's rule is explicit:
/// anything hashed for cryptographic binding must have EXACTLY ONE builder,
/// and this codebase has been bitten six times by parallel builders drifting
/// (the most recent, KI#38, cost a mesh-wide seq-proof failure). Core is the
/// sole cryptographic authority, so the payload is defined here and both the
/// SDK and Nabla call it.
///
/// The caller passes the **SMT bucket** (`smt_bucket(wallet_id, k_tier)`), not
/// a raw wallet_id — the single-keypair tiers share a wallet_id, so the bucket
/// is what identifies the row being authored.
/// THE single derivation of a Nabla TXID-attestation payload.
///
/// ```text
/// BLAKE3("AXIOM_TXID_ATTEST" || txid || status || nabla_tick_le
///        || origin_bytes || sender_registered_at_tick_le
///        || oods_size_u32_le || oods_healthy_u8 || origin_status_u8)
/// ```
///
/// `oods_size` / `oods_healthy` (ForkSettlement §9h [R53], Core W7a,
/// 2026-09-28): the signing node's own OODS reading and verdict, bound so a
/// relay cannot flip an unhealthy node's attestation to healthy
/// (`oods_healthy_u8` = 0x01 healthy / 0x00 not).
///
/// `origin_status` (ForkSettlement §9p, 2026-09-30, KI#221 residual 1): the
/// node's signed `Vouched` / `Held` / `Unknown` statement about the origin
/// (`origin_status_u8` = `OriginVouchStatus::payload_byte`: 0x00 Unknown /
/// 0x01 Vouched / 0x02 Held), bound so a relay cannot turn a node's `Held`
/// into `Unknown` (or back). Consistency with `origin` is Core's
/// `fact::txid_attestation_origin_consistent`, not this builder's.
///
/// A Nabla node SIGNS this; Core verifies it (CL5 Step 3.5 and
/// `verify_fact_link_internal`'s inherited-resolution loop) and the SDK
/// pre-verifies it — four independent assemblies of one signed value before
/// the 2026-08-02 Pattern 1 sweep. **Never re-implement** (the last hand-rolled
/// copy, a `fact.rs` test, was replaced by this call 2026-09-28).
///
/// `origin` + `sender_registered_at_tick` (YPX-001 §1.5.1b, ForkSettlement §3.2
/// [R11], 2026-09-28) are INSIDE the signed payload so a stored resolution
/// cannot be spliced onto a different origin or re-dated. `origin_bytes` is a
/// FIELD-WISE canonical encoding — deliberately NOT the CBOR of
/// `OriginRecord` (the `WitnessPreimage` serde form is a carrier, never a hash
/// preimage):
///
/// ```text
/// None  → 0x00
/// Some  → 0x01 || kind_u8 (Send=0x00, Redeem=0x01) || epoch_le
///              || consumed_state_id[32] || client_pk[32] || wallet_seq_le
///              || receiver_len_u32_le || receiver_wallet_id_utf8
///              || amount_le || nonce_le
/// ```
///
/// Every integer is little-endian fixed width; the one variable-length field
/// is length-prefixed, so the encoding is injective.
pub fn txid_attest_payload(
    txid: &[u8; 32],
    status: &str,
    nabla_tick: u64,
    origin: Option<&crate::types::OriginRecord>,
    sender_registered_at_tick: u64,
    oods_size: u32,
    oods_healthy: bool,
    origin_status: crate::types::OriginVouchStatus,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_TXID_ATTEST");
    hasher.update(txid);
    hasher.update(status.as_bytes());
    hasher.update(&nabla_tick.to_le_bytes());
    match origin {
        None => {
            hasher.update(&[0x00]);
        }
        Some(o) => {
            hasher.update(&[0x01]);
            let kind: u8 = match o.kind {
                crate::types::LegKind::Send => 0x00,
                crate::types::LegKind::Redeem => 0x01,
            };
            hasher.update(&[kind]);
            hasher.update(&o.epoch.to_le_bytes());
            let p = &o.preimage;
            hasher.update(&p.consumed_state_id);
            hasher.update(&p.client_pk);
            hasher.update(&p.wallet_seq.to_le_bytes());
            hasher.update(&(p.receiver_wallet_id.len() as u32).to_le_bytes());
            hasher.update(p.receiver_wallet_id.as_bytes());
            hasher.update(&p.amount.to_le_bytes());
            hasher.update(&p.nonce.to_le_bytes());
        }
    }
    hasher.update(&sender_registered_at_tick.to_le_bytes());
    hasher.update(&oods_size.to_le_bytes());
    hasher.update(&[oods_healthy as u8]);
    // ForkSettlement §9p (KI#221 residual 1) — the node's signed origin status,
    // one fixed byte (`OriginVouchStatus::payload_byte`, never the serde form).
    // Appended LAST without a domain bump (§13: CoreID rotation instead).
    hasher.update(&[origin_status.payload_byte()]);
    *hasher.finalize().as_bytes()
}

/// THE single derivation of the payload a CLAIMANT signs to register a cheque
/// claim at Nabla (YPX-022 §2.1.2a, KI#205 — the claim is AUTHENTICATED).
/// Public path: `axiom_core_logic::compute::cheque_claim_signing_payload`.
///
/// `BLAKE3("AXIOM_CHEQUE_CLAIM" || cheque_id || client_pk || [k_tier] || wallet_address)`.
///
/// The claimant's wallet signs this with the Ed25519 key `client_pk`; the
/// signature travels as `RegisterChequeClaimRequest::claim_sig`, is verified by
/// the Nabla node before the claim is stored (and by every node that applies
/// the flooded claim), and is then BOUND into the Nabla-signed
/// `ChequeClaimProof` through [`redeem_claim_nabla_payload`] so Core CL5 can
/// verify at redeem time that the claim was made by the key the cheque is
/// addressed to. Binding BOTH `client_pk` and `wallet_address` is what identifies
/// the receiver: the address alone binds only 8 bits of the key (KI#181), the key
/// alone binds no address.
///
/// No version suffix, deliberately (CLAUDE.md §13). SDK signs, Nabla and Core
/// verify — three crates, ONE builder (Pattern 1, KI#55). **Never re-implement.**
pub fn cheque_claim_signing_payload(
    cheque_id: &[u8; 32],
    client_pk: &[u8],
    k_tier: u8,
    wallet_address: &str,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_CHEQUE_CLAIM");
    hasher.update(cheque_id);
    hasher.update(client_pk);
    hasher.update(&[k_tier]);
    hasher.update(wallet_address.as_bytes());
    *hasher.finalize().as_bytes()
}

/// THE single derivation of the payload the Nabla WRITER signs on a successful
/// `register_cheque_claim` — the `ChequeClaimProof::nabla_signature` Core CL5
/// Step 3.5b verifies on every online redeem.
/// Public path: `axiom_core_logic::compute::redeem_claim_nabla_payload`.
///
/// `BLAKE3("AXIOM_REDEEM_CLAIM" || cheque_id || "CLAIMED" || claim_tick_le || claim_sig)`.
///
/// `claim_sig` is the claimant's signature over [`cheque_claim_signing_payload`]
/// (YPX-022 §2.1.2a item 5, KI#205): covering it here is what makes the Core
/// binding hold — a redeem cannot rest on a claim the receiver's key did not
/// make, because the Nabla signature Core checks would not verify over any other
/// `claim_sig`. Before 2026-09-25 this preimage was assembled BY HAND in
/// `modes.rs::execute_cl5` and in `nabla_node.rs` (two builders, in the KI#55
/// baseline); consolidated here so Nabla signs and Core verifies the SAME bytes
/// by construction. **Never re-implement.**
pub fn redeem_claim_nabla_payload(
    cheque_id: &[u8; 32],
    claim_tick: u64,
    claim_sig: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_REDEEM_CLAIM");
    hasher.update(cheque_id);
    hasher.update(b"CLAIMED");
    hasher.update(&claim_tick.to_le_bytes());
    hasher.update(claim_sig);
    *hasher.finalize().as_bytes()
}

/// THE single derivation of the ZKP nonce hash.
///
/// `BLAKE3("AXIOM_ZKP_NONCE" || nonce)`. Produced by the host VM AND by the
/// zkVM guest, then cross-checked by Lambda — three assemblies of one value
/// across the **two-VM boundary**, which is precisely where KI#54's
/// DMAP/ZKP divergence lived. The guest's own header warns that any hash
/// cross-checked by Lambda "MUST use the same function and domain tag as the
/// protocol definition"; it then hand-copied the construction. Consolidated
/// 2026-08-02 (Pattern 1 sweep). **Never re-implement.**
pub fn zkp_nonce_hash(nonce: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_ZKP_NONCE");
    hasher.update(nonce);
    *hasher.finalize().as_bytes()
}

/// THE single derivation of a FACT transition's `tx_hash`.
///
/// `BLAKE3("AXIOM_TXHASH" || previous_state_id || new_state_id)`. Consolidated
/// 2026-08-02 (Pattern 1 sweep) — it was assembled independently in
/// `core/logic/src/fact.rs`, `nabla/src/crypto.rs` and
/// `nabla/src/registration.rs`. **Never re-implement.**
pub fn fact_tx_hash(previous_state_id: &[u8; 32], new_state_id: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_TXHASH");
    h.update(previous_state_id);
    h.update(new_state_id);
    *h.finalize().as_bytes()
}

/// THE single derivation of the payload a Nabla node signs to confirm a FACT
/// link — and that Core re-verifies on every subsequent send.
///
/// `BLAKE3("AXIOM_FACT_CONFIRM" || tx_hash || new_state || tick_le)`.
///
/// The tag carries **no version suffix, deliberately.** It was briefly
/// `_V2` because `committed_at_tick` was added to the preimage (§17.10.5.3).
/// Bumping a domain tag is correct discipline once a protocol is DEPLOYED and
/// two versions must coexist — pre-release there is no population to be
/// compatible with, so the bump bought nothing and cost two things: a
/// permanent version scar in the protocol's naming, and a straggler V1
/// assembly in the group-registration path that was never migrated and could
/// therefore never verify here. One tag, one builder, one field set.
///
/// Nabla SIGNS this and Core VERIFIES it, in different crates — the exact
/// signer/verifier split that produced KI#54. Consolidated 2026-08-02
/// (Pattern 1 sweep) from two independent assemblies. A drift here fails
/// `verify_fact_link` with `FactInvalidSignature` on every subsequent send by
/// any wallet holding a confirmed link — silent, total, and indistinguishable
/// from forgery. **Never re-implement.**
pub fn fact_confirm_payload(
    previous_state_id: &[u8; 32],
    new_state_id: &[u8; 32],
    committed_at_tick: u64,
) -> [u8; 32] {
    let tx_hash = fact_tx_hash(previous_state_id, new_state_id);
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_FACT_CONFIRM");
    h.update(&tx_hash);
    h.update(new_state_id);
    h.update(&committed_at_tick.to_le_bytes());
    *h.finalize().as_bytes()
}

/// THE single derivation of a wallet's SMT bucket.
///
/// Tier addresses of one key SHARE a bucket: `k_tier == 3` (Standard) is the
/// identity, every other tier hashes. The bucket is the FIRST INPUT to
/// [`client_state_sign_payload`], so a wallet's registration signature is only
/// verifiable if the signer and the verifier derive the bucket identically.
///
/// Consolidated 2026-08-02 (Pattern 1 sweep). It previously had TWO
/// byte-identical implementations — `nabla/src/registration.rs` and
/// `sdk/core/src/state_sig.rs`. KI#53 unified the payload and left its own
/// first input duplicated; a drift in either copy would have made every
/// honest wallet's register fail to verify, which reads as an attack rather
/// than a bug. **Never re-implement this.**
pub fn smt_bucket(wallet_id: &[u8; 32], k_tier: u8) -> [u8; 32] {
    // YP §16.14.12 v2.19.0 — the bucket is the STATE CLASS: every online
    // tier (k≥3) shares the identity bucket; only the Ark ledger hashes.
    let (k_class, _) = crate::wallet_id::state_class(k_tier, crate::wallet_id::PROOF_TYPE_DMAP);
    if k_class == crate::wallet_id::K_DEFAULT {
        return *wallet_id;
    }
    let k_tier = k_class;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_SMT_TIER_BUCKET");
    hasher.update(wallet_id);
    hasher.update(&[k_tier]);
    *hasher.finalize().as_bytes()
}

pub fn client_state_sign_payload(
    smt_bucket: &[u8; 32],
    new_state: &[u8; 32],
    tx_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_WALLET_STATE");
    hasher.update(smt_bucket);
    hasher.update(new_state);
    hasher.update(tx_hash);
    *hasher.finalize().as_bytes()
}

pub fn compute_receipt_commitment(
    txid: &[u8; 32],
    state_hash: &[u8; 32],
    new_wallet_seq: u64,
    commitment_hash: &[u8; 32],
    epoch: u64,
    is_dev_class: bool,
    oods_flag: Option<&crate::types::OodsFlag>,
    ci: Option<&crate::types::ConfidenceIndex>,
    sender_state: Option<&[u8; 32]>,
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
    // YPX-010 §11.6 / P3.6 — the Core-computed CI factors on a k=3 send. PRESENCE and
    // every factor VALUE are bound, so the k witnesses cryptographically attest the
    // sender's offline-trust profile: an offline receiver reads Core-signed evidence it
    // can neither strip nor forge. `validator_signature`/`issuer_validator_pk` (the
    // retired online-credential fields) are NOT folded — the k-witness receipt sigs ARE
    // the authentication. A `None` (every non-k=3 receipt) folds a single 0 byte, so
    // those commitments stay byte-identical to the pre-CI formula shape below the tag.
    match ci {
        Some(c) => {
            hasher.update(&[1u8]);
            hasher.update(&c.wallet_pk);
            hasher.update(&c.last_k3_at.to_le_bytes());
            hasher.update(&c.ark_tx_count_since_k3.to_le_bytes());
            hasher.update(&c.k3_balance.to_le_bytes());
            hasher.update(&c.ark_tx_mean_amount.to_le_bytes());
            hasher.update(&[c.ark_validator_count]);
            hasher.update(&[c.has_fact_scar as u8]);
            hasher.update(&[c.has_any_k3 as u8]);
            hasher.update(&c.conflict_count.to_le_bytes());
        }
        None => {
            hasher.update(&[0u8]);
        }
    }
    // YP §32.3 — the sender's state_id this receiver's funds derive from
    // (`received_from:state_id`, the FACT sender_anchor Core computes at
    // redeem). PRESENCE and value are both bound: k=3 validators attest the
    // exact lineage the Nabla taint-propagation walks, so a downstream
    // receiver cannot strip or forge its `received_from` to evade §32.4
    // merge-quarantine taint. `None` on every non-redeem (send / genesis /
    // heal / recall) folds a single 0 byte, keeping those commitments
    // byte-identical to each other. Rotates the CoreID (inherent — the value
    // must be Core-attested for the taint layer to be non-forgeable, RULE 5).
    match sender_state {
        Some(s) => {
            hasher.update(&[1u8]);
            hasher.update(s);
        }
        None => {
            hasher.update(&[0u8]);
        }
    }
    *hasher.finalize().as_bytes()
}

/// RULE 1 consolidation (2026-08-09, `AXIOM_REPORT_RegistrationPathReview_20260809.md`
/// §"Recommended consolidation"): the ONE Core-owned "recompute the receipt
/// commitment, then count the DISTINCT Ed25519 witness sigs over it" primitive.
///
/// The preimage builder `compute_receipt_commitment` was already shared with
/// Nabla, but the VERIFY loop (recompute + `verify_ed25519` over ≥k distinct
/// `validator_pk`) lived TWICE — inline in `validation::validate_witnesses`
/// (receipt-commitment block) and in Nabla `registration::verify_seq_proof`.
/// That is a Pattern-1 duplication of the verification LOGIC; both call sites
/// now go through here.
///
/// Returns the count of DISTINCT `validator_pk`s carrying a valid 64-byte
/// Ed25519 signature over the recomputed commitment. Callers apply their own
/// quorum (RULE 1 "add a parameter, not a copy" — the k differs by caller and
/// is the ONLY behavioural difference): Core's inline receipt-commitment check
/// needs `>= 1` (the quorum COUNT is enforced separately, via the
/// `witness_sigs.len()` floor + the `commitment_hash` all-sigs verify), while
/// Nabla's seq-proof needs `>= MIN_FACT_WITNESSES` because a `SeqProof` carries
/// only the receipt-commitment sigs. Returning the count (not a bool) preserves
/// Nabla's `[SEQPROOF-FAIL] matched=X/Y` diagnostic (KI#38) for free.
///
/// Uses the Core-owned `verify_ed25519` (SEC-12b: the explicit verifier, never
/// length-based auto-detect) — an improvement over Nabla's hand-rolled
/// `ed25519_dalek` loop, which this consolidation retires.
#[allow(clippy::too_many_arguments)]
pub fn count_distinct_receipt_witness_sigs<'a>(
    txid: &[u8; 32],
    state_hash: &[u8; 32],
    new_wallet_seq: u64,
    commitment_hash: &[u8; 32],
    epoch: u64,
    is_dev_class: bool,
    oods_flag: Option<&crate::types::OodsFlag>,
    ci: Option<&crate::types::ConfidenceIndex>,
    sender_state: Option<&[u8; 32]>,
    sigs: impl Iterator<Item = (&'a [u8], &'a [u8])>,
) -> usize {
    use alloc::collections::BTreeSet;
    let commitment = compute_receipt_commitment(
        txid, state_hash, new_wallet_seq, commitment_hash, epoch, is_dev_class,
        oods_flag, ci, sender_state,
    );
    // pk carried as `&[u8]` so both callers fit: Core's `WitnessSig.validator_pk`
    // is `Vec<u8>`, Nabla's `SeqProofSig.validator_pk` is `[u8; 32]`. Distinctness
    // is by pk byte-content, which is what "≥k DISTINCT validators" means.
    let mut distinct: BTreeSet<&[u8]> = BTreeSet::new();
    for (pk, sig) in sigs {
        if sig.len() != 64 {
            continue;
        }
        if verify_ed25519(pk, &commitment, sig).is_ok() {
            distinct.insert(pk);
        }
    }
    distinct.len()
}

/// RULE 1 quorum wrapper — `count_distinct_receipt_witness_sigs(..) >= required_k`.
/// The named entry point the registration-path review calls for; callers that
/// need the raw count (Nabla's diagnostic) use the counter directly.
#[allow(clippy::too_many_arguments)]
pub fn verify_receipt_witness_quorum<'a>(
    txid: &[u8; 32],
    state_hash: &[u8; 32],
    new_wallet_seq: u64,
    commitment_hash: &[u8; 32],
    epoch: u64,
    is_dev_class: bool,
    oods_flag: Option<&crate::types::OodsFlag>,
    ci: Option<&crate::types::ConfidenceIndex>,
    sender_state: Option<&[u8; 32]>,
    sigs: impl Iterator<Item = (&'a [u8], &'a [u8])>,
    required_k: usize,
) -> bool {
    count_distinct_receipt_witness_sigs(
        txid, state_hash, new_wallet_seq, commitment_hash, epoch, is_dev_class,
        oods_flag, ci, sender_state, sigs,
    ) >= required_k
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

/// YPX-007 §9.2 (KI#125) — THE ZKP-qualification challenge. ONE builder: Lambda
/// sets it as the ignition `zkp_nonce`, Core re-derives it in `ZkpQualify`.
/// `BLAKE3("AXIOM_ZKQ_CHALLENGE" || validator_id || core_id || before_sig)` — an
/// Ed25519 signature under a key the validator does not hold is unpredictable,
/// so no proof over this challenge can predate the T0 reading.
pub fn compute_zkq_challenge(validator_id: &[u8; 32], core_id: &[u8; 32], before_sig: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_ZKQ_CHALLENGE");
    h.update(validator_id);
    h.update(core_id);
    h.update(before_sig);
    *h.finalize().as_bytes()
}

/// YPX-007 §9.2 (KI#125) — THE qualification-record signing payload. ONE builder:
/// Core signs it in `ZkpQualify`, `validation::verify_zkp_qualification_record`
/// verifies it. Every field of the record except `signature`.
pub fn compute_zkq_record_payload(r: &crate::types::ZkpQualificationRecord) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_ZKQ_RECORD");
    h.update(&r.validator_id);
    h.update(&r.dilithium_pk);
    h.update(&r.core_id);
    h.update(&r.program_digest);
    for a in [&r.att_before, &r.att_after] {
        h.update(&a.nabla_node_pk);
        h.update(&a.nabla_signature);
        h.update(&a.tick.to_le_bytes());
    }
    h.update(&r.zkp_nonce_hash);
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

/// KI#59 (out-of-order own-scar clearing) — canonical payload a Nabla node signs
/// to attest it saw+marked a FACT link's `(txid, new_state_id)` OUT OF ORDER (no
/// head advance). ONE builder (Pattern 1). Binding `new_state_id` is what closes
/// the fork objection: a forked pair (B→C, B→C') have different txids AND states,
/// so an attestation matches exactly one link.
pub fn compute_ooo_confirmation_payload(
    txid: &[u8; 32],
    new_state_id: &[u8; 32],
    nabla_tick: u64,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_OOO_CONFIRM");
    h.update(txid);
    h.update(new_state_id);
    h.update(&nabla_tick.to_le_bytes());
    *h.finalize().as_bytes()
}

/// §10.0 FOB fee-claim — canonical attestation payload (ONE builder, Pattern 1).
/// A hashmap Nabla signs this to attest: "Bounded-Fee\[validator_id, is_dev\] is
/// FULL at exactly `amount`, and the SPHINCS+-registered pool linkage names
/// `linked_wallet_id` as the ONLY authorized claimant." Core pins the fee-claim
/// tx against it (amount ==, sender ==, class ==) at the CL2 gate.
/// Domain: BLAKE3("AXIOM_FOB_CLAIM" || validator_id || is_dev || amount_le
///                || len(linked)_le || linked_wallet_id || claim_tick_le).
pub fn compute_fob_claim_attestation_payload(
    pool: u8,
    validator_id: &[u8; 32],
    is_dev: bool,
    amount: u64,
    linked_wallet_id: &str,
    claim_tick: u64,
    epoch: u64,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_FOB_CLAIM");
    // Pool discriminator (2026-09-14): fee sweep vs emission share — one
    // builder, one gate, no cross-presentation (`FOB_CLAIM_POOL_*`).
    h.update(&[pool]);
    h.update(validator_id);
    h.update(&[is_dev as u8]);
    h.update(&amount.to_le_bytes());
    h.update(&(linked_wallet_id.len() as u64).to_le_bytes());
    h.update(linked_wallet_id.as_bytes());
    h.update(&claim_tick.to_le_bytes());
    h.update(&epoch.to_le_bytes()); // §4.2a — the epoch the share is for
    *h.finalize().as_bytes()
}

/// Contribution emission voucher (`AXIOM_DESIGN_ValidatorEmission.md` §3):
/// the claimant's STAKE key (validator) or NODE key (Nabla node) signs this over
/// the Operational wallet it wants paid, for one epoch. ONE builder (Pattern 1);
/// the Nabla writer verifies it before issuing the claim attestation.
pub fn compute_emission_voucher_payload(operational_pk: &[u8; 32], epoch: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_EMISSION_VOUCHER");
    h.update(operational_pk);
    h.update(&epoch.to_le_bytes());
    *h.finalize().as_bytes()
}

/// §6b VBC REGISTRATION — the stamp's signing payload (ONE builder, Pattern 1).
/// Nabla signs this to attest: "I hold `wallet_pk` at balance `balance` at my
/// registered head as of `tick`, and it backs the certificate `vbc_hash`
/// for `validator_id`." Verified by `validation::verify_vbc_stamp`.
/// Domain: BLAKE3("AXIOM_VBC_REGISTER" || vbc_hash || validator_id || wallet_pk
///                || balance_le || tick_le)   (AXIOM_DESIGN_ValidatorJoin.md §6b.3)
pub fn compute_vbc_register_payload(
    vbc_hash: &[u8; 32],
    validator_id: &[u8; 32],
    wallet_pk: &[u8; 32],
    balance: u64,
    tick: u64,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_VBC_REGISTER");
    h.update(vbc_hash);
    h.update(validator_id);
    h.update(wallet_pk);
    h.update(&balance.to_le_bytes());
    h.update(&tick.to_le_bytes());
    *h.finalize().as_bytes()
}

/// §6b — what the OPERATOR signs when presenting a certificate for
/// registration (ONE builder, Pattern 1). Signed by the stake wallet's key —
/// the certificate's `subject_pubkey_ed25519` — so only the wallet the
/// certificate names can spend its consume-once registration; a stranger who
/// has seen the certificate on the wire cannot burn it.
/// Domain: BLAKE3("AXIOM_VBC_REGISTER_REQ" || vbc_hash || wallet_id || k_tier).
pub fn compute_vbc_register_request_payload(
    vbc_hash: &[u8; 32],
    wallet_id: &[u8; 32],
    k_tier: u8,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_VBC_REGISTER_REQ");
    h.update(vbc_hash);
    h.update(wallet_id);
    h.update(&[k_tier]);
    *h.finalize().as_bytes()
}

// KI#156 item 4 (DELETED 2026-09-21): `compute_validator_claim_payload`
// (domain "AXIOM_VALIDATOR_CLAIM_v1") was removed. It belonged to the RETIRED
// MarkValidatorEarnings withdrawal chain (KI#83 Step 9) and had 0 production
// callers — the live double-claim defence is FOB consume-once (`fob_record_claim`
// + tranche watermark), not this attestation.

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
    linked_wallet_id: &str,
    linkage_epoch: u64,
    tick: u64,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_VALIDATOR_POOL_LINK_v1");
    h.update(validator_id);
    h.update(&(linked_wallet_id.len() as u64).to_le_bytes());
    h.update(linked_wallet_id.as_bytes());
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

/// YP §18.8.4 — the CL10 Fan-Out diffusion id:
/// `BLAKE3("AXIOM_FANOUT_ID" ‖ content ‖ originator_pk)`.
///
/// THE one builder (Pattern 1, KI#55 2026-10-02): Core's CL10 verifier
/// (`modes::execute_cl10` step 5) and every signer (Lambda
/// `build_console_fanout` via `compute::`) call it. Pure function in the
/// core-logic library — not a "call into Core": Core's one-input/one-output
/// mode surface is unchanged (same precedent as `compute::zkp_nonce_hash`).
pub fn fanout_diffusion_id(content: &[u8], originator_pk: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_FANOUT_ID");
    h.update(content);
    h.update(originator_pk);
    *h.finalize().as_bytes()
}

/// YP §18.8.3 — the CL10 Fan-Out signing payload (the originator's Ed25519
/// signature covers IMMUTABLE fields only — `ttl_original`, never `ttl_current`):
/// `BLAKE3("AXIOM_FANOUT" ‖ diffusion_id ‖ content_type_u16le ‖ content ‖
/// ttl_original ‖ fanout ‖ timestamp_u64le)`.
///
/// THE one builder (Pattern 1, KI#55 2026-10-02) — verifier `execute_cl10`
/// step 7 and signer `build_console_fanout` both call it.
pub fn fanout_signing_payload(
    diffusion_id: &[u8; 32],
    content_type: u16,
    content: &[u8],
    ttl_original: u8,
    fanout: u8,
    timestamp: u64,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_FANOUT");
    h.update(diffusion_id);
    h.update(&content_type.to_le_bytes());
    h.update(content);
    h.update(&[ttl_original]);
    h.update(&[fanout]);
    h.update(&timestamp.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Compute produced_state_id for witness (send) operation
/// SHA3-256("AXIOM_STATE" || pk || new_balance || new_seq || consumed_state_id || nonce)
///
/// THE one builder of the AXIOM_STATE preimage (Pattern 1, KI#55 2026-10-02):
/// Core's send path (`validation::compute_produced_state_id`, which owns only
/// the balance math) calls it — the private concat-then-SHA3 copy that lived
/// there was merged (byte-identical; KAT `kat_axiom_state_produced_state_id`).
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

/// Compute state hash after transaction — the §15 anchor (YP §15).
/// `BLAKE3(pk || balance || seq || hibernation_until || wall_clock_lock ||
/// emission_claimed_epoch || stake_floor_until || wallet_version ||
/// ext_bytes_1 || ext_bytes_2 || ext_bytes_3 || ext_u64_1 || ext_u64_2 ||
/// ext_u64_3)`, integers little-endian. THE one builder (Pattern 1).
pub fn compute_state_hash(
    pk: &[u8],
    new_balance: u64,
    new_seq: u64,
    hibernation_until: u64,
    wall_clock_lock: u64,
    emission_claimed_epoch: u64,
    stake_floor_until: u64,
    wallet_format: &crate::types::WalletFormat,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(pk);
    hasher.update(&new_balance.to_le_bytes());
    hasher.update(&new_seq.to_le_bytes());
    // YPX-020 — bind hibernation into the witnessed state commitment so Core CL2
    // can enforce it tamper-evidently. Appended last (edit-in-place convention);
    // `0` for a non-hibernating wallet. Formula change → clean --data this rotation.
    hasher.update(&hibernation_until.to_le_bytes());
    // §5.2.2c stake lock — appended last, same edit-in-place convention as
    // hibernation above, and `0`/`0` for every non-staked wallet. Bound here so
    // the lock is k-witnessed: `verify_state_anchored` recomputes this hash
    // against the k-signed prev_receipt, so a client cannot present a wallet
    // state with the lock cleared. Formula change → clean --data this rotation.
    hasher.update(&wall_clock_lock.to_le_bytes());
    // §4.2a (2026-09-14) — the sixth field of the §15 anchor (once-per-epoch
    // emission claim, KI#166). A commitment-formula change: every anchor made
    // before it belongs to another network.
    hasher.update(&emission_claimed_epoch.to_le_bytes());
    // ValidatorJoin §6b.13 (KI#225, 2026-10-01) — the stake floor, then the
    // wallet-format block, appended LAST in this order: stake_floor_until,
    // wallet_version (u32 LE), ext_bytes_1..3, ext_u64_1..3 (u64 LE). A
    // commitment-formula change: every anchor made before it belongs to
    // another network (trustmesh wipe authorized for that deploy).
    hasher.update(&stake_floor_until.to_le_bytes());
    hasher.update(&wallet_format.wallet_version.to_le_bytes());
    hasher.update(&wallet_format.ext_bytes_1);
    hasher.update(&wallet_format.ext_bytes_2);
    hasher.update(&wallet_format.ext_bytes_3);
    hasher.update(&wallet_format.ext_u64_1.to_le_bytes());
    hasher.update(&wallet_format.ext_u64_2.to_le_bytes());
    hasher.update(&wallet_format.ext_u64_3.to_le_bytes());
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
    // §5.2.2c / YPX-020 — the SENDER id is signed too (added 2026-09-05, the owner).
    // It was unsigned while CL5 read it to decide: is this a self-redeem (which
    // CLEARS hibernation, so HAL/RECALL completion), is this a subsidy claim
    // (which STAMPS the stake lock), and the genesis-claim replay guard. A field
    // that decides those must not be editable by the holder of the cheque.
    sender_wallet_id: &str,
    receiver_wallet_id: &str,
    amount: u64,
    epoch: u64,
    // §5.2.2c — the ISSUER's wall clock at issuance, SIGNED (added 2026-09-05,
    // the owner). `epoch` above is copied from the claimant's own transaction, so a
    // deadline computed from it is a deadline the claimant chose: declaring
    // epoch 0 stamps a lock already in the past. `created_at` is the validator's
    // `SystemTime::now()`, and signing it is what makes it usable as a time base.
    created_at: u64,
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
    hasher.update(sender_wallet_id.as_bytes());
    hasher.update(receiver_wallet_id.as_bytes());
    hasher.update(&amount.to_le_bytes());
    hasher.update(&epoch.to_le_bytes());
    hasher.update(&created_at.to_le_bytes());
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
/// BLAKE3("AXIOM_TXID" || consumed_state_id || len32(client_pk) || client_pk || wallet_seq || len32(receiver_wallet_id) || receiver_wallet_id || amount || nonce || epoch)
///
/// Uses canonical field ordering — NOT JSON serialization.
/// This is the authoritative txid computation. Lambda MUST use this.
///
/// Delegates to [`compute_txid_parts`], which owns the byte layout.
pub fn compute_txid(tx: &crate::types::Transaction) -> [u8; 32] {
    compute_txid_parts(
        &tx.consumed_state_id,
        &tx.client_pk,
        tx.wallet_seq,
        &tx.receiver_wallet_id,
        tx.amount,
        tx.nonce,
        tx.epoch,
    )
}

/// Field-wise inner builder of the `AXIOM_TXID` txid — THE one place its
/// preimage byte layout is defined (Pattern 1). Both [`compute_txid`] (from a
/// `Transaction`) and [`crate::types::WitnessPreimage::txid`] (from a carried
/// preimage + epoch, Fork Settlement §2.2 / R11) call it; nothing else may
/// assemble this hash.
///
/// `client_pk` is a byte SLICE, not `[u8; 32]`: `Transaction.client_pk` is a
/// `Vec<u8>` (Ed25519 or Dilithium), and the txid must stay byte-identical for
/// a key of ANY length. Do not coerce it here.
// SECURITY-HASH: Domain-tagged BLAKE3 txid — "AXIOM_TXID" prefix prevents cross-protocol replay
pub fn compute_txid_parts(
    consumed_state_id: &[u8; 32],
    client_pk: &[u8],
    wallet_seq: u64,
    receiver_wallet_id: &str,
    amount: u64,
    nonce: u64,
    epoch: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_TXID");
    hasher.update(consumed_state_id);
    // 2026-10-01 (the owner: "tidy it at the same time"): the two VARIABLE-length
    // fields carry a u32-LE length prefix, so no two field tuples share one
    // preimage (without them `client_pk` and `receiver_wallet_id` could trade
    // bytes across the fixed `wallet_seq`). Not exploitable before — a key's
    // bytes cannot be chosen — but an unambiguous encoding needs no argument.
    hasher.update(&(client_pk.len() as u32).to_le_bytes());
    hasher.update(client_pk);
    hasher.update(&wallet_seq.to_le_bytes());
    hasher.update(&(receiver_wallet_id.len() as u32).to_le_bytes());
    hasher.update(receiver_wallet_id.as_bytes());
    hasher.update(&amount.to_le_bytes());
    hasher.update(&nonce.to_le_bytes());
    hasher.update(&epoch.to_le_bytes());
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
    // Founding-VBC hash — the heritage lineage, committed ONLY when non-zero.
    //
    // Non-zero-only, for two reasons:
    //   1. An INITIAL cert carries [0;32] (self-referential: its founding hash
    //      would be the hash of this very cert), so committing unconditionally
    //      would be circular. Excluding zero removes that.
    //   2. Every cert with a zero founding hash keeps a BYTE-IDENTICAL
    //      pre-image, so existing issuer signatures stay valid — the same
    //      property the OODS baseline relies on below. Verified 2026-09-01:
    //      all 20 deployed certs (10 VBC, 10 NBC) carry zero, so this change
    //      re-issues nothing.
    //
    // ⚠ MUST stay BEFORE the OODS block. `verify_oods_attestation` binds the
    // baseline with `nbc_commitment.ends_with(&suffix)`; anything appended
    // AFTER the baseline breaks that check. That path is
    // `#[cfg(not(feature = "dev-mode"))]`, so a dev fleet CANNOT catch the
    // regression — it would surface only in production.
    if vbc.founding_vbc_hash != [0u8; 32] {
        buf.extend_from_slice(&vbc.founding_vbc_hash);
    }
    // §5.3 GENESIS LINEAGE — appended ONLY when non-zero, for the same two
    // reasons as `founding_vbc_hash` above:
    //   1. the twenty deployed genesis certs carry zero, so their pre-image is
    //      byte-identical and their existing signatures stay valid;
    //   2. it MUST stay BEFORE the OODS block — `verify_oods_attestation`
    //      binds the baseline with `ends_with(&suffix)`, so anything appended
    //      after it breaks that check. That path is
    //      `#[cfg(not(feature = "dev-mode"))]`, so a DEV FLEET CANNOT CATCH
    //      the regression — it would surface only in production.
    if vbc.genesis_lineage != [0u8; 32] {
        buf.extend_from_slice(&vbc.genesis_lineage);
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
///     nabla_tick.to_le_bytes() ||
///     healed_balance.to_le_bytes()
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
    // YPX-018 Phase 5f Finding 4: healed_balance is bound into the signed
    // message (Nabla checks it against the heal cheque; since KI#260 no Core /
    // Lambda decision reads it). Old attestations (pre-Phase-5f) used `healed_balance: 0` via serde
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
/// - Performing the eligibility check (stored state == `healed_to_state_id`,
///   KI#260)
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
    
    // fips205 0.4.x: try_sign(message, ctx, HEDGED). The third arg is `hedged`,
    // NOT "deterministic" as an earlier comment wrongly claimed. hedged=TRUE
    // draws a random nonce from the OS RNG (getrandom), which PANICS inside the
    // deterministic RISC-V AVM guest ("getrandom called in AVM guest") — that is
    // exactly why CL8 NBC issuance died with guest exit(1) (issuance had never
    // run in-Core; genesis NBCs were ceremony-signed on the host). hedged=FALSE
    // is the FIPS 205 deterministic variant: the randomizer is derived from the
    // secret key's PRF, getrandom is never touched, and the signature is a valid,
    // reproducible SLH-DSA signature. Core MUST be deterministic, so this is the
    // only correct setting for any sign that can run in the guest.
    let signature = sk.try_sign(message, b"", false)
        .map_err(|_| ValidationError::InvalidVBC)?;
    
    Ok(signature.to_vec())
}

/// Derive a SPHINCS+ PUBLIC key from its private key.
///
/// Uses the FIPS-205 `get_public_key()` accessor rather than slicing the
/// private key's tail. The layout (`SK.seed || SK.prf || PK.seed || PK.root`)
/// happens to put the public key in the last 32 bytes, but a hand-rolled slice
/// is a second definition of the key format that would keep compiling if the
/// crate ever changed it — and would then hand back 32 plausible bytes that
/// verify nothing.
pub fn sphincs_pk_from_sk(private_key: &[u8]) -> CoreResult<Vec<u8>> {
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
    Ok(sk.get_public_key().into_bytes().to_vec())
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
    // ── KI#55 (2026-10-02) — Pattern 1 known-answer tests. Constants computed
    // INDEPENDENTLY in Python (`blake3`, `hashlib.sha3_256`) from the YP preimage
    // layouts, never from these builders (scratchpad `kat.py`).

    /// YP §18.8.4: content AABBCC, originator_pk 11×32.
    #[test]
    fn kat_fanout_diffusion_id() {
        assert_eq!(hex::encode(fanout_diffusion_id(&[0xAA, 0xBB, 0xCC], &[0x11; 32])),
            "ad6604a3e81b162b26005e954020dfc5eb41e46d79cdab4d2c3de53fd176f50f");
    }

    /// YP §18.8.3: that id, type 0x0001, content AABBCC, ttl_original 5,
    /// fanout 3, ts 1774070000.
    #[test]
    fn kat_fanout_signing_payload() {
        let did: [u8; 32] = hex::decode("ad6604a3e81b162b26005e954020dfc5eb41e46d79cdab4d2c3de53fd176f50f")
            .unwrap().try_into().unwrap();
        assert_eq!(hex::encode(fanout_signing_payload(&did, 0x0001, &[0xAA, 0xBB, 0xCC], 5, 3, 1774070000)),
            "733376563d660db4bec838e42649140ac8a37543aaa5ab64a5d50f4d6b3bbf26");
    }

    /// SHA3-256("AXIOM_STATE" ‖ pk 11×32 ‖ 1000 ‖ 2 ‖ consumed 22×32 ‖ 9).
    #[test]
    fn kat_axiom_state_produced_state_id() {
        assert_eq!(hex::encode(compute_produced_state_id(&[0x11; 32], 1000, 2, &[0x22; 32], 9)),
            "1644206be12165bcdcf44c697be17452cbf170900df0dc30d6751a7fd844b8c5");
    }

    /// 2026-10-01 — the txid preimage is unambiguous. Without the u32 length
    /// prefixes these two DIFFERENT transactions concatenate to the same bytes
    /// (`client_pk` absorbs the 8 `wallet_seq` bytes; `wallet_seq` absorbs the
    /// first 8 receiver bytes). MUTATION: drop either prefix ⇒ RED.
    #[test]
    fn txid_preimage_is_length_prefixed_so_variable_fields_cannot_trade_bytes() {
        let state = [7u8; 32];
        let pk_a = [1u8; 32];
        let seq_a: u64 = 0x0807_0605_0403_0201;
        let rcv_a = "ABCDEFGHrest@x.org";
        let mut pk_b = pk_a.to_vec();
        pk_b.extend_from_slice(&seq_a.to_le_bytes());
        let seq_b = u64::from_le_bytes(*b"ABCDEFGH");
        let rcv_b = "rest@x.org";
        // Fixture sanity: the unprefixed concatenations really are identical.
        let cat = |pk: &[u8], seq: u64, r: &str| { let mut v = pk.to_vec(); v.extend_from_slice(&seq.to_le_bytes()); v.extend_from_slice(r.as_bytes()); v };
        assert_eq!(cat(&pk_a, seq_a, rcv_a), cat(&pk_b, seq_b, rcv_b));
        let a = compute_txid_parts(&state, &pk_a, seq_a, rcv_a, 5, 9, 11);
        let b = compute_txid_parts(&state, &pk_b, seq_b, rcv_b, 5, 9, 11);
        assert_ne!(a, b, "two different transactions must never share a txid preimage");
    }

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
        // compute_state_hash(pk, balance, seq, hibernation_until, wall_clock_lock,
        //                   emission_claimed_epoch, stake_floor_until, wallet_format)
        let state = compute_state_hash(&[1u8; 32], 1000, 2, 0, 0, 0, 0,
            &crate::types::WalletFormat::CURRENT);
        assert_eq!(
            hex::encode(state),
            // Regenerated 2026-06-19: YPX-020 bound `hibernation_until` into the
            // state commitment (formula change, clean --data this rotation).
            // Regenerated 2026-09-05: §5.2.2c's TICK half was DELETED — the lock
            // is one general `wall_clock_lock`, not a stake-specific pair. Formula
            // change, so this rotation needs clean --data.
            // Regenerated 2026-09-03: §5.2.2c bound the validator stake lock
            // (`wall_clock_lock`) into the
            // state commitment — same reason and same shape as hibernation
            // above. Core-independent as the guardrail requires: both values are
            // carried on the wallet state and stamped by a claim's redeem, never
            // derived from which ELF ran. Formula change → clean --data this
            // rotation.
            // Regenerated 2026-09-14: design §4.2a / KI#166 bound `emission_claimed_epoch`
            // (the once-per-epoch mark of the contribution emission claim) into the
            // state commitment as the SIXTH field — same shape and reason as the two
            // locks above: carried on the wallet state, set by the claim's register,
            // never by which ELF ran. Formula change: fresh genesis this rotation.
            // Regenerated 2026-10-01: ValidatorJoin §6b.13 (KI#225) appended
            // `stake_floor_until` and the wallet-format block (wallet_version u32
            // LE, ext_bytes_1..3, ext_u64_1..3) LAST — carried on the wallet
            // state, never derived from which ELF ran. Cross-checked against an
            // independent Python BLAKE3 over the spec's byte layout (same value).
            // Formula change: fresh genesis this rotation (trustmesh wipe).
            "c14151662208394b79e04150b1436d7cb014ec154c2ac5f048b86000ec53bddf",
            "compute_state_hash changed — see GUARDRAIL doc above"
        );
        // compute_receipt_commitment(txid, state_hash, seq, commitment_hash, epoch, is_dev_class, oods_flag, None)
        // Golden regenerated 2026-07-03: YPX-021 §8.2 bound the OODS health
        // flag (presence + values) into the receipt commitment — a
        // deliberate formula change (CoreID rotation), NOT core-identity
        // binding. Still takes no core_id/core_version — the core-
        // independence invariant this guardrail protects is intact.
        // P3.6 (YPX-010 §11.6): the trailing `ci` arg folds the Core-computed
        // Confidence Index (a `None` folds one 0 byte). Still takes NO
        // core_id/core_version — the core-independence invariant is intact; only a
        // new Core-computed field moved the golden, exactly like `oods_flag` did.
        // §32.3 (2026-08-11): the trailing `sender_state` arg folds the
        // Core-attested `received_from:state_id` lineage (a `None` folds one 0
        // byte). Deliberate formula change → CoreID rotation. Still takes NO
        // core_id/core_version — the core-independence invariant is intact; only
        // a new Core-computed field moved the golden, exactly like `oods_flag`.
        let receipt = compute_receipt_commitment(&[2u8; 32], &[3u8; 32], 4, &[5u8; 32], 6, false, None, None, None);
        assert_eq!(
            hex::encode(receipt),
            "73ddb461df2fcb2a6bcfa7d83140d54cab49ed3f2ffd1fbaceae18e6e38e1f67",
            "compute_receipt_commitment changed — see GUARDRAIL doc above"
        );
        // With a present flag the commitment must move (presence is bound).
        let flag = crate::types::OodsFlag { tick: 77, oods_size: 1000, healthy: true };
        let receipt_flagged = compute_receipt_commitment(&[2u8; 32], &[3u8; 32], 4, &[5u8; 32], 6, false, Some(&flag), None, None);
        assert_ne!(receipt, receipt_flagged, "oods_flag presence must be bound into receipt_commitment");
        // P3.6 — a present CI must also move the commitment (presence + values bound).
        let ci = crate::types::ConfidenceIndex {
            wallet_pk: alloc::vec![9u8; 32], last_k3_at: 5, ark_tx_count_since_k3: 2,
            k3_balance: 1000, ark_tx_mean_amount: 100, ark_validator_count: 3,
            has_fact_scar: false, has_any_k3: true, conflict_count: 0,
            validator_signature: alloc::vec::Vec::new(), issuer_validator_pk: alloc::vec::Vec::new(),
        };
        let receipt_ci = compute_receipt_commitment(&[2u8; 32], &[3u8; 32], 4, &[5u8; 32], 6, false, None, Some(&ci), None);
        assert_ne!(receipt, receipt_ci, "CI presence must be bound into receipt_commitment");
        // §32.3 — a present sender_state must also move the commitment (presence + value bound).
        let receipt_sender = compute_receipt_commitment(&[2u8; 32], &[3u8; 32], 4, &[5u8; 32], 6, false, None, None, Some(&[0xABu8; 32]));
        assert_ne!(receipt, receipt_sender, "sender_state presence must be bound into receipt_commitment");
        // compute_cheque_commitment(txid, state_hash, produced, SENDER, receiver, amount, epoch, rate_bps, in, out, oracle=None)
        let cheque = compute_cheque_commitment(
            &[7u8; 32], &[8u8; 32], &[9u8; 32], "snd", "rcv", 11, 12, 99, 13, &[14u8; 32], &[15u8; 32], None,
            None,
        );
        assert_eq!(
            hex::encode(cheque),
            // Regenerated 2026-09-05: `sender_wallet_id` is now SIGNED. It was
            // unsigned while CL5 read it to decide self-redeem (which clears
            // hibernation — HAL/RECALL completion), subsidy-claim shape (which
            // stamps the stake lock), and the genesis replay guard. Core-
            // independent: it comes from the transaction, not from which ELF ran.
            "8de89e887103e4adeaff4ce8041f69c464aea73a26206c3f985426830d23e583",
            "compute_cheque_commitment changed — see GUARDRAIL doc above"
        );
    }

    /// The cheque's SENDER id is SIGNED (2026-09-05, the owner). CL5 reads it to
    /// decide three consequential things, so a holder must not be able to edit it:
    ///
    ///   - **self-redeem** → CLEARS hibernation. Unsigned, a hibernating wallet
    ///     could point ANY cheque's sender at itself and have Core lift its lock
    ///     without ever completing its HAL/RECALL.
    ///   - **subsidy-claim shape** → STAMPS the stake lock. Unsigned, a claimant
    ///     could point its own claim cheque's sender elsewhere, fail the
    ///     "sender == receiver" test, and take the stake with NO lock.
    ///   - the genesis-claim one-shot replay guard, keyed on the same shape.
    ///
    /// Mutation check: drop `sender_wallet_id` from the hasher and THIS test goes
    /// red — the two commitments collapse to equal.
    #[test]
    fn cheque_commitment_binds_the_sender_id() {
        let base = compute_cheque_commitment(
            &[7u8; 32], &[8u8; 32], &[9u8; 32], "alice@example.net", "bob@example.net",
            11, 12, 99, 13, &[14u8; 32], &[15u8; 32], None, None,
        );
        // Only the SENDER differs — everything the old commitment covered is identical.
        let tampered = compute_cheque_commitment(
            &[7u8; 32], &[8u8; 32], &[9u8; 32], "mallory@example.net", "bob@example.net",
            11, 12, 99, 13, &[14u8; 32], &[15u8; 32], None, None,
        );
        assert_ne!(base, tampered,
            "editing the cheque's sender must invalidate the validators' signature — \
             unsigned, it lets a holder flip self-redeem / claim-shape at will");

        // The self-redeem shape itself must be unforgeable: pointing the sender at
        // the receiver is exactly the edit that clears hibernation.
        let forged_self_send = compute_cheque_commitment(
            &[7u8; 32], &[8u8; 32], &[9u8; 32], "bob@example.net", "bob@example.net",
            11, 12, 99, 13, &[14u8; 32], &[15u8; 32], None, None,
        );
        assert_ne!(base, forged_self_send,
            "forging sender == receiver must not reproduce a signed commitment");
    }

    /// §5.2.2c — the ISSUER's clock is signed, so the claimant cannot pick the
    /// time the stake lock is measured from (the owner, 2026-09-05).
    ///
    /// The lock deadline is `created_at + lockup_seconds`. `created_at` is the
    /// validator's own `SystemTime::now()`; `epoch` beside it is copied verbatim
    /// from the CLAIMANT's transaction, which is why the deadline must not be
    /// computed from `epoch` — declaring `epoch = 0` would stamp a lock in 1972.
    /// Signing `created_at` closes the other half: the holder cannot edit it after
    /// the fact either.
    ///
    /// Mutation check: drop `created_at` from the hasher and this goes red.
    #[test]
    fn cheque_commitment_binds_the_issuer_clock() {
        let mk = |created_at: u64| compute_cheque_commitment(
            &[7u8; 32], &[8u8; 32], &[9u8; 32], "alice@example.net", "bob@example.net",
            11, 12, created_at, 13, &[14u8; 32], &[15u8; 32], None, None,
        );
        assert_ne!(mk(1_780_000_000), mk(0),
            "editing the issuer's clock must invalidate the signature — unsigned, a \
             backdated created_at stamps a stake lock that is already expired");
        assert_eq!(mk(1_780_000_000), mk(1_780_000_000), "same inputs, same commitment");
    }

    /// RULE 1 anti-drift guard: the ONE shared receipt-witness verify
    /// (`count_distinct_receipt_witness_sigs`) counts exactly the distinct
    /// validators that signed the recomputed commitment — the property Core's
    /// `validate_witnesses` (k=1) and Nabla's `verify_seq_proof` (k=3) both
    /// depend on. If a future edit changes what the counter counts, this fails
    /// for BOTH callers at once (which is the point — one function, one test).
    #[test]
    fn count_distinct_receipt_witness_sigs_counts_distinct_valid_signers() {
        use ed25519_dalek::{Signer, SigningKey};
        let txid = [0x11u8; 32];
        let state_hash = [0x22u8; 32];
        let seq = 7u64;
        let commitment_hash = [0x33u8; 32];
        let epoch = 42u64;

        let commitment = compute_receipt_commitment(
            &txid, &state_hash, seq, &commitment_hash, epoch, false, None, None, None,
        );

        // three DISTINCT honest signers over the recomputed commitment
        let sks: alloc::vec::Vec<SigningKey> =
            [3u8, 4, 5].iter().map(|b| SigningKey::from_bytes(&[*b; 32])).collect();
        let mut good: alloc::vec::Vec<([u8; 32], alloc::vec::Vec<u8>)> = sks
            .iter()
            .map(|sk| {
                (sk.verifying_key().to_bytes(),
                 sk.sign(&commitment).to_bytes().to_vec())
            })
            .collect();

        let count = |v: &[([u8; 32], alloc::vec::Vec<u8>)]| {
            count_distinct_receipt_witness_sigs(
                &txid, &state_hash, seq, &commitment_hash, epoch, false, None, None, None,
                v.iter().map(|(pk, s)| (pk.as_slice(), s.as_slice())),
            )
        };

        assert_eq!(count(&good), 3, "three distinct valid signers");
        assert!(verify_receipt_witness_quorum(
            &txid, &state_hash, seq, &commitment_hash, epoch, false, None, None, None,
            good.iter().map(|(pk, s)| (pk.as_slice(), s.as_slice())), 3));

        // a DUPLICATE signer does not inflate the count (distinct-by-pk)
        good.push(good[0].clone());
        assert_eq!(count(&good), 3, "a repeated pk is not counted twice");

        // a signature over a DIFFERENT commitment (wrong seq) does not count
        let wrong = SigningKey::from_bytes(&[9u8; 32]);
        let wrong_commit = compute_receipt_commitment(
            &txid, &state_hash, seq + 1, &commitment_hash, epoch, false, None, None, None,
        );
        good.push((wrong.verifying_key().to_bytes(),
                   wrong.sign(&wrong_commit).to_bytes().to_vec()));
        assert_eq!(count(&good), 3, "a sig over the wrong commitment is rejected");

        // a malformed (non-64-byte) sig is skipped, not panicked on
        good.push(([0xAAu8; 32], alloc::vec![0u8; 10]));
        assert_eq!(count(&good), 3, "a short sig is skipped");
        assert!(!verify_receipt_witness_quorum(
            &txid, &state_hash, seq, &commitment_hash, epoch, false, None, None, None,
            good.iter().map(|(pk, s)| (pk.as_slice(), s.as_slice())), 4),
            "quorum of 4 is not met by 3 distinct valid signers");
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
    /// Founding hash is committed when non-zero, AND the OODS baseline stays
    /// LAST so `verify_oods_attestation`'s `ends_with(suffix)` still holds.
    ///
    /// Row 3 (founding SET + baseline SET) is the case this project cannot
    /// exercise on its own mesh: the suffix binding is
    /// `#[cfg(not(feature = "dev-mode"))]` and every dev node skips it, so a
    /// wrong field ORDER here would pass the full local suite and a full fleet
    /// roll, and break only in production.
    #[test]
    fn founding_hash_committed_but_baseline_stays_last() {
        use crate::types::VBC;
        let sphincs_pk = vec![0x42u8; 32];
        let base = VBC {
            genesis_lineage: [0u8; 32],
            network_size_baseline: 0,
            baseline_tick: 0,
            version: 0x09,
            validator_id: *blake3::hash(&sphincs_pk).as_bytes(),
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
            nabla_registration: None,
        };
        let suffix = |v: &VBC| {
            let mut s = [0u8; 12];
            s[0..4].copy_from_slice(&v.network_size_baseline.to_le_bytes());
            s[4..12].copy_from_slice(&v.baseline_tick.to_le_bytes());
            s
        };

        // 1. zero founding, zero baseline — the legacy pre-image, unchanged.
        let legacy = compute_vbc_signing_payload_bytes(&base);

        // 2. zero founding, baseline set — identical to legacy plus the
        //    suffix, and the suffix is at the END.
        let mut b2 = base.clone();
        b2.network_size_baseline = 30;
        b2.baseline_tick = 77;
        let p2 = compute_vbc_signing_payload_bytes(&b2);
        assert!(p2.starts_with(&legacy), "a zero founding hash must not alter the legacy prefix");
        assert!(p2.ends_with(&suffix(&b2)), "baseline must be LAST");

        // 3. founding SET + baseline SET — the production-only case.
        let mut b3 = b2.clone();
        b3.founding_vbc_hash = [0xF0u8; 32];
        let p3 = compute_vbc_signing_payload_bytes(&b3);
        assert!(
            p3.windows(32).any(|w| w == [0xF0u8; 32]),
            "founding hash must be committed",
        );
        assert!(
            p3.ends_with(&suffix(&b3)),
            "OODS baseline MUST remain last — ends_with() is how \
             verify_oods_attestation binds it, and dev-mode skips that check",
        );

        // 4. founding SET, baseline zero — founding present, no suffix.
        let mut b4 = base.clone();
        b4.founding_vbc_hash = [0xF0u8; 32];
        let p4 = compute_vbc_signing_payload_bytes(&b4);
        assert_eq!(p4.len(), legacy.len() + 32, "exactly the founding hash is added");
        assert!(p4.ends_with(&[0xF0u8; 32]), "with no baseline, founding is last");

        // A different founding hash must change the commitment.
        let mut b5 = b4.clone();
        b5.founding_vbc_hash = [0x0Fu8; 32];
        assert_ne!(
            compute_vbc_signing_payload_bytes(&b5), p4,
            "founding hash must be covered by the signature — else it is forgeable",
        );
    }

    fn test_vbc_signing_payload_deterministic() {
        use crate::types::VBC;
        
        let sphincs_pk = vec![0x42u8; 32];
        let validator_id = *blake3::hash(&sphincs_pk).as_bytes();
        
        let vbc1 = VBC {
            genesis_lineage: [0u8; 32],
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
            nabla_registration: None,
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

    /// KI#205 (YPX-022 §2.1.2a): the claimant's claim payload is deterministic
    /// and every field is load-bearing — change any one input and the digest
    /// changes. Tests the builder where it is defined (RULE 1), so the SDK
    /// signer, the Nabla verifier and Core CL5 are all covered by one test.
    #[test]
    fn ki205_cheque_claim_signing_payload_is_deterministic_and_binds_every_field() {
        let id = [0x77u8; 32];
        let pk = [0xB7u8; 32];
        let base = cheque_claim_signing_payload(&id, &pk, 3, "receiver@test.com");
        assert_eq!(base, cheque_claim_signing_payload(&id, &pk, 3, "receiver@test.com"),
            "same inputs, same payload");
        let mut id2 = id; id2[31] ^= 1;
        assert_ne!(base, cheque_claim_signing_payload(&id2, &pk, 3, "receiver@test.com"), "cheque_id");
        let mut pk2 = pk; pk2[0] ^= 1;
        assert_ne!(base, cheque_claim_signing_payload(&id, &pk2, 3, "receiver@test.com"), "client_pk");
        assert_ne!(base, cheque_claim_signing_payload(&id, &pk, 0, "receiver@test.com"), "k_tier");
        assert_ne!(base, cheque_claim_signing_payload(&id, &pk, 3, "stranger@test.com"), "wallet_address");
    }

    /// KI#205 item 5: the Nabla proof payload covers `claim_sig` — the binding
    /// Core CL5 relies on. Deterministic; every field, INCLUDING claim_sig,
    /// changes the digest.
    #[test]
    fn ki205_redeem_claim_nabla_payload_is_deterministic_and_covers_claim_sig() {
        let id = [0x77u8; 32];
        let sig = alloc::vec![0x5Au8; 64];
        let base = redeem_claim_nabla_payload(&id, 500, &sig);
        assert_eq!(base, redeem_claim_nabla_payload(&id, 500, &sig), "same inputs, same payload");
        let mut id2 = id; id2[0] ^= 1;
        assert_ne!(base, redeem_claim_nabla_payload(&id2, 500, &sig), "cheque_id");
        assert_ne!(base, redeem_claim_nabla_payload(&id, 501, &sig), "claim_tick");
        let mut sig2 = sig.clone(); sig2[63] ^= 1;
        assert_ne!(base, redeem_claim_nabla_payload(&id, 500, &sig2),
            "claim_sig must be covered — otherwise a Nabla proof could be attached to a claim the writer never saw");
        // The pre-KI#205 preimage (no claim_sig) is NOT the same value.
        let mut old = blake3::Hasher::new();
        old.update(b"AXIOM_REDEEM_CLAIM"); old.update(&id); old.update(b"CLAIMED");
        old.update(&500u64.to_le_bytes());
        assert_ne!(base, *old.finalize().as_bytes(), "the old preimage must not collide with the bound one");
    }
}
