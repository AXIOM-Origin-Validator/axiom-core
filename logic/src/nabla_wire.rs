//! Nabla wire-protocol types — shared between SDK, ANTIE, and Nabla.
//!
//! Per `feedback_no_mirror_structs` (UMP rule): wire types MUST live in
//! `axiom_core_logic` exactly once. Pre-this-module these types had two
//! independent existences:
//!
//! 1. The authoritative definitions in `axiom_nabla::types` (Registration,
//!    DeedTransaction, K3Receipt, WitnessSig) — what the Nabla server
//!    deserializes from the wire.
//! 2. Hand-built `ciborium::Value::Map(vec![(Text("wallet_id"), ...)])`
//!    constructions in the SDK's `build_register_message` paths (one in
//!    `sdk/client/src/nabla.rs`, another in `sdk/core/src/machines/send.rs`).
//!
//! Every Machine-drift bug closed this session traces back to that
//! pattern: get_bytes Array vs Bytes (39b9770e), missing
//! sdk_validator_name tag (fe653ca0), zero receipt_commitment (b9fa3baf),
//! and the wrong-field-names register message (4b45484e). Compiler-
//! enforced typed encoding closes the door on the whole class.
//!
//! Naming note: Nabla calls its k=3 witness signature simply `WitnessSig`,
//! but `axiom_core_logic::types::WitnessSig` is the full Lambda witness
//! with Dilithium fields and `sdk_validator_name`. The two are
//! semantically distinct — Lambda's WitnessSig carries Dilithium-65 +
//! VBC bundle; Nabla's k=3 witness is the Ed25519-signed
//! state-registration consent. Renamed here to `K3WitnessSig` to
//! disambiguate.

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Wallet identifier — Ed25519 public key, 32 bytes.
pub type WalletId = [u8; 32];

/// State identifier — BLAKE3 of wallet state, 32 bytes.
pub type StateId = [u8; 32];

/// Transaction hash — on every register this is the PROTOCOL txid
/// (`compute_txid(tx)` / [`crate::types::WitnessPreimage::txid`], the value the
/// k validators fold into `receipt_commitment`). ONE txid domain since
/// 2026-07-07; the derived `BLAKE3("AXIOM_TXHASH"‖old‖new)` this comment used
/// to name is `fact_tx_hash`, a different hash (RULE 3 shape 7, corrected
/// 2026-09-28).
pub type TxHash = [u8; 32];

/// A single validator's signature on a k=3 receipt for Nabla
/// registration. Distinct from `axiom_core_logic::types::WitnessSig`
/// (which is the full Lambda witness with Dilithium-65 + VBC bundle).
/// This is the Ed25519-signed state-registration consent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct K3WitnessSig {
    /// Validator's Ed25519 public key.
    pub validator_pk: [u8; 32],
    /// Signature over `receipt_sign_payload(wallet_id, consumed_state_id,
    /// produced_state_id, tick)`.
    pub signature: Vec<u8>,
    /// Serialized execution proof (ZKP STARK receipt or DMAP attestation).
    #[serde(default)]
    pub execution_proof: Vec<u8>,
    /// Proof type discriminator: 0 = ZKP (STARK), 1 = DMAP (attestation).
    #[serde(default)]
    pub proof_type: u8,
    /// YP §19.6 — Ed25519 sig over `compute_receipt_commitment(...)` which
    /// binds `fee_breakdown` (Step 1). Nabla recomputes the commitment from
    /// K3Receipt fields + fee_breakdown and verifies this sig matches —
    /// closes the chain that lets receivers (or anyone in the Nabla mesh)
    /// trust the breakdown without re-running Lambda's slot check.
    ///
    /// ⚠ Corrected 2026-09-28 (RULE 3 shape 7): this comment used to say
    /// "Empty = no-fee path (heal / genesis / send) — Nabla skips the
    /// verification". FALSE. Lambda signs the commitment on EVERY witnessed
    /// transaction, finalizer included (`lambda/src/consensus.rs` ~4240,
    /// KI#38), and Nabla's register door step 5b′
    /// (`registration.rs::verify_registered_leg`, ForkSettlement §2.3 [R17])
    /// REQUIRES ≥ max(k_tier, 3) distinct valid ones on every non-zero-pk
    /// register. Empty means an INCOMPLETE witness round; such a register is
    /// refused.
    #[serde(default)]
    pub receipt_commitment_sig: Vec<u8>,
    /// Validator identity — `BLAKE3(sphincs_pk)`. Self-attested by the
    /// witnessing Lambda at sign time. Used by Nabla to derive
    /// `fee_breakdown` locally from the k K3WitnessSigs without the SDK
    /// having to touch any fee logic ("SDK does nothing about fees"
    /// architectural rule, 2026-06-04). Empty/zeros on pre-PR4 paths.
    #[serde(default)]
    pub validator_id: [u8; 32],
    /// Atoms this validator earned for witnessing this TX. Comes from
    /// `WitnessSig.slot_amount`, which was self-attested by the
    /// validator's own Core via `verify_slot_math` at sign time.
    /// Nabla walks `signatures[i].slot_amount` to derive the per-validator
    /// fee_breakdown; the SDK never reads or writes a fee field.
    /// Zero on pre-PR4 paths and non-fee paths (heal / send / genesis).
    #[serde(default)]
    pub slot_amount: u64,
}

/// k=3 receipt — proves a state transition was witnessed by k validators.
/// Carried as the `receipt` field of a `Registration`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K3Receipt {
    pub consumed_state_id: StateId,
    pub produced_state_id: StateId,
    pub amount: u64,
    pub signatures: Vec<K3WitnessSig>,
    /// Program identity digest: RISC Zero IMAGE_ID (ZKP) or BLAKE3(ELF)
    /// CoreID (DMAP). All zeroes during bootstrap (cross-check skipped).
    #[serde(default)]
    pub program_digest: [u8; 32],
    /// Tick at which receipt signatures were created. Nabla verifies
    /// against this tick (with staleness check). 0 = legacy: Nabla
    /// falls back to current_tick.
    #[serde(default)]
    pub tick: u64,
    /// YP §19.6 — fields needed for Nabla to recompute `receipt_commitment`
    /// over fee_breakdown. All five must equal what Core CL3/CL5 hashed
    /// into the commitment that k Lambdas signed — any divergence makes
    /// the receipt_commitment_sig verification fail.
    ///
    /// `txid` is the registration's own `tx_hash` field, not stored here
    /// to avoid duplication. The other five rides on K3Receipt.
    ///
    /// ⚠ MANDATORY — no `#[serde(default)]` (CLAUDE.md §13, ForkSettlement
    /// §2.3 [R17], 2026-09-28). These four were defaulted so the legacy
    /// "skeleton" receipt (zeroed commitment inputs, `canonical_receipt:
    /// None` in the SDK) decoded; that skeleton can never pass door step 5b′
    /// (its zeroed `commitment_hash` reproduces no preimage and no witness
    /// signed it), so a register that omits them now fails to DECODE instead
    /// of failing a verify later. The SDK skeleton path is an ERROR
    /// (`sdk/client/src/nabla.rs::build_register_message`,
    /// `sdk/core/src/machines/genesis_claim.rs::build_register_message`).
    pub state_hash: [u8; 32],
    pub new_wallet_seq: u64,
    pub commitment_hash: [u8; 32],
    /// Lambda's tx.epoch at witness time. Distinct from `tick` — `tick`
    /// is when signatures were created, `epoch` is the Transaction's
    /// `epoch` field that was hashed into receipt_commitment (and into the
    /// txid: `WitnessPreimage::txid(epoch)`).
    pub epoch: u64,
    /// YP §19.6 — receiver-pays fee allocation that Core CL5 bound into
    /// receipt_commitment. Empty on no-fee paths.
    #[serde(default)]
    pub fee_breakdown: alloc::vec::Vec<crate::types::FeeShare>,
    /// Dev-class flag — Core CL3/CL5 bound this into receipt_commitment,
    /// k=3 validators signed it. Nabla reads this at `/register` time
    /// to route fees + DEED to dev pools (`DevDeedPool`,
    /// `ValidatorDevNetLedger`) instead of public pools when `true`.
    /// See `AXIOM_DESIGN_FactClassIsolation.md`. No
    /// `skip_serializing_if` — every K3Receipt MUST carry the flag
    /// so a downstream Nabla can route correctly.
    #[serde(default)]
    pub is_dev_class: bool,
    /// YPX-021 §8.2 — the OODS health flag Core bound into
    /// `receipt_commitment`. Must ride the registration so Nabla's §5b
    /// commitment recompute (and `verify_seq_proof`) hash the same value
    /// the k validators signed. `None` when the receipt carries no flag.
    /// NO `skip_serializing_if` — like `is_dev_class` above, the field MUST
    /// ride every K3Receipt: node-to-node wire is bincode (not self-describing),
    /// so a skipped-when-None field fails the receiver's bincode decode
    /// (heal/genesis receipts legitimately carry `None`). CLAUDE.md §13.
    #[serde(default)]
    pub oods_flag: Option<crate::types::OodsFlag>,

    /// P3.6 — the Core-stamped CI factors, carried on the K3Receipt so a node
    /// recomputing `receipt_commitment` folds in the SAME value the k validators
    /// signed. `None` on non-k=3 receipts. `#[serde(default)]` for the same
    /// bincode-wire reason as `oods_flag` above (a k=3 send carries `Some`).
    #[serde(default)]
    pub confidence_index: Option<crate::types::ConfidenceIndex>,

    /// YP §32.3 — the sender's `state_id` this redeem's funds derive from
    /// (`received_from:state_id`). Core CL5 stamps it from the FACT
    /// `sender_anchor` and folds it into `receipt_commitment`, so the k=3
    /// witness sigs attest the lineage. Nabla reads this at `/register` to
    /// set `NablaEntry.received_from`, the edge §32.4 merge-quarantine taint
    /// propagation walks. `None` on every non-redeem (send / genesis / heal /
    /// recall). NO `skip_serializing_if` — like `oods_flag`/`is_dev_class`,
    /// the field MUST ride every K3Receipt over the bincode wire (CLAUDE.md
    /// §13); a redeem carries `Some`.
    #[serde(default)]
    pub sender_state: Option<StateId>,
}

impl K3Receipt {
    /// Extract the k `K3WitnessSig`s from raw witness-signature CBOR values
    /// produced by the SDK's witness round, into a receipt whose commitment
    /// inputs are still ZERO. PRIVATE since 2026-09-28 (ForkSettlement [R17]):
    /// the zeroed receipt is the "skeleton" no register may ship any more —
    /// the only caller is [`Self::from_witness_values_with_fees`], which
    /// patches in the canonical commitment inputs.
    ///
    /// Each input `ciborium::Value` is a WitnessSig map carrying
    /// `validator_pk`, `signature` (Ed25519 over commitment_hash, NOT
    /// what Nabla wants), `execution_proof`, `proof_type`, and
    /// `receipt_signature` (Ed25519 over Nabla's
    /// `receipt_sign_payload(wallet_id, consumed, produced, tick)` —
    /// THIS is what Nabla verifies). We pull the receipt_signature out
    /// and rename it to `signature` in the typed K3WitnessSig so
    /// Nabla's signature-verification path lines up.
    fn from_witness_values(
        old_state: &[u8],
        new_state: &[u8],
        witness_sigs: &[ciborium::Value],
    ) -> Self {
        let consumed: [u8; 32] = old_state.try_into().unwrap_or([0u8; 32]);
        let produced: [u8; 32] = new_state.try_into().unwrap_or([0u8; 32]);
        let signatures: Vec<K3WitnessSig> = witness_sigs
            .iter()
            .filter_map(|ws| {
                let map = ws.as_map()?;
                let get = |k: &str| -> Option<&ciborium::Value> {
                    map.iter().find(|(kk, _)| kk.as_text() == Some(k)).map(|(_, v)| v)
                };
                let validator_pk = match get("validator_pk")? {
                    ciborium::Value::Bytes(b) => {
                        let mut arr = [0u8; 32];
                        let n = b.len().min(32);
                        arr[..n].copy_from_slice(&b[..n]);
                        arr
                    }
                    ciborium::Value::Array(a) => {
                        let mut arr = [0u8; 32];
                        for (i, v) in a.iter().take(32).enumerate() {
                            if let Some(n) = v.as_integer() {
                                if let Ok(b) = u8::try_from(i128::from(n)) {
                                    arr[i] = b;
                                }
                            }
                        }
                        arr
                    }
                    _ => return None,
                };
                let signature = match get("receipt_signature")? {
                    ciborium::Value::Bytes(b) => b.clone(),
                    ciborium::Value::Array(a) => a
                        .iter()
                        .filter_map(|v| v.as_integer().and_then(|i| u8::try_from(i128::from(i)).ok()))
                        .collect(),
                    _ => return None,
                };
                let execution_proof = match get("execution_proof") {
                    Some(ciborium::Value::Bytes(b)) => b.clone(),
                    Some(ciborium::Value::Array(a)) => a
                        .iter()
                        .filter_map(|v| v.as_integer().and_then(|i| u8::try_from(i128::from(i)).ok()))
                        .collect(),
                    _ => Vec::new(),
                };
                let proof_type = match get("proof_type") {
                    Some(ciborium::Value::Integer(i)) => {
                        u8::try_from(i128::from(*i)).unwrap_or(0)
                    }
                    _ => 0,
                };
                // PR4 follow-up — pull validator_id (BLAKE3(sphincs_pk))
                // and slot_amount (atoms this validator earned) directly
                // off the witness CBOR. The fields originate on
                // WitnessSig (added 2026-06-03) and are self-attested at
                // sign time. Nabla derives fee_breakdown locally from
                // these two fields per K3WitnessSig — the SDK touches
                // nothing fee-related.
                let validator_id: [u8; 32] = match get("validator_id") {
                    Some(ciborium::Value::Bytes(b)) => {
                        let mut a = [0u8; 32];
                        let n = b.len().min(32);
                        a[..n].copy_from_slice(&b[..n]);
                        a
                    }
                    Some(ciborium::Value::Array(av)) => {
                        let mut a = [0u8; 32];
                        for (i, v) in av.iter().take(32).enumerate() {
                            if let Some(n) = v.as_integer() {
                                if let Ok(b) = u8::try_from(i128::from(n)) {
                                    a[i] = b;
                                }
                            }
                        }
                        a
                    }
                    _ => [0u8; 32],
                };
                let slot_amount: u64 = match get("slot_amount") {
                    Some(ciborium::Value::Integer(i)) => {
                        u64::try_from(i128::from(*i)).unwrap_or(0)
                    }
                    _ => 0,
                };
                Some(K3WitnessSig {
                    validator_pk,
                    signature,
                    execution_proof,
                    proof_type,
                    // YP §19.6 — extracted from `receipt_commitment_sig`
                    // on the witness CBOR (Lambda Step 2's per-slot sign).
                    // Step 7 is complete: the canonical builder
                    // (`from_witness_values_with_fees` / `build_*_receipt`)
                    // populates this from the Lambda-signed wire, and the
                    // skip-when-zero shim was removed (the strict
                    // receipt_commitment check at `validation.rs::validate_witnesses`
                    // is live). Empty here now means the k=3 round never signed
                    // the commitment — an INCOMPLETE (or legacy) witness round,
                    // NOT a pre-rollout state. `from_receipt` then yields no
                    // `SeqProof`, so the seq-proof gate treats such an advance as
                    // un-attestable and it cannot converge over anti-entropy
                    // (docs/AXIOM_DESIGN_NablaAntiEntropy.md §5.2.2).
                    receipt_commitment_sig: match get("receipt_commitment_sig") {
                        Some(ciborium::Value::Bytes(b)) => b.clone(),
                        Some(ciborium::Value::Array(a)) => a
                            .iter()
                            .filter_map(|v| v.as_integer().and_then(|i| u8::try_from(i128::from(i)).ok()))
                            .collect(),
                        _ => alloc::vec::Vec::new(),
                    },
                    validator_id,
                    slot_amount,
                })
            })
            .collect();
        K3Receipt {
            consumed_state_id: consumed,
            produced_state_id: produced,
            amount: 0,
            signatures,
            program_digest: [0u8; 32],
            tick: 0,
            // Placeholders ONLY — `from_witness_values_with_fees` (the sole
            // caller) overwrites all four from the canonical Receipt. A
            // receipt shipped with these zeros is the skeleton door step 5b′
            // refuses (ForkSettlement [R17]).
            state_hash: [0u8; 32],
            new_wallet_seq: 0,
            commitment_hash: [0u8; 32],
            epoch: 0,
            fee_breakdown: alloc::vec::Vec::new(),
            // The SDK's ONE faithful builder
            // (`axiom_sdk_core::types::k3_receipt_from_canonical`) overwrites
            // this from the canonical Receipt's k-signed `is_dev_class`.
            is_dev_class: false,
            // Same skeleton treatment — caller overwrites from the
            // canonical Receipt (YPX-021 §8.2).
            oods_flag: None,
            confidence_index: None,
            // §32.3 — caller overwrites from the canonical Receipt's
            // `sender_state`; `None` keeps non-redeem paths byte-identical.
            sender_state: None,
        }
    }

    /// YP §19.6 — fee-aware K3Receipt builder. Same witness-CBOR
    /// extraction as [`Self::from_witness_values`] but additionally
    /// populates the five extension fields Nabla needs to recompute
    /// `receipt_commitment` and verify the receipt_commitment_sig chain.
    ///
    /// Caller passes the values Core CL3 / CL5 produced for this TX
    /// (`PublicOutputs.new_state_hash`, `new_wallet_seq`,
    /// `commitment_hash`, `tx.epoch`) plus the SDK-proposed
    /// `fee_breakdown` (built via `axiom_sdk_core::send::build_fee_breakdown`).
    /// The resulting K3Receipt embeds everything Nabla's Step 5 chain
    /// check needs — zero-trust input: if any field diverges from what
    /// Lambda i hashed, Lambda i's `receipt_commitment_sig` won't verify
    /// against Nabla's recomputed hash, and the register rejects.
    #[allow(clippy::too_many_arguments)]
    pub fn from_witness_values_with_fees(
        old_state: &[u8],
        new_state: &[u8],
        witness_sigs: &[ciborium::Value],
        amount: u64,
        state_hash: [u8; 32],
        new_wallet_seq: u64,
        commitment_hash: [u8; 32],
        epoch: u64,
        fee_breakdown: alloc::vec::Vec<crate::types::FeeShare>,
    ) -> Self {
        // Reuse the witness-CBOR extraction (the receipt_commitment_sig
        // for each slot comes off the wire). Then patch in the fields.
        let mut r = Self::from_witness_values(old_state, new_state, witness_sigs);
        r.amount = amount;
        r.state_hash = state_hash;
        r.new_wallet_seq = new_wallet_seq;
        r.commitment_hash = commitment_hash;
        r.epoch = epoch;
        r.fee_breakdown = fee_breakdown;
        r
    }
}

/// The witnessed leg a registration announces, carried so ANY node can
/// recompute what the k validators signed without local state —
/// AXIOM_DESIGN_ForkSettlement.md §2.2 (the self-proving leg), §2.3 [R17]
/// (door step 5b′) and [R‑MEDIUM-3] (the message's `old_state` is unsigned;
/// the preimage is). Rides on [`Registration::preimage`] and, inside Nabla,
/// on every `SeqProof` (StateUpdate flood, AE, StatePull/RangeSync, WAL,
/// snapshot).
///
/// Mirrors [`crate::types::LegKind`] (the design's `kind` discriminator):
///
/// * `Send` — every send-SHAPED transaction (Normal, Heal, HAL re-anchor,
///   Recall, burn, genesis/stake claim, VBC request, fee claim …). Its
///   `receipt.commitment_hash` is `compute_commitment_hash(tx)` and its txid is
///   `compute_txid(tx)`; the carried [`crate::types::WitnessPreimage`]
///   reproduces BOTH (`.commitment_hash()`, `.txid(epoch)`), so the leg is
///   verified, not trusted.
/// * `Redeem { redeem, cheque }` — a CL5 redeem. Its `commitment_hash` is
///   `compute_redeem_commitment(cheque_txid, receiver_pk, new_balance,
///   state_id, consumed_state_id)` (`modes.rs` Step 10), which binds NO
///   WITNESS_V2 preimage. ForkSettlement [R8] Part B bound the receiver's
///   `consumed_state_id` into that commitment (wave 2b-ii, 388a4bce); since
///   Fork Settlement W7a (2026-09-28, spec R52c / §9g, not deployed) the
///   variant CARRIES the five builder inputs ([`crate::types::RedeemPreimage`])
///   and `validation::redeem_preimage_matches` recomputes them — a redeem leg
///   is self-proving like a send leg (the door verifies it:
///   `registration.rs::verify_redeem_leg_preimage`, W7b).
///   ⚠ Corrected 2026-10-01 (RULE 3 shape 7): this said the door arm was
///   still `Redeem => return Ok(())` — W7b wired it.
///
///   `cheque` (KI#241 F-2, Fable review 2026-10-01, appended LAST) — the
///   cheque's ORIGIN send leg as an [`crate::types::OriginRecord`] (the
///   sender's whole `WitnessPreimage` + its epoch, `kind == Send`). It is
///   k-bound by RECOMPUTATION: `cheque.preimage.txid(cheque.epoch)` must equal
///   `redeem.cheque_txid`, which the redeem commitment binds (BLAKE3
///   collision resistance does the rest). It gives every node — door, flood,
///   AE, WAL, snapshot alike, because it rides the record, not only the
///   `Registration` — the cheque's GROSS amount (`cheque.preimage.amount`),
///   which Nabla's provenance burn exit (M4) needs even when the SENDER never
///   registered at that node. Delivered to the receiver by ANTIE's
///   `ChequePayload.send_origin` (verified by the SDK on receive). It is
///   NOT this leg's preimage: [`LegPreimage::send_preimage`] stays `None` for
///   a redeem (fork-claim keys must never see the sender's preimage).
///
/// There is deliberately NO `Option` / default (§13): every register states
/// its leg, and every producer fills it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LegPreimage {
    Send(crate::types::WitnessPreimage),
    Redeem {
        redeem: crate::types::RedeemPreimage,
        /// The cheque's origin send leg (F-2). LAST, mandatory (§13).
        cheque: crate::types::OriginRecord,
    },
}

// Manual `Hash` (consistent with the derived `Eq`: every field, in order):
// Nabla's `SeqProof` — which carries this — derives `Hash`, and
// `WitnessPreimage` (owned by `types.rs`) does not. This is a std-collection
// hash, never a protocol hash (Pattern 1 is untouched).
impl core::hash::Hash for LegPreimage {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        fn witness<H: core::hash::Hasher>(p: &crate::types::WitnessPreimage, state: &mut H) {
            p.consumed_state_id.hash(state);
            p.client_pk.hash(state);
            p.wallet_seq.hash(state);
            p.receiver_wallet_id.hash(state);
            p.amount.hash(state);
            p.nonce.hash(state);
        }
        match self {
            LegPreimage::Send(p) => {
                0u8.hash(state);
                witness(p, state);
            }
            LegPreimage::Redeem { redeem, cheque } => {
                1u8.hash(state);
                redeem.hash(state);
                witness(&cheque.preimage, state);
                cheque.epoch.hash(state);
                (cheque.kind == crate::types::LegKind::Send).hash(state);
            }
        }
    }
}

/// Why a `Transaction` has no send-leg preimage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegPreimageError {
    /// `WitnessPreimage.client_pk` is the 32-byte Ed25519 key the wallet's
    /// client-state sig is checked under; a transaction signed under another
    /// key length has no send leg (see `WitnessPreimage` docs).
    ClientPkNot32Bytes(usize),
    /// `redeem_of_cl5`: the CL5 run did not ACCEPT, or its outputs lack the
    /// produced state / new balance, or the inputs lack the cheque bundle's
    /// txid — there is no witnessed redeem leg to carry.
    NotAnAcceptedCl5,
    /// `redeem_of_cl5`: `PublicInputs.receiver_pk` is not a 32-byte Ed25519 key.
    ReceiverPkNot32Bytes(usize),
    /// `redeem_of_cl5` (KI#241 F-2): the carried cheque origin is not a `Send`
    /// leg, or `cheque.preimage.txid(cheque.epoch)` is not the cheque's txid —
    /// it is not this cheque's origin (a forged / wrong amount, wrong epoch).
    ChequeOriginMismatch,
}

/// THE one predicate binding a carried cheque origin to a k-bound cheque txid
/// (KI#241 F-2): `kind == Send` and `preimage.txid(epoch) == cheque_txid`
/// (`WitnessPreimage::txid` → `crypto::compute_txid_parts`, the ONE txid
/// builder). Called by `LegPreimage::redeem_of_cl5` (construction), Nabla's
/// door/flood/AE leg verifier and the SDK's receive check — never re-derived.
pub fn cheque_origin_matches(cheque: &crate::types::OriginRecord, cheque_txid: &[u8; 32]) -> bool {
    cheque.kind == crate::types::LegKind::Send && cheque.preimage.txid(cheque.epoch) == *cheque_txid
}

impl LegPreimage {
    /// The send-shaped leg of `tx` — a pure field COPY into the carrier; the
    /// hash layout stays owned by the inner builders `WitnessPreimage` calls
    /// (Pattern 1: nothing is hashed here).
    pub fn send_of(tx: &crate::types::Transaction) -> Result<Self, LegPreimageError> {
        Self::witness_of(tx).map(LegPreimage::Send)
    }

    fn witness_of(tx: &crate::types::Transaction) -> Result<crate::types::WitnessPreimage, LegPreimageError> {
        let client_pk: [u8; 32] = tx
            .client_pk
            .as_slice()
            .try_into()
            .map_err(|_| LegPreimageError::ClientPkNot32Bytes(tx.client_pk.len()))?;
        Ok(crate::types::WitnessPreimage {
            consumed_state_id: tx.consumed_state_id,
            client_pk,
            wallet_seq: tx.wallet_seq,
            receiver_wallet_id: tx.receiver_wallet_id.clone(),
            amount: tx.amount,
            nonce: tx.nonce,
        })
    }

    /// The ORIGIN record of send `tx` (KI#241 F-2) — the ONE constructor of the
    /// cheque origin a receiver carries on its redeem leg: `send_of(tx)`'s
    /// `WitnessPreimage`, `epoch = tx.epoch`, `kind = Send`. Called by ANTIE
    /// (`ChequePayload.send_origin`, built from the witnessed `Transaction`)
    /// and by the SDK for its own self-redeems; a pure field copy.
    pub fn origin_of(tx: &crate::types::Transaction) -> Result<crate::types::OriginRecord, LegPreimageError> {
        Ok(crate::types::OriginRecord {
            preimage: Self::witness_of(tx)?,
            epoch: tx.epoch,
            kind: crate::types::LegKind::Send,
        })
    }

    /// The redeem leg of a CL5 run — THE one constructor (W7a, spec R52c/R52k):
    /// a pure field COPY of exactly what `execute_cl5` Step 10 hashed —
    /// `cheque_bundle.txid()`, `receiver_pk`, `outputs.new_balance`,
    /// `outputs.produced_state_id`, `modes::cl5_consumed_state_id(inputs)`.
    /// Nothing is hashed here (Pattern 1); `validation::redeem_preimage_matches`
    /// against `outputs.commitment_hash` is the check that it is right.
    ///
    /// `cheque` (KI#241 F-2) — the cheque's origin send leg, carried on the
    /// leg. REFUSED (`ChequeOriginMismatch`) unless [`cheque_origin_matches`]
    /// against the bundle's txid: a leg that cannot be right is never built.
    pub fn redeem_of_cl5(
        inputs: &crate::types::PublicInputs,
        outputs: &crate::types::PublicOutputs,
        cheque: crate::types::OriginRecord,
    ) -> Result<Self, LegPreimageError> {
        if outputs.result != crate::types::ValidationResult::Accept {
            return Err(LegPreimageError::NotAnAcceptedCl5);
        }
        let cheque_txid = inputs
            .cheque_bundle
            .as_ref()
            .and_then(|b| b.txid())
            .ok_or(LegPreimageError::NotAnAcceptedCl5)?;
        let pk = inputs.receiver_pk.as_deref().ok_or(LegPreimageError::NotAnAcceptedCl5)?;
        let receiver_pk: [u8; 32] = pk
            .try_into()
            .map_err(|_| LegPreimageError::ReceiverPkNot32Bytes(pk.len()))?;
        let new_balance = outputs.new_balance.ok_or(LegPreimageError::NotAnAcceptedCl5)?;
        let new_state_id = outputs.produced_state_id.ok_or(LegPreimageError::NotAnAcceptedCl5)?;
        if !cheque_origin_matches(&cheque, &cheque_txid) {
            return Err(LegPreimageError::ChequeOriginMismatch);
        }
        Ok(LegPreimage::Redeem {
            redeem: crate::types::RedeemPreimage {
                cheque_txid,
                receiver_pk,
                new_balance,
                new_state_id,
                consumed_state_id: crate::modes::cl5_consumed_state_id(inputs),
            },
            cheque,
        })
    }

    /// The design's `kind` discriminator.
    pub fn kind(&self) -> crate::types::LegKind {
        match self {
            LegPreimage::Send(_) => crate::types::LegKind::Send,
            LegPreimage::Redeem { .. } => crate::types::LegKind::Redeem,
        }
    }

    /// The WITNESS_V2 preimage of a send leg; `None` for a redeem leg (a
    /// redeem's carried cheque origin is NOT its own preimage — see
    /// [`LegPreimage::cheque_origin`]).
    pub fn send_preimage(&self) -> Option<&crate::types::WitnessPreimage> {
        match self {
            LegPreimage::Send(p) => Some(p),
            LegPreimage::Redeem { .. } => None,
        }
    }

    /// The cheque origin a redeem leg carries (KI#241 F-2); `None` for a send.
    pub fn cheque_origin(&self) -> Option<&crate::types::OriginRecord> {
        match self {
            LegPreimage::Redeem { cheque, .. } => Some(cheque),
            LegPreimage::Send(_) => None,
        }
    }

    /// The redeem-commitment preimage of a redeem leg; `None` for a send leg.
    pub fn redeem_preimage(&self) -> Option<&crate::types::RedeemPreimage> {
        match self {
            LegPreimage::Redeem { redeem, .. } => Some(redeem),
            LegPreimage::Send(_) => None,
        }
    }
}

/// State-registration request payload — the inner of `WireMessage::Register`.
/// Sent by SDK after a successful witness round; Nabla writes
/// `wallet_id → new_state` into the SMT after verifying the k=3 receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registration {
    /// The wallet's Ed25519 public key — THE cryptographic identity (§10.2:
    /// "same owner" = the shared pk) and the first 32 bytes of the payload
    /// the k=3 validators sign (`receipt_sign_payload`). Bans key on it, so
    /// one banned pk covers every tier address (§10.4).
    pub wallet_id: WalletId,
    pub old_state: StateId,
    pub new_state: StateId,
    pub tx_hash: TxHash,
    pub receipt: K3Receipt,
    /// The registering wallet's security tier (option-C ruling, 2026-07-19):
    /// under the single-keypair pair the normal (k=3) and Ark (k=0) members
    /// share `wallet_id` (the pk), so Nabla buckets its sequential SMT by
    /// `(wallet_id, k_tier)` — without this, both tiers collided into ONE
    /// chain and the ark member's first registration could never enter.
    /// NOT validator-signed, and deliberately so: the tier is already bound
    /// twice cryptographically (the wallet_id-string checksum encodes it,
    /// and every tier-aware `state_id` folds it into the k-signed state
    /// chain), so a lied tier lands in a bucket whose sequential old-state
    /// check rejects it. Set at the ONE builder from the wallet's own
    /// address; the HTTP register path defaults it to 3 (webclient =
    /// Standard tier, byte-identical behavior).
    pub k_tier: u8,
    /// Wallet owner's Ed25519 public key (YPX-009 client-signed state).
    #[serde(default)]
    pub client_pk: [u8; 32],
    /// Ed25519 sig over `client_state_sign_payload(bucket, new_state, tx_hash)`
    /// = `"AXIOM_WALLET_STATE" ‖ smt_bucket(client_pk, k_tier) ‖ new_state ‖
    /// tx_hash` (`crypto.rs::client_state_sign_payload`, the ONE builder;
    /// verified at the door by `gossip::verify_client_state_sig`).
    /// ⚠ Corrected 2026-09-28 (ForkSettlement [R‑LOW], RULE 3 shape 7): this
    /// comment said `wallet_id ‖ … ‖ tick_le`. There is NO tick in the
    /// payload, and the key is the SMT BUCKET, not `wallet_id` (they differ
    /// for every non-Standard tier).
    #[serde(default)]
    pub client_sig: Vec<u8>,
    // ── §5.2.2c DECLARED STATE — the Nabla-side stake-lock check (KI#132) ────
    //
    // These three are the only fields of `compute_state_hash(pk, balance, seq,
    // hibernation_until, wall_clock_lock)` that a Registration did not already
    // carry (`pk` = `client_pk`, `seq` = `receipt.new_wallet_seq`). With them,
    // Nabla RECOMPUTES the hash and compares it to `receipt.state_hash` — which
    // it ALREADY verifies k witness signatures over, via
    // `verify_receipt_commitment_sigs` -> `compute_receipt_commitment`.
    //
    // So these are DECLARED but not TRUSTED: a lie changes the recomputed hash
    // and the registration is refused. Same pattern already in production at
    // `nabla/src/clara.rs` for `healed_balance`.
    //
    // ⚠ MANDATORY — no `#[serde(default)]`, deliberately (CLAUDE.md §13). An
    // OPTIONAL declaration is a check an attacker skips by omission, which is
    // RULE 3 shape 4: the code would read as a lock check and provide nothing.
    // Pre-mainnet every format is current; old clients are expected to break.
    //
    // ⚠ ARMOUR, NOT ENFORCEMENT. Nabla FAILS OPEN (RULE 5): a patched node
    // simply does not run this. The lock's enforcement is CORE's — the tick
    // gate in `validate_transaction` and the CL5 redeem gate. This stops an
    // HONEST node from writing a locked wallet's state into its SMT.
    /// Wallet balance bound into `receipt.state_hash`.
    pub declared_balance: u64,
    /// `hibernation_until` bound into `receipt.state_hash`.
    pub declared_hibernation_until: u64,
    /// `wall_clock_lock` bound into `receipt.state_hash` — the stake lock.
    pub declared_wall_clock_lock: u64,
    pub declared_emission_claimed_epoch: u64, // §4.2a — the sixth §15 field, same rule as the lock
    /// §6b.13 — `stake_floor_until` and the wallet-format block bound into
    /// `receipt.state_hash`. Same rule as the lock: declared, recomputed, a lie
    /// changes the hash. Nabla keeps the floor on the head it registers — it is
    /// what stamp check 5 (§6b.4) reads.
    pub declared_stake_floor_until: u64,
    pub declared_wallet_format: crate::types::WalletFormat,
    /// §10.0 FOB fee-claim — carried when THIS registration is the fee-claim
    /// tx's register: Nabla runs verify #1 (attestation valid + amount == its
    /// OWN pool view, full sweep only) BEFORE committing, then SWEEPS the pool
    /// consume-once and records the claim. `None` on every other register.
    #[serde(default)]
    pub fob_claim: Option<crate::types::FobClaimAttestation>,
    /// §17.11: Genesis claim flag — DEED check skipped, pool deduction
    /// at registration.
    #[serde(default)]
    pub is_genesis_claim: bool,
    /// YPX-020 HAL hibernation: set when this register is a dead-overlap
    /// re-anchor (`TxKind::HalReanchor`). Nabla stamps `hibernation_until =
    /// current_tick + HIBERNATION_WINDOW` on the wallet so its subsequent
    /// cheque-claim (self-redeem) is refused until the window elapses.
    /// Mirrors `is_genesis_claim`.
    #[serde(default)]
    pub is_hal_reanchor: bool,
    /// YPX-022 RECALL hibernation: set when this register is a recall re-anchor
    /// (`TxKind::Recall`). Routes through the SAME HAL hibernation stamp — Nabla
    /// stamps `hibernation_until = current_tick + HIBERNATION_WINDOW` so the recall's
    /// completion-redeem is delayed for the maturity/convergence window (the SAME
    /// mechanism + constant as HAL, not a clone). Mirrors `is_hal_reanchor`.
    #[serde(default)]
    pub is_recall: bool,
    /// YPX-001 §1.5.1a — set when the registered TX is a BURN: the txid of
    /// the scarred link being retired (`Transaction.burn_target_tx_id`).
    /// Nabla records the target as resolved-by-burn and query-txid attests
    /// it "BURNED", which is what lets DOWNSTREAM wallets clear inherited
    /// scars when the origin chose burn over heal. `None` for every
    /// non-burn register.
    #[serde(default)]
    pub burn_target_tx_id: Option<[u8; 32]>,

    /// FACT class isolation — claimant's full wallet_id string
    /// (`developer@axiom.internal/aabbccdd42`). Nabla anchors this to
    /// the receipt's pk via `verify_pk_binding` (cryptographic), then
    /// derives the class via `is_dev_wallet` (semantic). Required —
    /// no `#[serde(default)]` per CLAUDE.md §13.
    pub claimant_wallet_id: alloc::string::String,

    /// FACT class isolation — SDK's claim that this register targets
    /// the dev (`@axiom.internal`) class. Nabla cross-checks against
    /// `is_dev_wallet(claimant_wallet_id)` and rejects on mismatch
    /// (defense in depth — closes leak in both directions, neither
    /// pool can be drained by a wallet of the opposite class).
    /// Required — no `#[serde(default)]`.
    pub is_dev_claim: bool,

    /// ForkSettlement wave 2a (§2.2, §2.3 [R17], [R‑MEDIUM-3]) — the leg this
    /// register announces. The door (step 5b′) REQUIRES, for a `Send` leg:
    /// `preimage.commitment_hash() == receipt.commitment_hash`,
    /// `preimage.txid(receipt.epoch) == tx_hash`,
    /// `preimage.consumed_state_id == old_state` (the unsigned message field
    /// must agree with the signed preimage), `preimage.client_pk == client_pk`,
    /// `preimage.wallet_seq == receipt.new_wallet_seq`; and for every leg
    /// ≥ max(k_tier, 3) distinct valid `receipt_commitment_sig`s.
    ///
    /// Why the WHOLE preimage rides here rather than only the two fields the
    /// wire lacked (`receiver_wallet_id`, `nonce`): `receipt.amount` is NOT the
    /// transaction amount on every register — heal / re-align / heal-burn
    /// registers declare `tx_amount = 0` for the fee cap
    /// (`axiom_sdk_core::types::k3_receipt_from_canonical`, KI#200) while the
    /// k-signed commitment binds the tx's real amount; and the [R‑MEDIUM-3]
    /// check needs the consumed state as a SIGNED value, not the message's
    /// `old_state` compared to itself. LAST — mandatory, no default (§13).
    pub preimage: LegPreimage,
}

/// DEED-fee transaction — the second tuple element of
/// `WireMessage::Register(Registration, DeedTransaction)`. Pays the
/// state-write fee. Placeholder shape for Phase 1; production fills in
/// the real Core Transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeedTransaction {
    pub sender_wallet_id: WalletId,
    pub receiver_wallet_id: WalletId,
    pub amount: u64,
    pub signature: Vec<u8>,
}

/// SDK ↔ Nabla wire envelope. Subset of `axiom_nabla::transport::WireMessage`
/// — only the variants the SDK actually sends. The full WireMessage on
/// the Nabla side carries additional Nabla-internal variants (TARDIS,
/// gossip, banning) that the SDK never produces. Variants are
/// **externally-tagged** by name (serde+ciborium default), so a wire byte
/// produced by `ciborium::into_writer(&WireMessage::Register(reg, deed),
/// _)` here deserializes byte-for-byte into the full
/// `axiom_nabla::transport::WireMessage::Register(...)` variant on the
/// Nabla side. The two enums need not be order-equivalent; tag-by-name
/// is the contract.
///
/// UMP Phase 2 (2026-05-17): expanded from the single `Register` variant
/// to carry **every** wallet→Nabla request. The SDK constructs these
/// typed variants directly — no hand-built `ciborium::Value::Map`
/// envelopes, no mirror structs. Every byte on the SDK→Nabla wire is
/// typed serde end-to-end; the compiler enforces variant naming and
/// field shapes, closing the whole drift class. Same protocol flow,
/// same messages — only the construction is typed.
///
/// Client→Nabla request envelope — request variants only.
///
/// "UMP" historically meant *wallet*-originated, and most variants here
/// are: a wallet's SDK constructs `Register`, `Query`, `QueryTxidRequest`,
/// etc. But the envelope is not wallet-exclusive — it also carries
/// validator- and operator-originated requests that target a Nabla node:
///   - `PulseProofRequest` — a Lambda *validator* forwards a YPX-009
///     PulseProof to Nabla for gossip injection.
///   - `JfpSecretRequest` / `JfpSecretsRequest` — JFP/DWP governance
///     participants register and query vote secrets.
///
/// What they share is direction (external caller → Nabla, one
/// request/response exchange over TCP), not the wallet identity. The
/// Nabla-internal mesh variants (TARDIS, gossip, NBC issuance, state
/// sync, peer banning) deliberately stay in
/// `axiom_nabla::transport::WireMessage` — they are node↔node, never
/// produced by an external client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WireMessage {
    /// State registration after a k=3 witness round (+ DEED fee).
    Register(Registration, DeedTransaction),
    /// Wallet registration + ban-status probe (reachability check).
    Query { wallet_id: WalletId },
    /// YPX-021 §8.2 / Ark L Phase 2 — fetch the node's current signed OODS
    /// reading (Nabla-signed + NBC-anchored live tick). Response: `OodsReadingResponse`.
    OodsReadingRequest(crate::wire_client::OodsReadingRequest),
    /// Response to `OodsReadingRequest`.
    OodsReadingResponse(crate::wire_client::OodsReadingResponse),
    /// `/query-txid` — global double-redeem / claim status lookup.
    QueryTxidRequest(crate::wire_client::QueryTxidRequest),
    /// `/register-cheque-claim` — §4.6 double-redeem prevention.
    RegisterChequeClaimRequest(crate::wire_client::RegisterChequeClaimRequest),
    /// `/clara` — CLARA TX_HEAL participant registration.
    RegisterClaraRequest(crate::wire_client::RegisterClaraRequest),
    /// `/query` — wallet state + ban-status lookup.
    QueryWalletStateRequest(crate::wire_client::QueryWalletStateRequest),
    /// `/register` fact-confirm — receipt-proven state registration.
    FactConfirmRequest(crate::wire_client::RegisterRequest),
    /// `/pulse-proof` — YPX-009 validator→Nabla PulseProof forward for
    /// gossip injection (Phase 3c).
    PulseProofRequest(crate::wire_client::PulseProofRequest),
    /// `/jfp-secret` — JFP/DWP vote-secret registration (Phase 3c).
    JfpSecretRequest(crate::wire_client::JfpSecretRequest),
    /// `/jfp-secrets` — query registered vote secrets for a DWP wallet
    /// (Phase 3c).
    JfpSecretsRequest(crate::wire_client::JfpSecretsRequest),
    /// `/bridge` — §6.6 partition-recovery peer bridge (Phase 3c).
    BridgeRequest(crate::wire_client::BridgeRequest),
    /// YP §19.6 — validator earnings query. Returns a signed
    /// `QueryValidatorEarningsResponse` with the accumulated
    /// fee_breakdown slots this Nabla has on file for the queried
    /// validator. Hashmap nodes are authoritative; bloom nodes return
    /// empty + non-authoritative so the SDK re-queries elsewhere.
    QueryValidatorEarningsRequest(crate::wire_client::QueryValidatorEarningsRequest),
    /// YP §19.6 — operator declares which wallet receives fee
    /// withdrawals from this validator's pool. SPHINCS+-signed; the
    /// validator dashboard at :7700-7709 is the operator-facing entry
    /// point. Linkage_epoch must strictly increase on re-link.
    RegisterValidatorPoolRequest(crate::wire_client::RegisterValidatorPoolRequest),
    /// YP §19.6 — operator queries the current pool linkage for a
    /// validator (used by the dashboard to display "your pool drains
    /// to wallet X (epoch N)").
    QueryValidatorPoolRequest(crate::wire_client::QueryValidatorPoolRequest),
    /// `/recall` — YPX-022 sender-initiated reclaim of a not-yet-completed send.
    RecallRequest(crate::wire_client::RecallRequest),
    /// Response to `RecallRequest`.
    RecallResponse(crate::wire_client::RecallResponse),
    /// §10.0 FOB fee-claim — fetch the pool/linkage attestation (added LAST).
    FobClaimAttestationRequest(crate::wire_client::FobClaimAttestationRequest),
    /// §6b VBC registration — the operator presents a candidate certificate
    /// for Nabla's stamp (appended LAST). Response: `RegisterVbcResponse`.
    RegisterVbcRequest(crate::wire_client::RegisterVbcRequest),
    /// Response to `RegisterVbcRequest`.
    RegisterVbcResponse(crate::wire_client::RegisterVbcResponse),
    /// YP §25.2.4 contribution emission — the Operational wallet asks for this
    /// epoch's claim attestation (added LAST). Reply: `FobClaimAttestationResponse`.
    EmissionClaimAttestationRequest(crate::wire_client::EmissionClaimAttestationRequest),
    /// KI#59 — the wallet submits a k-witnessed FACT link for an out-of-order
    /// scar-resolution confirmation (added LAST). Reply: `OooConfirmResponse`.
    OooConfirmRequest(crate::wire_client::OooConfirmRequest),
    /// Response to `OooConfirmRequest`.
    OooConfirmResponse(crate::wire_client::OooConfirmResponse),
}

// ── Query reply (moved from nabla/src/types.rs, KI#173 — UMP rule; definitions unchanged) ──

/// Wallet status during normal operation and merge resolution.
/// NORMAL → FROZEN (on fork detection) → BANNED (permanent, after quarantine).
/// TAINTED = downstream wallet contaminated by forked inputs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub enum WalletStatus {
    /// Normal operation — transactions accepted.
    #[default]
    Normal,
    /// Frozen during merge quarantine — no transactions accepted.
    /// Contains the tick when freeze was triggered.
    Frozen,
    /// Contaminated by tainted inputs from a forked wallet.
    Tainted,
    /// Permanently banned — double-spend source or unresolvable taint.
    Banned,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct GroupMemberState {
    pub member_pk: [u8; 32],
    pub share_bps: u16,
    pub available: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NablaResponse {
    pub wallet_id: WalletId,
    pub current_state: StateId,
    pub tx_hash: TxHash,
    /// WI3: k-witnessed chain position of the head — REQUIRED for merkle-proof
    /// verification, because the SMT leaf hash now folds in `wallet_seq`. A
    /// verifier reconstructs the `NablaEntry` from this response; without the
    /// matching seq the leaf hash differs and the proof fails. No serde(default).
    pub wallet_seq: u64,
    pub root_hash: [u8; 32],
    pub synced_to_tick: u64,
    pub group_members: Option<Vec<GroupMemberState>>,
    pub merkle_proof: Option<MerkleProof>,
    pub signature: Vec<u8>,
    /// The answering node's role: 0 = reader, 1 = writer. INFORMATIONAL —
    /// nothing gates on it (~~"Validators MUST reject writer responses"~~: no
    /// code ever did). KI#247 (owner ruling 2026-10-02): the `role_signature`
    /// field beside it (`AXIOM_NABLA_ROLE`) was DELETED — two signers, no
    /// verifier anywhere (RULE 3 ghost).
    #[serde(default)]
    pub role: u8,

    // ── YPX-002 §4.6 receiver verification fields ──
    //
    // These three fields are covered by `response_sign_payload` (and
    // therefore by the node's Ed25519 `signature`), so a client that
    // verifies the response signature can trust them to the same degree
    // as `current_state` and `root_hash`.
    //
    // ⚠ TRUE ONLY SINCE 2026-08-07 (ghost audit G18). Before then the binary
    // assigned `nbc_issuer_pk` AFTER `query()` had signed, so the signature
    // covered an empty issuer while the wire carried a real one — this comment
    // was telling readers a field was trustworthy when the signed bytes and the
    // shipped bytes differed. Use `NablaNode::query_with_issuer`; anything that
    // mutates a covered field after signing re-opens it.
    //
    // ⚠ NOTE: `response_sign_payload` currently has NO verifier anywhere in the
    // tree — it is called only at the two signing sites. The signature is
    // correct now, but nothing checks it, so it is not yet load-bearing.
    //
    //   - `nbc_issuer_pk` : §4.3 cross-branch grouping key. Raw bytes of
    //     the SPHINCS+ pubkey from the responding node's NBC issuer set
    //     (first entry = immediate parent CA). Two nodes are cross-branch
    //     iff their `nbc_issuer_pk` differs. Absent (empty) on pre-§4.6
    //     nodes; receiver MUST treat empty as "branch unknown" and count
    //     the node as satisfying cross-branch only vacuously.
    //   - `registration_tick` : §4.6 step 7 maturity gate input.
    //     `current_tick - registration_tick >= MATURITY_TICKS_MIN` ⟹ CLEAN.
    //     0 when the wallet has no entry in this node's SMT.
    //   - `wallet_status` : §4.6 steps 3+5 BANNED check. Receiver MUST
    //     reject the cheque immediately if ANY queried node returns Banned.
    //
    // All three are `#[serde(default)]` so pre-§4.6 Nabla nodes still
    // round-trip without breaking the wire format.
    #[serde(default)]
    pub nbc_issuer_pk: Vec<u8>,
    #[serde(default)]
    pub registration_tick: u64,
    #[serde(default)]
    pub wallet_status: WalletStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub key: WalletId,
    pub siblings: Vec<[u8; 32]>,
}
