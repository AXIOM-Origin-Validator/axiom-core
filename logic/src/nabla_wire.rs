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

/// Transaction hash — BLAKE3("AXIOM_TXHASH" || old_state || new_state).
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
    /// Empty = no-fee path (heal / genesis / send / pre-step-7 SDK). Nabla
    /// skips the receipt_commitment verification in that case (matches
    /// today's behaviour byte-for-byte).
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
    /// to avoid duplication. The other five rides on K3Receipt:
    #[serde(default)]
    pub state_hash: [u8; 32],
    #[serde(default)]
    pub new_wallet_seq: u64,
    #[serde(default)]
    pub commitment_hash: [u8; 32],
    /// Lambda's tx.epoch at witness time. Distinct from `tick` — `tick`
    /// is when signatures were created, `epoch` is the Transaction's
    /// `epoch` field that was hashed into receipt_commitment.
    #[serde(default)]
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
}

impl K3Receipt {
    /// Build a K3Receipt from raw witness-signature CBOR values produced
    /// by the SDK's witness round. Used by both the imperative
    /// `register_with_nabla` path and the SendMachine register path so
    /// they construct byte-identical receipts.
    ///
    /// Each input `ciborium::Value` is a WitnessSig map carrying
    /// `validator_pk`, `signature` (Ed25519 over commitment_hash, NOT
    /// what Nabla wants), `execution_proof`, `proof_type`, and
    /// `receipt_signature` (Ed25519 over Nabla's
    /// `receipt_sign_payload(wallet_id, consumed, produced, tick)` —
    /// THIS is what Nabla verifies). We pull the receipt_signature out
    /// and rename it to `signature` in the typed K3WitnessSig so
    /// Nabla's signature-verification path lines up.
    pub fn from_witness_values(
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
                    // Empty when SDK hasn't yet populated (pre-Step-7) —
                    // Nabla then skips the receipt_commitment chain verify
                    // and behaviour is byte-identical to today.
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
            // YP §19.6 — empty/zero defaults preserve today's behaviour.
            // Step 7's SDK builder populates these from the canonical Lambda
            // Receipt (build_send_receipt / build_redeem_receipt outputs)
            // so Nabla can recompute receipt_commitment and verify the
            // bound fee_breakdown.
            state_hash: [0u8; 32],
            new_wallet_seq: 0,
            commitment_hash: [0u8; 32],
            epoch: 0,
            fee_breakdown: alloc::vec::Vec::new(),
            // Legacy partial-witness path skeleton — caller (SDK
            // `register_with_nabla`) MUST overwrite from the
            // canonical Receipt's `is_dev_class` field before
            // shipping. Default `false` keeps non-dev paths
            // byte-identical to pre-fix behaviour.
            is_dev_class: false,
            // Same skeleton treatment — caller overwrites from the
            // canonical Receipt (YPX-021 §8.2).
            oods_flag: None,
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

/// Proof of a single sub-quorum (k<3) state transition that the Nabla
/// SMT never registered — the "advance-on-proof" artifact
/// (KI #5, `docs/AXIOM_DESIGN_KI5_AdvanceOnProof.md` §4.2).
///
/// ## Why this exists
///
/// A k=2 (2-of-3) partial commit is a *real* network event: a validator
/// crashes or drops a witness response mid-round. The wallet's Lambda-side
/// state advances `X → P` but the transition is sub-quorum, so it can
/// never be registered with Nabla (a register needs a k=3 receipt). The
/// wallet then heals forward (`P → H`, fully k=3-witnessed) — but every
/// heal's `/register` is rejected at `StateMismatch[SMT_VS_REG]` because
/// Nabla's SMT is still pinned at `X` while the heal's `old_state` is `P`.
/// The SMT can never catch up: it only advances on a clean register, and
/// the `X → P` step is permanently unregisterable.
///
/// A `PartialBridgeReceipt` carries cryptographic *proof* of the `X → P`
/// step — the sub-quorum witness signatures. When attached to the heal's
/// `Registration`, Nabla verifies the proof, advances its SMT `X → H` (the
/// bridge `X → P` followed by the register's own k=3 `P → H`), and records
/// the partial txid so the partial's dead k=2 cheques can never replay.
///
/// This is **not** a client-resync (CLAUDE.md §14): the proof is composed
/// of validator-witnessed authority (the sub-quorum sigs over a real
/// receipt payload). It is honoured *only* because the register's own k=3
/// receipt supersedes `P` — proving a full quorum genuinely moved past it.
/// Nabla verifies every signature; it never trusts a client assertion.
///
/// The bridge proves **exactly one** sub-quorum link (spec §4.5 / §7). A
/// gap of more than one unproven step is rejected — `continuity` (spec
/// §4.3 check 1) forces `produced_state_id == reg.old_state`, so a
/// two-step gap cannot be flush with the register.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialBridgeReceipt {
    /// SMT-pinned state the bridge starts from (`X`). MUST equal the
    /// Nabla SMT's current `current_state` for this wallet — the bridge
    /// is anchored, never free-floating (spec §4.3 check 1).
    pub consumed_state_id: StateId,
    /// State the sub-quorum partial advanced to (`P`). MUST equal the
    /// heal `Registration.old_state` (spec §4.3 check 1).
    pub produced_state_id: StateId,
    /// txid of the sub-quorum partial transition. Recorded into Nabla's
    /// tiered txid bloom on a successful advance so the partial's dead
    /// k=2 cheques can never be replayed (spec §4.3 / §5).
    pub tx_hash: TxHash,
    /// The sub-quorum witness signatures for the `X → P` partial.
    /// `1 <= len() < 3` — at least one committer, strictly below quorum
    /// (spec §4.3 check 2). Each signs Nabla's
    /// `crypto::receipt_sign_payload(wallet_id, X, P, tick)`.
    pub witness_sigs: Vec<K3WitnessSig>,
}

/// State-registration request payload — the inner of `WireMessage::Register`.
/// Sent by SDK after a successful witness round; Nabla writes
/// `wallet_id → new_state` into the SMT after verifying the k=3 receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registration {
    pub wallet_id: WalletId,
    pub old_state: StateId,
    pub new_state: StateId,
    pub tx_hash: TxHash,
    pub receipt: K3Receipt,
    /// Wallet owner's Ed25519 public key (YPX-009 client-signed state).
    #[serde(default)]
    pub client_pk: [u8; 32],
    /// Ed25519 sig over BLAKE3("AXIOM_WALLET_STATE" || wallet_id ||
    /// new_state || tx_hash || tick_le).
    #[serde(default)]
    pub client_sig: Vec<u8>,
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
    /// KI #5 advance-on-proof: when this register's `old_state` is ahead
    /// of the Nabla SMT entry because of an intervening sub-quorum partial
    /// commit, this proves the missed `SMT_state → old_state` link so
    /// Nabla can advance its SMT before applying this register.
    ///
    /// `None` for every normal register — behaviour is then byte-identical
    /// to pre-this-field code. Tail field with `#[serde(default)]` so the
    /// wire stays compatible (serde encodes by field name).
    #[serde(default)]
    pub partial_bridge: Option<PartialBridgeReceipt>,

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
///   - `EndorseBanChallengeRequest` / `ChallengeBanRequest` — operator
///     ban-governance tooling (Yellow Paper §32).
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
    /// `/endorse-ban-challenge` — ban-challenge endorsement (Phase 3c).
    EndorseBanChallengeRequest(crate::wire_client::EndorseBanChallengeRequest),
    /// `/challenge-ban` — submit a full ban challenge with k=3
    /// endorsements (Phase 3c).
    ChallengeBanRequest(crate::wire_client::ChallengeBanRequest),
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
    /// YP §19.6 — Lambda informs Nabla that a withdrawal round
    /// finalised, so Nabla advances `last_claimed_tick` for the
    /// validator. Future earnings queries naturally exclude the
    /// already-claimed window via the `since_tick` filter.
    MarkValidatorEarningsClaimedRequest(crate::wire_client::MarkValidatorEarningsClaimedRequest),
    /// Response to `MarkValidatorEarningsClaimedRequest`. Mirrors the
    /// Nabla-side `transport::WireMessage` variant so Lambda's TCP
    /// client (Step 9B.8) can decode the reply without depending on
    /// the `axiom-nabla` crate.
    MarkValidatorEarningsClaimedResponse(crate::wire_client::MarkValidatorEarningsClaimedResponse),
    /// `/recall` — YPX-022 sender-initiated reclaim of a not-yet-completed send.
    RecallRequest(crate::wire_client::RecallRequest),
    /// Response to `RecallRequest`.
    RecallResponse(crate::wire_client::RecallResponse),
}
