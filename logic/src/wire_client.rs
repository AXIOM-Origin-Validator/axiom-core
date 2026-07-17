// AXIOM — Nabla client wire-protocol typed envelopes.
//
// MOVED 2026-05-17 (UMP Phase 1) from `axiom_nabla::wire_client` into
// `axiom_core_logic` so the SDK — which cannot depend on the `axiom-nabla`
// server crate (its dep cone: fips204 / fips205 / tokio) — can construct
// these typed requests directly instead of hand-building
// `ciborium::Value::Map`s or layer-local mirror structs. Wire types MUST
// live in `axiom_core_logic` exactly once (CLAUDE.md §13 /
// feedback_no_mirror_structs). `axiom_nabla::wire_client` now re-exports
// this module unchanged, so existing Nabla-side references keep resolving.
//
// For each op:
//   * `*Request`  — what the SDK sends.
//   * `*Response` — what the SDK receives.
//
// The `handle_*` functions in `nabla_node.rs` operate on these typed
// envelopes. HTTP transport wraps the envelope in CBOR; TCP transport
// wraps it in a `WireMessage` variant (CBOR-encoded by the transport
// layer).
//
// CBOR-stability invariants:
//   * Every field has an explicit name; ciborium uses serde field names so
//     adding a new field at the tail with `#[serde(default)]` is safe.
//   * `[u8; 32]` fixed-length arrays serialize as CBOR byte strings.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────
// QueryTxid — global double-redeem / claim status lookup.
// HTTP equivalent: GET /query-txid?txid=<64-hex>
// SDK callsites: redeem.rs (prepass), verify_cheque.rs (§4.6), nabla.rs.
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryTxidRequest {
    /// 32-byte transaction id (BLAKE3 of canonical TX bytes).
    pub txid: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryTxidResponse {
    pub txid: [u8; 32],
    /// `"REDEEMED"` or `"NOT_REDEEMED"`.
    /// Returned as a `&'static str`-style discriminant so the SDK can match
    /// on a String without a separate enum that would have its own CBOR
    /// discriminant byte (and thus break wire stability if reordered).
    pub status: String,
    /// Wallet id of the redeemer (empty when not yet redeemed or when
    /// running in Bloom mode where redeemer identity is not tracked).
    #[serde(default)]
    pub registered_by: Vec<u8>,
    /// Ed25519 public key of the responding Nabla node.
    pub nabla_node_pk: Vec<u8>,
    /// Ed25519 signature over BLAKE3("AXIOM_TXID_ATTEST" || txid || status
    /// || tick_le). Receiver verifies under `nabla_node_pk`.
    pub nabla_signature: Vec<u8>,
    /// Nabla virtual tick at the time the attestation was signed.
    pub nabla_tick: u64,
    /// `"hashmap"` or `"bloom"` — bloom mode degrades to probabilistic
    /// detection.
    pub txid_service: String,
    /// NBC issuer SPHINCS+ public key — needed by Core CL5 to verify the
    /// trust chain.
    pub nbc_issuer_pk: Vec<u8>,
    /// NBC SPHINCS+ signature over the NBC commitment.
    pub nbc_signature: Vec<u8>,
    /// NBC commitment (pre-image bytes; YPX-018 §5f) — Core re-hashes
    /// instead of trusting a caller-supplied digest.
    pub nbc_commitment: Vec<u8>,
    /// `"UNCLAIMED"` or `"CLAIMED"` (§4.6 cheque-claim state).
    pub claim_status: String,
    /// The Nabla tick at which this txid's send was COMPLETED (completion
    /// registered in the SMT); `None` if not completed or not tracked
    /// (e.g. bloom mode). UNSIGNED, informational — like `claim_status` it is
    /// NOT bound into `nabla_signature`. Lets a recall UI gate its countdown
    /// EXACTLY (`available_at = completion_tick + RECALL_INIT_WINDOW_LOW`)
    /// instead of padding a lag buffer. NOT a security input: the authoritative
    /// recall-window gate is Core CL2 / `register_recall` against the k-attested
    /// SMT `completion_tick`, so a tampered value can only skew a cosmetic
    /// countdown — a premature recall attempt is still rejected on-chain.
    pub completion_tick: Option<u64>,
}

// ─────────────────────────────────────────────────────────────────────────
// RegisterChequeClaim — §4.6 3-node double-redeem prevention.
// HTTP equivalent: POST /register-cheque-claim
// SDK callsites: nabla.rs (two).
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterChequeClaimRequest {
    pub cheque_id: [u8; 32],
    /// Ed25519 public key (32 bytes) of the claiming client.
    pub client_pk: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterChequeClaimResponse {
    /// Outcome discriminator: `"OK"`, `"CONFLICT"`, `"CONFIRMED"`, or
    /// `"ERROR"`. Same shape the HTTP body used; the SDK already
    /// branches on this string.
    pub status: String,
    /// On `"OK"`: the Nabla-writer-signed `ChequeClaimProof` Core CL5
    /// requires for redeem.  `None` on every non-OK outcome.  Type
    /// unification (2026-05-14, per CLAUDE.md §8 "Nabla and validator
    /// use the same UMP"): the wire struct embeds the same
    /// `crate::types::ChequeClaimProof` Core verifies —
    /// no mirror fields, no `cbor_value_as_bytes`-style compat shims.
    #[serde(default)]
    pub proof: Option<crate::types::ChequeClaimProof>,
    /// Human-readable failure detail (empty on OK).
    #[serde(default)]
    pub error: String,
}

// ─────────────────────────────────────────────────────────────────────────
// Recall — YPX-022 §2.1 sender-initiated reclaim of a NOT-yet-completed send.
// SDK callsite: recall.rs (Phase 3.5). Nabla's register_recall REFUSES iff the
// txid already has a COMPLETION (k-witnessed → redeemable) registration; genuine
// sub-quorum partials (KI#5 partial_bridge) stay recallable. Authorship-gated.
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecallRequest {
    /// The failed sub-quorum send being reclaimed. Nabla RECOMPUTES
    /// `txid = compute_txid(failed_send_tx)` (never trusts a passed txid) and stamps
    /// `presend_state_hash = failed_send_tx.consumed_state_id`, so the pre-send state
    /// is authoritatively bound to the recalled txid — the sender cannot substitute a
    /// higher-balance state (it wouldn't hash to `txid`). (YPX-022 §2.1, 3.2b-2.)
    pub failed_send_tx: crate::types::Transaction,
    /// Ed25519 public key (32 bytes) of the SENDER — MUST equal
    /// `failed_send_tx.client_pk` (only the sender may recall their own send).
    pub sender_pk: Vec<u8>,
    /// Ed25519 signature by `sender_pk` over BLAKE3("AXIOM_RECALL" || txid).
    pub sender_sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecallResponse {
    /// Outcome: "OK" (reclaimed + txid consumed non-redeemable), "COMPLETED"
    /// (refused — a completion registration exists → already redeemable),
    /// "CONFLICT" (a racing redeem claimed first), or "ERROR".
    pub status: String,
    /// On "OK": the Nabla-stamped `RecallAttestation` (txid-bound `presend_state_hash`)
    /// the SDK carries into the RECALL tx's CL2 (§2.1). `None` on every non-OK outcome.
    #[serde(default)]
    pub attestation: Option<crate::types::RecallAttestation>,
    /// Human-readable failure detail (empty on OK). NO skip_serializing_if —
    /// node↔node wire is bincode (see wire_all_variants_serialize / §13).
    #[serde(default)]
    pub error: String,
}

// ─────────────────────────────────────────────────────────────────────────
// RegisterClara — CLARA TX_HEAL participant registration.
// HTTP equivalent: POST /clara
// SDK callsites: heal.rs.
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterClaraRequest {
    pub wallet_pk: [u8; 32],
    pub declared_garbage: Vec<[u8; 32]>,
    /// Heal cheque carrying the chain re-anchor signatures.
    pub heal_cheque: crate::types::ChequeBundle,
    /// Authoritative heal transaction. Nabla derives healed_from_state_id
    /// (= tx.consumed_state_id) and healed_at_seq (= tx.wallet_seq) from
    /// here; neither is caller-asserted (Phase 5f).
    pub heal_transaction: crate::types::Transaction,
    /// Wallet's declared post-heal balance. Verified against the cheque's
    /// state_hash before issuing the attestation (Phase 5f Finding 4).
    pub healed_balance: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterClaraResponse {
    /// `"REGISTERED"` on accept, `"REDIRECT"` (reader-only target), or
    /// `"ERROR"` (with structured `error_code` + `error_reason`).
    pub status: String,
    /// CLARA attestation — typed so the CBOR wire carries native bytes.
    /// `None` on non-REGISTERED outcomes. Receivers verify the contained
    /// signature under Core CL2.
    #[serde(default)]
    pub attestation: Option<crate::types::ClaraAttestation>,
    /// SMT root hash at the time the registration was committed. Empty
    /// on non-REGISTERED outcomes. Carries the proof-of-acceptance that
    /// the HTTP body's `confirmation.root_hash` carried as hex.
    #[serde(default)]
    pub confirmation_root_hash: Vec<u8>,
    /// Nabla virtual tick at the time of registration. Zero on non-OK.
    #[serde(default)]
    pub confirmation_tick: u64,
    /// Responding node's id. Empty on non-OK.
    #[serde(default)]
    pub confirmation_node_id: Vec<u8>,
    /// Structured error code (one of `axiom_errors::error_code::*`) on
    /// non-REGISTERED outcomes. Empty on REGISTERED.
    #[serde(default)]
    pub error_code: String,
    /// Human-readable error reason for non-REGISTERED outcomes.
    #[serde(default)]
    pub error_reason: String,
}

// ─────────────────────────────────────────────────────────────────────────
// QueryWalletState — wallet registration + ban status lookup.
// HTTP equivalent: GET /query?wallet_pk=<64-hex>
// SDK callsites: nabla.rs::query_wallet_state (called from verify_cheque
// §4.6 prepass + verify_cheque post-Timer-A re-check).
//
// Added 2026-05-14 to close the 6th of 7 grandfathered HTTP→TCP sites
// from CLAUDE.md §8.  Same response shape as the JSON body the HTTP
// handler emits (`handle_http_query` in nabla_node.rs), but typed bytes
// instead of hex strings so the SDK doesn't need to round-trip-decode.
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryWalletStateRequest {
    /// 32-byte Ed25519 pubkey of the wallet being queried.
    pub wallet_pk: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryWalletStateResponse {
    /// `"REGISTERED"` if the wallet has an SMT entry, `"NOT_FOUND"` otherwise.
    pub status: String,
    /// Echo of the requested wallet pk (32 bytes).
    pub wallet_id: [u8; 32],
    /// Current state_id committed at the responding node.  Zero-byte
    /// array on NOT_FOUND.
    #[serde(default)]
    pub current_state: Vec<u8>,
    /// Tx-hash of the most recent state-advancing transaction for this
    /// wallet.  Zero on NOT_FOUND.
    #[serde(default)]
    pub tx_hash: Vec<u8>,
    /// SMT root hash at the time the response was generated.
    pub root_hash: Vec<u8>,
    /// The Nabla node's virtual tick at response time.
    pub synced_to_tick: u64,
    /// The tick at which the wallet's most recent state was registered
    /// (matches `SmtEntry.tick`).  Zero on NOT_FOUND.
    #[serde(default)]
    pub registration_tick: u64,
    /// `"NORMAL"`, `"FROZEN"`, `"TAINTED"`, or `"BANNED"`.  Empty on
    /// NOT_FOUND.  Mirrors `axiom_nabla::types::WalletStatus`.
    #[serde(default)]
    pub wallet_status: String,
    /// Responding node's id (32 bytes).
    pub node_id: [u8; 32],
    /// NBC issuer SPHINCS+ pubkey for branch-grouping during §4.6
    /// verification triplet selection.  Empty until the node has
    /// accepted its NBC.
    #[serde(default)]
    pub nbc_issuer_pk: Vec<u8>,
    /// `"reader"` or `"writer"` — YPX §25.5.4 role attestation.
    pub role: String,
    /// Ed25519 signature over BLAKE3("AXIOM_NABLA_ROLE" || node_id ||
    /// role_byte || wallet_pk || state_id || tick_le).  Receiver
    /// verifies under `node_id`'s embedded Ed25519 pk (via NBC).
    pub role_signature: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────
// QueryChequeClaim — §4.6 cheque claim status lookup.
// HTTP equivalent: GET /query-cheque-claim?cheque_id=<64-hex>
// SDK callsites: webclient verify_cheque.
// HTTP-only — no TCP variant.  Lives here so the same CBOR struct
// works on both sides of the wire.
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryChequeClaimResponse {
    pub cheque_id: [u8; 32],
    /// `"CLAIMED"` or `"UNCLAIMED"`.
    pub status: String,
    /// Ed25519 public key of the responding Nabla node.
    pub nabla_node_pk: Vec<u8>,
    /// Ed25519 signature over BLAKE3("AXIOM_CHEQUE_QUERY" ||
    /// cheque_id || status || tick_le).
    pub nabla_signature: Vec<u8>,
    /// Nabla virtual tick at response time.
    pub nabla_tick: u64,
}

// ─────────────────────────────────────────────────────────────────────────
// Register — webclient state registration.
// HTTP equivalent: POST /register
// SDK callsites: webclient WASM, Machine paths until their TCP cutover.
// HTTP-only.
// ─────────────────────────────────────────────────────────────────────────

/// Per-validator signature carried by `RegisterReceipt`.  Distinct from
/// `axiom_core_logic::types::WitnessSig` because the HTTP /register path
/// only needs the validator pubkey + raw signature — it does NOT verify
/// the full VBC chain (the cheque already proved that).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterReceiptSig {
    pub validator_pk: [u8; 32],
    pub signature: Vec<u8>,
}

/// HTTP /register receipt shape — Nabla recomputes
/// `receipt_sign_payload(wallet_pk, consumed_state_id, produced_state_id,
/// tick)` and verifies k=3 signatures from `signatures`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterReceipt {
    pub tick: u64,
    pub consumed_state_id: [u8; 32],
    pub produced_state_id: [u8; 32],
    pub signatures: Vec<RegisterReceiptSig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub wallet_pk: [u8; 32],
    pub new_state: [u8; 32],
    #[serde(default)]
    pub old_state: [u8; 32],
    #[serde(default)]
    pub supplemental: bool,
    #[serde(default)]
    pub is_genesis_claim: bool,
    /// k=3 receipt proving the new_state was witnessed.  Required for
    /// both supplemental and normal registration; `None` is rejected.
    #[serde(default)]
    pub receipt: Option<RegisterReceipt>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterResponse {
    /// `"REGISTERED"` / `"REDIRECT"`.
    pub status: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub wallet_pk: [u8; 32],
    #[serde(default)]
    pub new_state: [u8; 32],
    #[serde(default)]
    pub root_hash: [u8; 32],
    #[serde(default)]
    pub tick: u64,
    #[serde(default)]
    pub node_id: [u8; 32],
    #[serde(default)]
    pub nabla_node_pk: Vec<u8>,
    #[serde(default)]
    pub nabla_signature: Vec<u8>,
    /// Convenience duplicate of `nabla_signature` — kept because the
    /// SDK reads either name depending on call site.  Pre-CBOR JSON
    /// had both, retained here to avoid touching every read site in
    /// one commit; collapses to one field in a follow-up.
    #[serde(default)]
    pub fact_confirm_signature: Vec<u8>,
    #[serde(default)]
    pub pool_exhausted: bool,

    // NBC trust-anchor fields (KI#8 — 2026-05-15).
    //
    // These let the receiver (and Core CL2 verify_fact_link) prove
    // this Nabla node was admitted by the root authority — without
    // them an attacker with a stolen Nabla Ed25519 key could mint
    // valid-looking fact confirmations.  NO skip_serializing_if:
    // node-to-node wire is bincode (not self-describing), so a
    // skipped-when-empty field fails the receiver's bincode decode
    // (a pre-NBC node carries these empty). CLAUDE.md §13.
    #[serde(default)]
    pub nbc_issuer_pk: Vec<u8>,
    #[serde(default)]
    pub nbc_signature: Vec<u8>,
    #[serde(default)]
    pub nbc_commitment: Vec<u8>,
}

/// 409 Conflict response — old_state didn't match the stored
/// current_state for this wallet.  Carries the drift evidence the
/// SDK uses to trigger heal/resync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterMismatchResponse {
    pub error_response: axiom_errors::ErrorResponse,
    pub stored_state: [u8; 32],
    pub provided_old_state: [u8; 32],
}

// ─────────────────────────────────────────────────────────────────────────
// PulseProof — YPX-009 Lambda → Nabla forward.
// TCP-CBOR `WireMessage::PulseProofRequest` (Phase 3c). HTTP equivalent
// (`POST /pulse-proof`) is gated `410 Gone`.
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PulseProofRequest {
    pub validator_pk: [u8; 32],
    pub epoch: u64,
    pub full_accumulator: [u8; 32],
    pub entry_count: u32,
    pub sample_size: u32,
    pub audit_hash: [u8; 32],
    pub argon2id_per_sec: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PulseProofResponse {
    pub status: String,
    pub epoch: u64,
}

// ─────────────────────────────────────────────────────────────────────────
// JfpSecret — DWP secret commitment (YP §8.4.3).
// TCP-CBOR `WireMessage::JfpSecretRequest` / `JfpSecretsRequest` (Phase
// 3c). HTTP equivalents (`POST /jfp-secret`, `GET /jfp-secrets`) are gated
// `410 Gone`.
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JfpSecretRequest {
    pub dwp_wallet_id: [u8; 32],
    pub secret: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JfpSecretResponse {
    pub ok: bool,
}

/// `/jfp-secrets` query request — keyed by DWP wallet id. Over HTTP this
/// was a GET with a `?dwp_wallet_id=<hex>` query string; the TCP-CBOR
/// `WireMessage::JfpSecretsRequest` variant carries the id as native
/// bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JfpSecretsRequest {
    pub dwp_wallet_id: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JfpSecretsResponse {
    pub secrets: Vec<[u8; 32]>,
    pub count: u64,
}

// ─────────────────────────────────────────────────────────────────────────
// Bridge — §6.6 partition recovery.
// TCP-CBOR `WireMessage::BridgeRequest` (Phase 3c). HTTP equivalent
// (`POST /bridge`) is gated `410 Gone`. Operator-callable primitive
// for mesh repair; normative wallet flow does NOT invoke it.
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeRequest {
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeResponse {
    pub status: String,
    pub received: u64,
    pub new_nodes: u64,
    pub updated: u64,
}

// ─────────────────────────────────────────────────────────────────────────
// EndorseBanChallenge / ChallengeBan — operator ban governance.
// TCP-CBOR `WireMessage::EndorseBanChallengeRequest` / `ChallengeBanRequest`
// (Phase 3c). HTTP equivalents (`POST /endorse-ban-challenge`,
// `POST /challenge-ban`) are gated `410 Gone`.
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndorseBanChallengeRequest {
    pub wallet_id: [u8; 32],
    pub original_tx_id: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndorseBanChallengeResponse {
    /// Ed25519 pubkey of the responding Nabla node — the verifier
    /// uses this to verify `signature` over `commitment`.
    pub node_id: [u8; 32],
    pub signature: Vec<u8>,
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeBanEndorsement {
    pub node_id: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeBanRequest {
    pub wallet_id: [u8; 32],
    pub original_tx_id: [u8; 32],
    pub endorsements: Vec<ChallengeBanEndorsement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeBanResponse {
    /// `"challenged"` (ban found and queued locally) or
    /// `"challenged_via_gossip"` (ban not local, gossiped instead).
    pub status: String,
    pub challenge_window_ticks: u64,
}


// ─────────────────────────────────────────────────────────────────────────
// MarkValidatorEarningsClaimed — YP §19.6 fee ledger
// Lambda → Nabla notification that a validator's accumulated earnings
// up to `claimed_through_tick` have been withdrawn via a k-witnessed
// withdrawal round. Nabla advances its stored `last_claimed_tick` so
// future earnings queries return only fresh entries.
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarkValidatorEarningsClaimedRequest {
    pub validator_id: [u8; 32],
    /// The validator has claimed everything `tick <= claimed_through_tick`.
    /// Nabla rejects if this is not strictly greater than its stored
    /// `last_claimed_tick` for this validator (replay protection).
    pub claimed_through_tick: u64,
    /// k Lambda Ed25519 sigs over BLAKE3 of the canonical claim payload
    /// (`compute_validator_claim_payload`). Nabla verifies k >= 3 valid
    /// sigs from k DISTINCT validators before advancing.
    pub lambda_signatures: alloc::vec::Vec<crate::nabla_wire::K3WitnessSig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarkValidatorEarningsClaimedResponse {
    /// `"CLAIMED"` (advanced), `"REJECTED_REPLAY"` (not monotonic),
    /// `"REJECTED_SIG"` (< 3 valid sigs), `"REJECTED_INTERNAL"`.
    pub status: alloc::string::String,
    pub validator_id: [u8; 32],
    pub stored_last_claimed_tick: u64,
}

// ─────────────────────────────────────────────────────────────────────────
// ValidatorWithdrawal — YP §20.10 fee ledger
// SDK → Lambda admin endpoint. Validator presents a signed earnings
// attestation (Step 6 / 8.3.A) and chosen k witnesses; Lambda enforces
// §20.10 conflict-of-interest and (on k-quorum agreement) initiates the
// mint into the linked_wallet_id from validator_pool's net (90%) share.
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorWithdrawalRequest {
    pub validator_id: [u8; 32],
    /// Signed Nabla attestation of accumulated earnings (Step 6).
    pub earnings_attestation: QueryValidatorEarningsResponse,
    /// Signed Nabla attestation of the current pool linkage (Step 8.1).
    /// The SDK queries Nabla twice (earnings + pool) and bundles both
    /// signed responses so Lambda can verify everything without round-
    /// trips. Both responses are signed by the SAME Nabla node and
    /// verified via the same NBC chain.
    pub pool_linkage: QueryValidatorPoolResponse,
    /// SPHINCS+ proof that the operator authorised this withdrawal
    /// (same SPHINCS+ identity as the pool registration). Binds the
    /// validator_id + earnings_attestation hash + chosen_witnesses.
    pub sphincs_pk: alloc::vec::Vec<u8>,
    pub sphincs_sig: alloc::vec::Vec<u8>,
    /// The k validators the operator picked to witness this withdrawal.
    /// §20.10: must be disjoint from the union of `full_fee_breakdown`
    /// across all `earnings_attestation.entries`.
    pub chosen_witnesses: alloc::vec::Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorWithdrawalResponse {
    /// `"INITIATED"` (witness round started), various `"REJECTED_*"`.
    pub status: alloc::string::String,
    pub validator_id: [u8; 32],
    /// 90% of `earnings_attestation.total_amount` — the actual amount
    /// that will be minted into `linked_wallet_id`. The 10% DEED slice
    /// stays in Nabla's deed_pool (per Refactor C).
    pub net_amount: u64,
    /// Where the mint will land (from Nabla's validator_pool linkage).
    pub linked_wallet_id: [u8; 32],
    /// Tick the validator is claiming through (= until_tick of the
    /// attestation). Nabla advances last_claimed_tick to this value
    /// on success.
    pub claimed_through_tick: u64,
}

// ─────────────────────────────────────────────────────────────────────────
// RegisterValidatorPool — YP §19.6 fee ledger
// Operator-driven (per-validator management dashboard at :7700-7709).
// SDK callsite: NONE — wallet SDK never uses this. Lambda admin
// (`lambda/src/admin.rs`) is the operator-facing client.
// ─────────────────────────────────────────────────────────────────────────

/// Validator declares which wallet receives fee withdrawals from its
/// pool. The pool itself is the sum of `fee_breakdown` slots in Nabla's
/// `txid_records` keyed by `validator_id`; this struct just binds the
/// pool's drain target.
///
/// Identity binding:
///   - `validator_id` = BLAKE3(`sphincs_pk`) — the operator's stable
///     identity, owned by their SPHINCS+ keypair.
///   - `linked_wallet_id` is where withdrawals land.
///   - `linkage_epoch` strictly increases on re-link (rotate wallet);
///     Nabla rejects any registration with epoch ≤ stored epoch.
///   - `sphincs_sig` is over the canonical link-payload
///     (`compute_validator_pool_link_payload`). Validates that the
///     SPHINCS+ key holder authorised THIS specific binding at THIS
///     epoch — closes the replay vector where an old linkage could be
///     re-presented after a wallet rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterValidatorPoolRequest {
    pub validator_id: [u8; 32],
    pub linked_wallet_id: [u8; 32],
    /// SPHINCS+ public key — Nabla recomputes BLAKE3(sphincs_pk) and
    /// asserts equality with `validator_id`.
    pub sphincs_pk: alloc::vec::Vec<u8>,
    /// SPHINCS+ signature over the canonical link payload.
    pub sphincs_sig: alloc::vec::Vec<u8>,
    /// Strictly increasing per-validator. Nabla rejects epoch ≤ stored.
    /// Initial registration uses epoch 1 (epoch 0 is "no pool registered").
    pub linkage_epoch: u64,
    /// Validator's view of the current tick — Nabla rejects if outside
    /// the freshness window (replay protection).
    pub tick: u64,
}

/// Outcome of pool registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterValidatorPoolResponse {
    /// `"REGISTERED"` (first-time), `"RELINKED"` (epoch-bumped),
    /// `"REJECTED_EPOCH"`, `"REJECTED_SIG"`, `"REJECTED_STALE_TICK"`,
    /// `"REJECTED_ID_MISMATCH"`.
    pub status: alloc::string::String,
    pub validator_id: [u8; 32],
    pub stored_linked_wallet_id: [u8; 32],
    pub stored_linkage_epoch: u64,
    pub stored_at_tick: u64,
}

/// Query the current pool binding for a validator. Operator dashboards
/// use this to display "your pool drains to wallet X (epoch N)".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryValidatorPoolRequest {
    pub validator_id: [u8; 32],
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueryValidatorPoolResponse {
    pub validator_id: [u8; 32],
    /// `true` if a pool linkage is on file for this validator.
    pub registered: bool,
    pub linked_wallet_id: [u8; 32],
    pub linkage_epoch: u64,
    pub registered_at_tick: u64,
}

// ─────────────────────────────────────────────────────────────────────────
// QueryValidatorEarnings — YP §19.6 fee ledger
// HTTP equivalent: GET /query-validator-earnings?vid=<64-hex>&since_tick=<n>
// SDK callsites: validator-side fee-withdrawal flow (Step 8).
// ─────────────────────────────────────────────────────────────────────────

/// Validator queries any Nabla node (or any peer for cross-checking) for
/// its accumulated fee earnings on this Nabla's local view since
/// `since_tick`. Hashmap-mode nodes return authoritative data drawn from
/// their `txid_records` store; bloom-mode nodes return an empty
/// non-authoritative response so the SDK knows to query elsewhere.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryValidatorEarningsRequest {
    /// 32-byte validator_id (`BLAKE3(sphincs_pk)`) — same value
    /// `Receipt.fee_breakdown[i].validator_id` carries.
    pub validator_id: [u8; 32],
    /// Earnings strictly since this tick. `0` returns everything this
    /// Nabla has on file for this validator.
    pub since_tick: u64,
}

/// One row of validator earnings for a single source tx. Step 8.3.A
/// extension: `full_fee_breakdown` carries every slot from the original
/// receipt (not just this validator's amount) so the withdrawal handler
/// can enforce §20.10 — the validators who witnessed the original TX
/// cannot witness this validator's fee withdrawal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EarningsEntry {
    pub tx_hash: [u8; 32],
    /// This validator's slot — `fee_breakdown[i].amount` where
    /// `validator_id == self`. Pre-extracted for callers that don't
    /// need to walk `full_fee_breakdown`.
    pub amount: u64,
    pub tick: u64,
    /// The complete fee_breakdown from txid_records — every witnessing
    /// validator's slot, in the original receipt's order. The §20.10
    /// "do not witness fees you earned" rule excludes the union of
    /// `full_fee_breakdown[i].validator_id` across all claimed entries.
    pub full_fee_breakdown: alloc::vec::Vec<crate::types::FeeShare>,
}

/// Response payload. Signed by the responding Nabla node so downstream
/// consumers (the validator's SDK; cross-checking peers; future audit
/// tooling) can verify the claim without trusting any single node.
///
/// Signature: Ed25519 over
/// `compute_earnings_attestation_payload(nabla_node_id, validator_id,
///   since_tick, until_tick, total_amount, &entries, is_authoritative)`.
/// Verify with `nabla_node_pk` (32-byte Ed25519 PK), which the NBC fields
/// chain back to the Nabla root authority.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueryValidatorEarningsResponse {
    pub validator_id: [u8; 32],
    pub since_tick: u64,
    /// Tick at which this Nabla node sealed the response. Combined with
    /// `since_tick` gives the window the response covers; older entries
    /// may have been pruned (out of scope for Step 6, none today).
    pub until_tick: u64,
    /// Sum of `amount` over all `entries` (this validator's gross fees;
    /// net = total_amount * 90/100, with 10% to DEED). Pre-computed so
    /// consumers don't have to walk the list.
    pub total_amount: u64,
    /// Authoritative NET cap from Nabla's per-validator NET ledger
    /// (PR3 — `axiom_nabla::node::ValidatorNetLedger.balance`). This
    /// is what `verify_validator_withdrawal` uses as the mint cap.
    /// At AXC scale `net_balance ≈ total_amount * 9 / 10`, but the
    /// ledger version is atom-precise because it folds in the
    /// proportional-split-with-deterministic-remainder produced by
    /// `compute_deed_split`. After mint, the operator's
    /// `MarkValidatorEarningsClaimedRequest` decrements this balance
    /// (see PR4); next query returns the post-claim figure.
    ///
    /// `#[serde(default)]` so a Nabla running a pre-PR4 build still
    /// deserialises cleanly — the field comes back as 0 and the
    /// withdrawal flow falls back to the legacy `total_amount * 90/100`
    /// formula in `verify_validator_withdrawal`.
    #[serde(default)]
    pub net_balance: u64,
    /// Per-tx slot entries. Deterministic order — by tick ascending then
    /// tx_hash lex — so the response is byte-stable across re-queries
    /// to the same node. Each entry includes the FULL fee_breakdown
    /// (Step 8.3.A) for §20.10 enforcement at withdrawal time.
    pub entries: alloc::vec::Vec<EarningsEntry>,
    /// `true` on hashmap-mode nodes (authoritative); `false` on bloom-mode
    /// nodes (no records stored — empty response). The SDK MUST re-query
    /// elsewhere on `false` rather than treating empty as zero earnings.
    pub is_authoritative: bool,
    /// Responding Nabla node identity — `BLAKE3(sphincs_pk)` matching the
    /// node's NBC `validator_id`. Bound into the signed payload.
    pub nabla_node_id: [u8; 32],
    /// Ed25519 public key the response signature is verified under.
    pub nabla_node_pk: alloc::vec::Vec<u8>,
    /// Ed25519 signature over the canonical attestation payload.
    pub nabla_signature: alloc::vec::Vec<u8>,
    /// NBC issuer SPHINCS+ public key — chain root anchor for verifying
    /// `nabla_node_pk` belongs to a real Nabla operator.
    pub nbc_issuer_pk: alloc::vec::Vec<u8>,
    /// NBC SPHINCS+ signature over the NBC commitment.
    pub nbc_signature: alloc::vec::Vec<u8>,
    /// NBC commitment (pre-image bytes) — consumer re-hashes rather than
    /// trusting a caller-supplied digest. Same shape as
    /// `QueryTxidResponse.nbc_commitment`.
    pub nbc_commitment: alloc::vec::Vec<u8>,
}
