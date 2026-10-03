//! Core data types for AXIOM
//!
//! All types use `#[derive(Serialize, Deserialize)]` for Canonical JSON encoding.

use alloc::boxed::Box;
use alloc::string::String;
// `vec!` macro for the no_std build of the AVM-guest ELF. Used by
// `Transaction::to_canonical_cbor_value` (introduced 9a106c1). Without
// this import the ELF rebuild fails with "cannot find macro `vec` in
// this scope" — the `Vec` type import above doesn't bring the macro
// in, the macro lives in `alloc::vec` (the module).
use alloc::vec;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Burn address — money sent here is permanently destroyed (YPX-001 §1.5.4).
/// Used to resolve scarred FACT links by burning the tainted amount.
pub const BURN_ADDRESS: &str = "BURN/00000000";

/// Deed address — receives the 10-atom Nabla registration payment.
/// Protocol-mandated amount bypasses the dust limit.
///
/// Build-time configurable: set `AXIOM_DEED_ADDRESS` env var before compiling
/// to use a real genesis-derived wallet ID (e.g. from `compute_deed_wallet_id()`).
/// Default `"DEED/00000000"` is the dev/test placeholder.
pub const DEED_ADDRESS: &str = match option_env!("AXIOM_DEED_ADDRESS") {
    Some(addr) => addr,
    None => "DEED/00000000",
};

// Compile-time safety: DEED_ADDRESS must start with "DEED/" to prevent
// build-env hijack redirecting registration fees to an attacker wallet.
const _: () = {
    let b = DEED_ADDRESS.as_bytes();
    assert!(
        b.len() >= 5
            && b[0] == b'D'
            && b[1] == b'E'
            && b[2] == b'E'
            && b[3] == b'D'
            && b[4] == b'/',
        "DEED_ADDRESS must start with 'DEED/'"
    );
};

/// Fee address — receives protocol fee transactions.
/// Protocol-mandated amount bypasses the dust limit.
pub const FEE_ADDRESS: &str = "FEE/00000000";

/// Per-validator fee cap, in basis points of the transaction amount.
/// 30 bps = 0.30%. Bounds any single validator's slot in `Receipt.fee_breakdown`.
/// YP §19.6 amendment — aligns with EU Regulation 2015/751 per-service ceiling.
pub const MAX_VALIDATOR_FEE_BPS: u32 = 30;

/// Aggregate fee cap across all validators on a single transaction, in basis
/// points of the amount. 90 bps = 0.90%. Bounds the sum of `Receipt.fee_breakdown`.
/// YP §19.6 amendment.
pub const MAX_TOTAL_TX_FEE_BPS: u32 = 90;

/// Divisor used to interpret basis points (`bps / 10_000 = fraction`).
pub const FEE_BPS_DIVISOR: u64 = 10_000;

/// Fraction of every TX's total validator fees that goes to the DEED
/// infrastructure-funding pool, in basis points. 1000 bps = 10%.
/// Applied to `sum(fee_breakdown[i].amount)` per receipt; the remaining
/// 90% is split proportionally across the witnessing validators. See
/// `docs/AXIOM_DESIGN_DeedDistribution.md` and `compute_deed_split`.
pub const DEED_BPS: u32 = 1_000;

/// How long the DEED pool collects, in seconds. Compared against
/// `tick - GENESIS_NEWS_ANCHOR` at every register. Past the cutoff,
/// validators keep the full slot and the DEED pool size freezes.
/// 10 calendar years, no leap-day adjustment — lands ~2.5 days short
/// of the 10-year calendar anniversary.
// ⚠ `DEED_COLLECTION_DURATION_SECS` (10 years) RETIRED 2026-09-14 — DEED is
// PERPETUAL by ruling (YP §25.4 v2.21.0, `AXIOM_DESIGN_ValidatorEmission.md` §6):
// `compute_deed_split` no longer has a cutoff. Do not reintroduce a sunset.

/// Protocol version tag included in every signing message.
/// Prevents cross-network and cross-version signature replay attacks.
pub const AXIOM_PROTOCOL_VERSION: &str = "AXIOM/2.11";

/// DWP group wallet address prefix — JFP vote TXs (1 atom) bypass dust limit.
/// Group wallets are created by the DWP query flow and already exist when votes arrive.
/// See Yellow Paper §8.4.
pub const DWP_ADDRESS_PREFIX: &str = "DWP/";

/// Genesis claim amount — 1 AXC credited to new wallets from the Airdrop Pool.
/// 1 AXC = 10^10 atoms (Yellow Paper §17.11, White Paper §2.10.2).
/// Core uses this as the effective amount for produced_state_id and commitment
/// computation when `is_genesis_claim == true` (tx.amount is 0).
pub const GENESIS_CLAIM_AMOUNT: u64 = axiom_denomination::axc(1);

/// YPX-012: Oracle claim data embedded in a transaction.
/// Presence of this field marks the TX as an oracle claim.
/// Core validates: sender == receiver, k >= 5, platform whitelisted, living signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleClaimData {
    /// Must match a whitelist entry exactly (e.g., "https://foldingathome.org").
    pub platform_url: String,
    /// Platform's immutable numeric user ID.
    pub user_id: u64,
    /// Platform username — must contain Living Signature (AXM_<hex16>).
    pub username: String,
    /// Current total credits/points observed by the witnessing validators.
    pub credit_total: u64,
    /// Credit delta since last claim (credit_total - last_claimed_balance).
    pub credit_delta: u64,
    /// AXC payout computed by Lambda from credit_delta and config conversion rate.
    /// Core validates: payout_amount <= ORACLE_MAX_PAYOUT_PER_CLAIM AND platform whitelisted.
    /// Core does NOT recompute from credit_delta — Lambda owns the rate.
    #[serde(default)]
    pub payout_amount: u64,
    /// ZK-TLS proof blob (optional). When present, Lambda verifies via
    /// oracle_zktls::verify_zktls_proof before passing to Core.
    /// See docs/ORACLE_FUTURE_ZKTLS.md for integration plan.
    #[serde(default)]
    pub zktls_proof: Option<Vec<u8>>,
}

/// Core Logic Mode - determines which validation path to execute
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
// Default exists ONLY under `cfg(test)`: it lets fixtures build a PublicInputs
// without hand-listing ~25 fields, and cannot be leaned on by production code.
#[cfg_attr(test, derive(Default))]
#[allow(non_camel_case_types)]
pub enum CoreLogicMode {
    /// CL1: Client Core Out - validate outgoing transaction
    #[cfg_attr(test, default)]
    CL1,
    /// CL2: Validator Core In - verify incoming proof, validate transaction
    CL2,
    /// CL3: Validator Core Out - verify Lambda's work, produce witness proof
    CL3,
    /// CL4: Client Core In — verify incoming receipt.
    ///
    /// RESERVED FUTURE GATE (2026-07-05, KI#36). Intentionally NOT wired: today
    /// a receiver never moves value on a raw receipt — value advances only at
    /// CL5 (redeem), which is Core-verified twice (the receiver's own local
    /// `run_cl5` on the incoming cheque + the k-witness CL5 round), so a
    /// standalone CL4 pass would be pure redundancy. The slot is kept (not
    /// deleted) as the natural home for a *future* client-side receipt gate —
    /// if we ever need the receiver to get Core's verdict on an incoming
    /// receipt BEFORE redeem (e.g. a display-trust or forwarding guard), place
    /// it here. Until then it's DEFERRED in scripts/check_mode_coverage.py and
    /// the balance-advance invariant (Q1-A) is the live defense-in-depth. See
    /// AXIOM_REPORT_KnownIssues.md #36.
    CL4,
    /// CL5: Validator Redeem - validate cheque redemption (balance increase)
    CL5,
    // CL6 (standalone VBC verification) removed 2026-07-05: it was dead code —
    // VBC verification happens inside CL2/CL3/CL5 (validate_witnesses + the
    // S-ABR full-VBC check) and NBCs use CL7. Numeric slot 6 is now retired.
    /// CL7: NBC Verification (Nabla) — verify NBC bundle via Core IPC (k=1, NABLA_ROOT_AUTHORITY_PKS)
    CL7,
    /// CL8: NBC Issuance Signing — Core signs NBC with issuer's SPHINCS+ key (Nabla)
    CL8,
    // CL9 (scar-heal signing) REMOVED 2026-09-15 with the YPX-001 §1.5.3 push path — code 9 reserved.
    /// CL10: Fan-Out Verification — verify diffusion message (§18.8)
    CL10,
    /// CL11: Console Validation — verify Console Certificate chain + election (YPX-013)
    CL11,
    /// CL12: Send Proof Verification — offline, third-party verification of a
    /// retained Send Proof (transaction + finalized receipt). Beyond the k
    /// witness signatures, Core verifies every witness's VBC chains to
    /// `ROOT_AUTHORITY_PKS`, so a proof forged with throwaway validator keys is
    /// REJECTED. The verdict is Core's, reproducible via DMAP-VM or attestable
    /// via the zkVM. Carries the proof in `transaction` + `prev_receipts[0]`.
    CL12,
    /// CL2_PREFILTER: ANTIE gateway pre-execution.
    ///
    /// State-INDEPENDENT subset of CL2. Runs every check that can be made
    /// from the request alone (signatures, dust, Ark rules, oracle rules,
    /// genesis lockup, reference length, frozen wallets, sender_wallet_id
    /// shape, version, fact-chain integrity, burn target). Skips every
    /// check that requires Lambda's stored wallet state (balance, wallet_seq
    /// chain, state_id chain, S-ABR
    /// overlap math, VBC expiry of forwarded prev_receipts, CLARA eligibility).
    ///
    /// Used by ANTIE so its Core pre-execution can run with
    /// `current_state = None` — no fabricated WalletState, no false claim
    /// about Lambda's storage. Lambda's own CL2 pass owns the authoritative
    /// stateful checks against real stored state.
    ///
    /// CLAUDE.md §8 ("Layer roles are strict") — ANTIE never synthesizes
    /// what Lambda should verify. CL2_PREFILTER is the architectural fix
    /// that lets ANTIE honor that rule without losing its early-reject
    /// gating. See YPX-018 §2.1.2.
    CL2_PREFILTER,

    /// ArkSendFinalize (YPX-010 §11.2.1) — the OFFLINE k=0 ⟠-trade send-link
    /// finalize, run on the SENDER's own device after the receiver returns its
    /// co-signature (leg R2). There are no validators offline and the SDK may not
    /// assemble FACT links (CLAUDE §12), so the sender's Core does it: validate the
    /// k=0 Ark→Ark transfer, verify the `receiver_witness` (pk-bound to
    /// `receiver_wallet_id`, exclusivity §11.7), assemble the send link
    /// (`required_k = K_ARK`, no validator witnesses, the receiver-as-witness
    /// attached), and return the sender's updated chain in
    /// `PublicOutputs.ark_send_fact_chain`. The redeem-link counterpart is CL5's
    /// assembly (`modes.rs` `execute_cl5`); this is the send-link counterpart.
    ArkSendFinalize,
    /// ZkpQualify (YPX-007 §9.4, KI#125) — judge the startup ZKP benchmark and
    /// SIGN the qualification record. Reads `oods_attestation` (T0, before the
    /// proof), `zkq_request` (T1 + the host-verified journal binding),
    /// `my_validator_id` / `my_dilithium_pk` / `my_dilithium_sk`, `local_core_id`.
    /// Accept ⇒ `PublicOutputs.zkp_qualification`. Never a gate (§9.6). IPC 17.
    ZkpQualify,
}

/// Validation result from Core.bin
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationResult {
    Accept,
    Reject,
    /// FATAL: Validator configuration is broken — Lambda MUST shut down.
    /// This is returned when Core's OWN VBC fails verification (root key mismatch,
    /// expired, invalid chain). The validator cannot produce honest results.
    /// "Can crash, must not lie."
    Fatal,
}

/// A transaction in AXIOM
/// 
/// SECURITY: Uses deny_unknown_fields to prevent field aliasing attacks (C2)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    /// State ID being consumed by this transaction
    pub consumed_state_id: [u8; 32],
    
    /// Client's public key (Ed25519 or Dilithium)
    pub client_pk: Vec<u8>,

    /// Sender's wallet_id — identifies which tier address the sender is using.
    /// Core enforces identity binding: sender_wallet_id must match WalletState.wallet_id
    /// once established (prevents lockup bypass and Ark policy spoofing).
    /// Used for Ark tier enforcement (§11.9), genesis lockup, and oracle policy.
    #[serde(default)]
    pub sender_wallet_id: String,

    /// Wallet sequence number (must be prev + 1)
    pub wallet_seq: u64,
    
    /// Receiver's wallet_id (REQUIRED) - the actual wallet identity
    /// Format: "email/hex8" e.g. "bob@example.com/a3f7b232"
    /// The hex8 = checksum(6) + salt(2) for anti-typo protection
    /// checksum = BLAKE3(email || master_pk || salt)[0:6]
    pub receiver_wallet_id: String,
    
    /// Receiver's email override (OPTIONAL)
    /// If Some, send cheque to this email instead of wallet_id's email
    /// If None, extract email from receiver_wallet_id
    pub receiver_address: Option<String>,
    
    /// Amount in atoms (smallest unit)
    /// MUST be > 0 (zero amount transactions are rejected)
    pub amount: u64,
    
    /// Payment reference (max 256 chars)
    pub reference: String,
    
    /// Nonce for replay protection (epoch-scoped)
    pub nonce: u64,
    
    /// Epoch derived from consumed_state_id
    pub epoch: u64,
    
    /// Client's signature over the transaction
    pub client_sig: Vec<u8>,

    // `owner_proof` (a second Ed25519 signature under a key derived from the
    // SAME private key as `client_sig`) was DELETED 2026-09-25 (KI#108). It
    // proved exactly what `client_sig` already proves; the owner's ruling
    // 2026-08-20: "If you lost key you lost key." The struct is
    // `deny_unknown_fields`, so a wire map still carrying the key is refused.

    /// FACT scar passcode (YPX-001 §1.5)
    /// 6-digit code generated by overlapped validator when sender's money is scarred.
    /// Core strips this (like balance) for S-ABR — Lambda refills from stored record.
    /// Presence indicates receiver has consented to receive scarred money.
    /// None = no scar (normal TX) or first attempt (validator will pause and notify).
    pub scar_passcode: Option<u32>,

    /// Burn target TX ID (YPX-001 §1.5.4)
    /// When set, this TX is a burn: money sent to BURN_ADDRESS to resolve a scarred
    /// FACT link. The target is the tx_id of the scarred link being burned.
    /// Requires receiver_wallet_id == BURN_ADDRESS.
    pub burn_target_tx_id: Option<[u8; 32]>,

    /// YPX-022 RECALL — the failed (sub-quorum) send this recall reclaims.
    /// Audit reference only: the AUTHORITATIVE target + pre-send state rides
    /// the Nabla recall attestation (§2.1/§2.2). This documents the recalled
    /// txid on the RECALL tx (mirrors `burn_target_tx_id`).
    pub recall_target_tx_id: Option<[u8; 32]>,

    /// YPX-012: Oracle claim data (optional). When present, this TX is an oracle claim.
    /// Core enforces: sender == receiver, k >= 5, platform whitelisted, living signature.
    /// Validators independently verify platform credits before witnessing.
    #[serde(default)]
    pub oracle_claim: Option<OracleClaimData>,

    /// YPX-007: Required number of validators (0, 3, 4, or 5).
    /// Core-filled from wallet_id extraction — sender MUST NOT set this.
    /// Persisted for S-ABR overlap on the next transaction.
    #[serde(default)]
    pub required_k: u8,

    /// YPX-007: Proof type (0=zkvm, 1=dmap, 2=ark).
    /// Core-filled from wallet_id extraction — sender MUST NOT set this.
    #[serde(default)]
    pub proof_type: u8,

    /// Core version tag (e.g. "Kyoto/1.1/GENESIS").
    /// Checked at the very beginning of validate_transaction().
    /// Can be faked — real verification is the ELF hash (DMAP CoreID / ZKP IMAGE_ID).
    /// This is a cheap pre-filter to reject incompatible transactions early.
    #[serde(default)]
    pub core_version: String,

    /// BLAKE3 of the Core ELF the sender ran when building this TX.
    /// This is the **authoritative** version gate — `core_version` is the
    /// human label, `core_id` is the machine check. Step -1.5 of CL2:
    /// if non-zero and != `PublicInputs.local_core_id`, fast-reject with
    /// `ValidationError::CoreIdMismatch` before any DMAP / signature work.
    ///
    /// Empty (all-zero) is accepted for backward compat with TXs built
    /// before this field existed.
    ///
    /// Sender (SDK) reads this from `axiom_sdk::runtime().local_core_id`
    /// (which is `BLAKE3(elf_bytes)` computed at `setup()` time).
    /// Validators read theirs from compile-time `CANONICAL_CORE_ID`
    /// (release builds) or the same runtime hash (dev builds).
    #[serde(default)]
    pub core_id: [u8; 32],

    /// Discriminant for the protocol-level operation this transaction
    /// performs. Replaces the v2.x bool sprawl (`is_heal`,
    /// `is_genesis_claim`) so future ops add a `TxKind` variant instead
    /// of a new flag. Type-system enforces mutual exclusion: a TX can
    /// be exactly one of these.
    ///
    /// Helpers `tx.is_heal()`, `tx.is_genesis_claim()`,
    /// `tx.is_validator_withdrawal_mint()` exist for ergonomic reads
    /// at call sites that don't need exhaustive matching.
    #[serde(default)]
    pub kind: TxKind,
}

/// The `AXIOM_WITNESS_V2` preimage of one witnessed transaction — the six
/// fields `compute_commitment_hash` binds (`txid` binds the same six plus the
/// transaction's `epoch`).
///
/// Carried so that ANY node, holding no local state, can recompute a leg's
/// `commitment_hash` (→ `receipt_commitment`, which the k witnesses signed)
/// and its `txid` — AXIOM_DESIGN_ForkSettlement.md §2.2 (the self-proving
/// fork evidence) and R11 (the `OriginRecord` a Nabla node vouches for, bound
/// to the cheque by txid RECOMPUTATION, §3.2).
///
/// Byte layout for hashing is defined ONLY by the field-wise inner builders
/// `validation::compute_commitment_hash_parts` and
/// `crypto::compute_txid_parts` (via [`WitnessPreimage::commitment_hash`] /
/// [`WitnessPreimage::txid`]). This struct's serde encoding is a CARRIER
/// format, never a hash preimage — do not hash its CBOR (Pattern 1).
///
/// `client_pk` is the 32-byte Ed25519 key the fork-claim `client_sig` is
/// checked under (§2.2 step 3). `Transaction.client_pk` is a `Vec<u8>`; a
/// transaction whose key is not 32 bytes has no `WitnessPreimage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessPreimage {
    pub consumed_state_id: [u8; 32],
    pub client_pk: [u8; 32],
    pub wallet_seq: u64,
    pub receiver_wallet_id: String,
    pub amount: u64,
    pub nonce: u64,
}

impl WitnessPreimage {
    /// The `AXIOM_WITNESS_V2` commitment — calls the ONE inner builder.
    pub fn commitment_hash(&self) -> [u8; 32] {
        crate::validation::compute_commitment_hash_parts(
            &self.consumed_state_id,
            &self.client_pk[..],
            self.wallet_seq,
            &self.receiver_wallet_id,
            self.amount,
            self.nonce,
        )
    }

    /// The `AXIOM_TXID` txid under `epoch` — calls the ONE inner builder.
    pub fn txid(&self, epoch: u64) -> [u8; 32] {
        crate::crypto::compute_txid_parts(
            &self.consumed_state_id,
            &self.client_pk[..],
            self.wallet_seq,
            &self.receiver_wallet_id,
            self.amount,
            self.nonce,
            epoch,
        )
    }
}

/// The preimage of one CL5 REDEEM leg — exactly the five inputs
/// `validation::compute_redeem_commitment` binds (`modes.rs` Step 10), so ANY
/// node holding no local state can recompute the redeem leg's
/// `commitment_hash` (→ `receipt_commitment`, which the k witnesses signed).
/// AXIOM_DESIGN_ForkSettlement.md §9g / spec R52c (P6, the [R8] follow-on —
/// `consumed_state_id` has been inside the redeem commitment since wave 2b-ii,
/// 388a4bce). Carried as the payload of
/// [`crate::nabla_wire::LegPreimage::Redeem`]; 136 bytes of field data.
///
/// Fields, in the builder's order:
/// * `cheque_txid` — the cheque's txid (`ChequeBundle::txid()`), which IS the
///   origin send's txid; the redeem registers under it.
/// * `receiver_pk` — the redeeming wallet's 32-byte Ed25519 key
///   (`PublicInputs.receiver_pk`).
/// * `new_balance` — the receiver's post-redeem balance (`PublicOutputs.new_balance`).
/// * `new_state_id` — the receiver's produced state (`PublicOutputs.produced_state_id`).
/// * `consumed_state_id` — the receiver's pre-redeem state, RECEIVER-DECLARED
///   (`modes::cl5_consumed_state_id`: `current_state.state_id`, zero when
///   absent — CL5 runs no §15 anchor on it; spec F8 / R52e).
///
/// Byte layout for hashing is defined ONLY by `compute_redeem_commitment`
/// (via [`RedeemPreimage::commitment_hash`]); this struct's serde encoding is a
/// CARRIER format, never a hash preimage (Pattern 1). Build it from a CL5 run
/// with `nabla_wire::LegPreimage::redeem_of_cl5` (the ONE constructor) and
/// verify with `validation::redeem_preimage_matches` (the ONE verifier).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedeemPreimage {
    pub cheque_txid: [u8; 32],
    pub receiver_pk: [u8; 32],
    pub new_balance: u64,
    pub new_state_id: [u8; 32],
    pub consumed_state_id: [u8; 32],
}

impl RedeemPreimage {
    /// The `AXIOM_REDEEM_WITNESS` commitment — calls the ONE builder.
    pub fn commitment_hash(&self) -> [u8; 32] {
        crate::validation::compute_redeem_commitment(
            &self.cheque_txid,
            &self.receiver_pk[..],
            self.new_balance,
            &self.new_state_id,
            &self.consumed_state_id,
        )
    }
}

/// Which commitment builder a carried leg's preimage recomputes to —
/// AXIOM_DESIGN_ForkSettlement.md §2.2 ("Redeem legs [R8, Q7]") and §3.2
/// (`OriginRecord.kind`). A different axis from [`TxKind`]: every `TxKind`
/// (Normal / Heal / Recall / HAL …) is structurally SEND-shaped and hashes
/// through `compute_commitment_hash`; `Redeem` selects the redeem commitment.
/// No `Default`: a leg's kind is always stated, never assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LegKind {
    Send,
    Redeem,
}

/// The origin leg a Nabla node vouches for inside a [`NablaTxidAttestation`] —
/// AXIOM_DESIGN_ForkSettlement.md §2.4 / §3.2 [R11], YPX-001 §1.5.1b. The node's
/// own TXID RECORD of the leg: the whole `AXIOM_WITNESS_V2` preimage, the epoch it
/// was witnessed in, and which commitment builder it recomputes through.
///
/// Core binds it to the cheque by RECOMPUTATION — `preimage.txid(epoch)` must equal
/// the cheque's txid (the registrant's `client_pk` is inside that preimage), so no
/// key has to be carried or trusted. Bound into the attestation's signed payload by
/// the ONE builder `crypto::txid_attest_payload` through a field-wise canonical
/// encoding (never this struct's CBOR — Pattern 1, see [`WitnessPreimage`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginRecord {
    pub preimage: WitnessPreimage,
    pub epoch: u64,
    pub kind: LegKind,
}

/// ForkSettlement §9p (KI#221 closure residual 1, 2026-09-30) — the SIGNED
/// origin status a Nabla node states inside its [`NablaTxidAttestation`]: what
/// its OWN records say about the origin of `txid`, so a receiver can tell an
/// honest WAIT from a HOLD without guessing (before §9p the node signed the SAME
/// empty attestation for both).
///
/// * `Vouched` — the node vouches the origin (`origin` is `Some`). The ONLY
///   status under which Core's settle rule (`fact::origin_settle_ready_at`)
///   can ever hold.
/// * `Held` — the origin descends from a fork or a held receive in the node's
///   records (`provenance::Judgment::Held`, or its `(pk, consumed)` key holds
///   ≥ 2 legs). `origin` is `None`. Never settles.
/// * `Unknown` — anything else: not listening, no record, a re-derivation
///   queued, the input not grounded here yet, contested-not-held. `origin` is
///   `None`. Never settles.
///
/// Consistency (Core, `fact::txid_attestation_origin_consistent`): `Vouched`
/// ⇔ `origin.is_some()`. A mismatch is a MALFORMED attestation — refused like a
/// bad signature. Bound into the ONE payload builder `crypto::txid_attest_payload`
/// as one byte ([`OriginVouchStatus::payload_byte`]), so a relay cannot flip it.
/// LIVENESS ONLY for the receiver's SDK: `Held` stops the SDK's bounded wait;
/// it can never clear money (a hostile node lying `Held` only makes the consent
/// prompt appear sooner). `Default` = `Unknown` (fail-closed: never settles).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum OriginVouchStatus {
    #[default]
    Unknown,
    Vouched,
    Held,
}

impl OriginVouchStatus {
    /// The byte `crypto::txid_attest_payload` binds — fixed, never the serde
    /// form (Pattern 1): `Unknown = 0x00`, `Vouched = 0x01`, `Held = 0x02`.
    pub const fn payload_byte(self) -> u8 {
        match self {
            OriginVouchStatus::Unknown => 0x00,
            OriginVouchStatus::Vouched => 0x01,
            OriginVouchStatus::Held => 0x02,
        }
    }
}

/// What kind of operation a `Transaction` performs. Mutually exclusive
/// by construction.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxKind {
    /// Default — a normal value-transfer transaction (Alice → Bob).
    #[default]
    Normal,

    /// YPX-018 Phase 5f — TX_HEAL self-send marker.
    ///
    /// CLARA wallet-recovery self-send: the wallet sends to itself to
    /// produce a real ChequeBundle for `POST /clara`. Relaxes the
    /// §11.9.4 self-send rejection (normally only Ark wallets can
    /// self-send). Otherwise goes through normal CL1 validation, k=3
    /// witnessing, FACT chain, scar handling, etc. Does NOT bypass any
    /// security check — only gates the self-send rejection rule.
    ///
    /// Reference: YPX-018 §2.4, Yellow Paper §17.10.14.
    Heal,

    /// New-wallet airdrop claim. Relaxes S-ABR (no prev_receipts) and
    /// self-send rejection. Core validates `wallet_seq == 1`, `prev_seq
    /// == 0`, `amount == 0`. Validators issue `GENESIS_CLAIM_AMOUNT`
    /// cheque; Nabla controls the pool balance.
    ///
    /// Reference: Yellow Paper §17.11.
    GenesisClaim,

    /// §10.0 FOB fee-claim (2026-08-10 ruling; replaces the retired Step 9B
    /// TCP model, KI#83). A NO-DEBIT self-send from the validator's ATTACHED
    /// (stake) wallet that sweeps the FULL Bounded-Fee pool: Core's CL2 gate
    /// requires a `FobClaimAttestation` and pins amount (== full pool),
    /// claimant (== the SPHINCS+-registered linked wallet) and class
    /// (is_dev_wallet == att.is_dev, the §10.2a last-mile). Rides the ordinary
    /// client-carried k=3 round (no S-ABR); Nabla verifies twice (register +
    /// claim) and sweeps the pool consume-once; the CL5 redeem of the claim
    /// cheque is the only balance write. `AXIOM_DESIGN_BoundedPools.md` §10.0.
    ValidatorWithdrawalMint,

    /// YPX-020 HAL — dead-overlap re-anchor self-send.
    ///
    /// A wallet whose prior witnesses have vanished cannot assemble the
    /// `k-1` S-ABR overlap and is stuck. A HAL re-anchor `X → X'` is
    /// witnessed by FRESH validators and **relaxes the overlap check**
    /// (modes.rs CL2). It does NOT relax the double-spend gate: that role
    /// moves to Nabla, which (1) rejects the re-anchor register until the
    /// convergence wait has elapsed (so a concurrent spend converges first)
    /// and (2) rejects it if `old_state` is in the monotonic consumed-state
    /// bloom (replay of an already-spent state). Core's relaxation MUST NOT
    /// deploy without that Nabla wait+bloom — they are one safety unit.
    ///
    /// Reference: YPX-020 §2/§6.
    ///
    /// YPX-020 §2 (2026-06-23): there is NO `HalComplete` kind. Completion is the
    /// REDEEM of the re-anchor's distress cheque (a self-send), which clears the
    /// hibernation lock on its produced state (see `modes.rs::execute_cl5`). The
    /// separate completion self-send was removed.
    HalReanchor,

    /// YPX-022 — RECALL self-send: reclaim a *failed* (sub-quorum, < k) send whose
    /// cheque the receiver can never redeem. Like `HalReanchor` it re-anchors with
    /// fresh witnesses and rides the binary hibernation lock, but its overlap
    /// substitute is the `< k` + window gate — the same `cheques.len() < required_k`
    /// predicate CL5 uses to reject a redeem (`modes.rs`) — and it consumes the
    /// target cheque at Nabla so the receiver's later redeem dies. Discriminator
    /// only for now; the gate + wire flag land in later steps (build plan
    /// `docs/AXIOM_BUILD_RECALL_OODS_v1.md`).
    Recall,

    // ╔═ BOOTSTRAP SUBSIDY — REMOVE WHEN POOLS DRAIN ═══════════════╗
    // Removal: delete this block. Nothing outside the feature refers
    // to it. Pools: Bootstrap (400x500), FoundationBootstrap (5x500k).
    // Design: AXIOM_DESIGN_ValidatorJoin.md §5.2.5
    // ╚═════════════════════════════════════════════════════════════╝
    //
    // ⚠ THE VARIANTS AND THEIR WIRE EMITS ARE **UNCONDITIONAL** — they are NOT
    // behind `bootstrap-subsidy`, and must not be. A `TxKind` present only under
    // a feature changes the canonical CBOR, and therefore the transaction byte
    // length, the receipt commitment and the CoreID: two builds of one source
    // would be two protocol versions, i.e. a mesh split by compile flag. Only
    // the LOGIC is gated. Removal is therefore TWO ACTS (§5.2.5): drop the
    // feature (free, any time), then retire the variants at some later rotation
    // that is happening anyway. Between the two acts a stale claim degrades to
    // `Normal` on the canonical wire, is DEBITED rather than credited, hits an
    // empty wallet and is rejected on insufficient balance — it fails closed.

    /// `AXIOM_DESIGN_ValidatorJoin.md` §5.2.3 — tier-2 (Foundation) stake claim.
    /// Credits `TIER2_CLAIM_ATOMS` (register `tier2_claim_axc`) from the
    /// `FoundationBootstrap` pool, `FOUNDATION_SUBSIDISED_SLOTS` seats. Same shape as `GenesisClaim`: `wallet_seq == 1`, the
    /// claimant's wallet starts empty, and the value comes from a Nabla-held
    /// pool rather than the sender's balance.
    ///
    /// TWO kinds rather than one because the pools drain at different times
    /// (5 slots vs 400), so each must be deletable on its own schedule. The
    /// single `ValidatorJoin` kind this replaces was reverted (`95b3d192`)
    /// because it credited UNCONDITIONALLY — correct for a pool-funded joiner,
    /// wrong for the SELF-FUNDED one, who already holds the stake and would be
    /// credited twice. A self-funded joiner submits NEITHER kind, so the
    /// ambiguity cannot arise (§5.2.3).
    ValidatorFoundationStakeClaim,

    /// §5.2.3 — tier-3 (Community) stake claim. Credits `TIER3_CLAIM_ATOMS`
    /// (register `tier3_claim_axc`) from the `Bootstrap` pool,
    /// `COMMUNITY_SUBSIDISED_SLOTS` slots. Sibling of
    /// `ValidatorFoundationStakeClaim`; see its doc for why there are two.
    ValidatorCommunityStakeClaim,

    /// §5.2.2d — a request for a VBC. An ORDINARY transaction in every respect
    /// (advances seq, obeys S-ABR, recallable, registers with Nabla); the ONLY
    /// difference is what the k=3 witnesses return: a certificate signed via
    /// CL8 instead of a value cheque. The three witnesses ARE the three issuers,
    /// which is why `VBC_REQUIRED_ISSUERS == 3` equals k.
    ///
    /// The requester does NOT choose provisional vs full — the issuer decides
    /// from the balance already carried in the request (anchored to the k-signed
    /// prev receipt), by setting the expiry. CL8 enforces the rest.
    VbcRequest,

    /// Contribution emission claim (`AXIOM_DESIGN_ValidatorEmission.md`, YP
    /// §25.2.4 v2.21.0). The SAME shape as `ValidatorWithdrawalMint`: a
    /// NO-DEBIT self-send from the claimant's OPERATIONAL wallet carrying a
    /// `FobClaimAttestation` with `pool == FOB_CLAIM_POOL_EMISSION`; Core's CL2
    /// gate verifies the attestation and pins amount / claimant / class / pool;
    /// no S-ABR overlap (pool-side consume-once, like the airdrop); the CL5
    /// redeem of the claim cheque is the only balance write. One claim per
    /// (identity, epoch) — enforced by the Nabla writer, which recomputes the
    /// epoch share before the register commits. Appended LAST (wire order).
    EmissionClaim,
}

/// §12 — **`kind` TRAVELS ON THE WIRE. There is no discriminator mapping.**
///
/// ⚠ **READ THIS BEFORE ADDING A `TxKind`.** Until 2026-09-07 the canonical
/// encoder decomposed `kind` into SEVEN parallel `is_*` bools, and FOUR
/// hand-maintained decoders re-assembled it — because the typed `Transaction`
/// is `deny_unknown_fields`, so a bool nobody stripped rejected the ENTIRE
/// decode. CLAUDE.md records what that cost: "Miss one and the typed
/// `Transaction` rejects **EVERY** transaction, not just the new kind — a fresh
/// wallet could not claim genesis." Missing the RECONSTRUCTION instead of the
/// strip was the quiet half: `kind` degraded to `Normal`, so a claim was
/// DEBITED rather than credited and HAL/RECALL silently lost their overlap
/// relaxation.
///
/// **The wrong reading that kept it alive** was this encoder's own contract
/// comment, which claimed the canonical bytes "are what `client_sig` is
/// computed over". They are not, and never were. Every cryptographically-bound
/// preimage in AXIOM is built from EXPLICIT FIELDS, never from this CBOR:
/// `compute_signing_message` (validation.rs), `compute_txid` /
/// `compute_receipt_commitment` (crypto.rs) and `compute_commitment_hash`
/// (validation.rs) each hash named fields one at a time. CLAUDE.md §13 states
/// the same rule ("txid/commitment hash EXPLICIT FIELDS, never the canonical
/// CBOR"). This encoder is a pure WIRE ENVELOPE: changing it invalidates
/// nothing at rest — not a receipt, not a signature, not a wallet file.
///
/// So `kind` is emitted directly, as the serde representation the typed decoder
/// already expects, and the four decoders reconstruct nothing. Adding a variant
/// is now a one-line change to the enum: the encoder carries it, every decoder
/// reads it, and no site can be "missed".
///
/// Guarded by `canonical_cbor_tests` below, which drives the REAL encoder into
/// the REAL typed decoder for every member of [`TxKind::ALL`].
impl TxKind {
    /// Every variant, so a round-trip test cannot silently miss a new one.
    ///
    /// ⚠ Adding a variant WITHOUT adding it here leaves the guard passing over a
    /// smaller set — the "check that cannot fail" shape. Nothing else forces
    /// this list, so it IS the coverage: the canonical round-trip test below
    /// iterates it, and a variant left out is simply never driven.
    pub const ALL: [TxKind; 9] = [
        TxKind::Normal,
        TxKind::Heal,
        TxKind::GenesisClaim,
        TxKind::ValidatorWithdrawalMint,
        TxKind::HalReanchor,
        TxKind::Recall,
        TxKind::ValidatorFoundationStakeClaim,
        TxKind::ValidatorCommunityStakeClaim,
        TxKind::VbcRequest,
    ];
}


/// YPX-020 — HIBERNATION window: epochs a wallet is held "out of work" after a
/// HAL re-anchor, so a concurrent spend converges (fork→ban) before the
/// re-anchored funds become spendable again. Enforced at Core CL2 + Nabla.
/// Production = ~the 25 h convergence wait. Dev-mode shortens it to 50 ticks
/// (50 × TICK_INTERVAL_SECS = ~250s, ~4 min) so the soak can drive a full
/// re-anchor → hibernate → unhibernate cycle quickly while still OUTLASTING the
/// ~30–50s witness round — the window is stamped at the re-anchor's TX epoch
/// (round start), so a too-short value (the old 10 = 50s) elapses before
/// hal_reanchor even returns and the UI countdown reads as a dead timer.
/// NB: this is baked into the ELF, so the dev CoreID ≠ the prod CoreID (expected).
/// Single source: protocol_core.toml `[timing]` (2026-07-07 consolidation) —
/// dev/prod selected by the build.rs `_dev`-pair codegen. See the toml key
/// docs; the prod/dev values are unchanged (18000 / 50).
pub use crate::validation::HIBERNATION_WINDOW;

/// YPX-022 RECALL maturity window — the ONE time mechanism RECALL has, and it is the
/// SAME mechanism HAL uses: the wallet carries `produced_hibernation_until` in its
/// k-witnessed state (via `hibernation_until_for`) and Core binary-gates it. HAL and
/// RECALL differ ONLY in this duration constant.
///
/// ⚠ CORRECTED 2026-09-05. This doc said "Core binary-gates it, **Nabla enforces
/// the tick-wait on completion**". NABLA ENFORCES NOTHING HERE, and that is
/// DELIBERATE, not a gap: `GossipMessage::Hibernation` is unauthenticated, so any
/// peer can assert `(client_pk, until)` for any wallet. Nabla's map is therefore
/// INFORMATIONAL — its only read clears the entry — and gating on it would turn
/// one forged packet into a permanent send-lock on any wallet by public key
/// (`g9_forged_hibernation_cannot_block_a_register`; ghost audit G9). A gate was
/// built on the strength of this comment on 2026-09-05 and reverted the same day
/// when that test caught it.
///
/// So the WAIT ITSELF IS CLIENT POLICY, enforced by nobody: `register_cheque_claim`
/// is explicitly "Clockless — the client self-times the window". Making it real
/// needs the Hibernation gossip to carry the k=3 register attestation first
/// (YPX-020 §2b). Do not describe this window as enforced until that lands.
/// Tick count, projected exactly like `HIBERNATION_WINDOW`. Baked into the ELF →
/// dev CoreID ≠ prod CoreID (expected). Prod value tuned against TARDIS cadence.
/// Single source: protocol_core.toml `[timing]` (720 / 20 dev, unchanged).
pub use crate::validation::RECALL_HIBERNATION_WINDOW;
/// Dev-WALLET (`@axiom.internal`) short windows — see `hibernation_until_for`.
pub use crate::validation::{DEV_WALLET_HIBERNATION_WINDOW, DEV_WALLET_RECALL_HIBERNATION_WINDOW};
/// YPX-022 §2.1 recall initiation window — protocol_core.toml `[timing]`
/// ([18000, 50000] prod / [10, 100000] dev, unchanged). Exposed HERE (the
/// ELF-bound protocol surface) so Nabla and the Mac FFI read the SAME
/// constant instead of hand-mirroring it (Mac's drift ask, 2026-07-07).
pub use crate::validation::{RECALL_INIT_WINDOW_LOW, RECALL_INIT_WINDOW_HIGH,
    RECALL_INIT_WINDOW_LOW_DEV, RECALL_INIT_WINDOW_HIGH_DEV, recall_init_window};
/// CL5 cheque-claim-proof freshness bound — protocol_core.toml
/// `cheque_claim_proof_max_age_ticks` (KI#205). Read it WITH the recall window.
pub use crate::validation::CHEQUE_CLAIM_PROOF_MAX_AGE_TICKS;

/// KI#205 (YPX-022 §2.1.2a, RULED 2026-09-25) — the cheque-claim registers must
/// keep the order the `protocol_core.toml` comment block states, or the recall
/// gate is a ghost:
///
/// * `cheque_claim_proof_max_age_ticks < recall_init_window_low` — CL5's proof
///   FRESHNESS bound must expire BEFORE a recall can open. If it did not, a
///   proof's freshness would look like what blocks a recall, and a patient
///   receiver could wait it out (that was the hole). The thing that blocks a
///   recall is the AUTHENTICATED CLAIM Nabla holds until `recall_init_window_high`.
/// * `recall_init_window_low < recall_init_window_high` — the window is non-empty.
///
/// PROD registers only: the claim freshness has NO dev twin while
/// `recall_init_window_low_dev` is 10, so the dev fleet deliberately inverts the
/// first inequality (the toml explains why a gate proving this ruling must ask
/// `register_recall` directly). Asserting the dev pair here would be asserting
/// the inversion; asserting prod is what protects real money.
///
/// ⚠ A REAL const assertion (evaluates the registers, fails the build) — not the
/// empty `const _X: () = {}` shape RULE 3 calls a ghost.
const _CHEQUE_CLAIM_REGISTERS_KEEP_THE_RULED_ORDER: () = {
    assert!(
        CHEQUE_CLAIM_PROOF_MAX_AGE_TICKS.0 < RECALL_INIT_WINDOW_LOW.0,
        "KI#205: cheque_claim_proof_max_age_ticks must be SHORTER than recall_init_window_low          (protocol_core.toml) — the CL5 proof-freshness bound must never be what blocks a recall"
    );
    assert!(
        RECALL_INIT_WINDOW_LOW.0 < RECALL_INIT_WINDOW_HIGH.0,
        "YPX-022 §2.1: recall_init_window_low must be below recall_init_window_high"
    );
};

/// Seconds per tick — the protocol's maximum inter-tick interval (a TARDIS tick
/// is generated from unix time with an `age <= 5s` freshness bound; it can be
/// faster but never slower). `epoch`/`tick` values are unix-second stamps, so a
/// window expressed in TICKS is projected onto a stamp by multiplying by this
/// bound: real ticks arrive faster, so the projected stamp is an upper bound the
/// actual tick never passes — the window holds for AT LEAST that many ticks.
/// Mirrors `axiom_nabla::constants::TICK_INTERVAL_SECS`.
pub const TICK_INTERVAL_SECS: u64 = crate::validation::protocol_gen::TICK_INTERVAL_SECS;

/// THE single tick-count → unix-second projection. Every window expressed in
/// TICKS (recall init window, hibernation windows, cheque maturity) projects onto
/// the unix-second `tick`/`epoch` scale through THIS one function — never an
/// inline `* TICK_INTERVAL_SECS` (which is where the copies drifted, and where one
/// silently went wrong: see [`TickCount`]). Real ticks arrive at most
/// `TICK_INTERVAL_SECS` apart, so the projected stamp is an upper bound the actual
/// tick never passes — the window holds for AT LEAST `ticks` ticks.
pub const fn ticks_to_secs(ticks: u64) -> u64 {
    ticks.saturating_mul(TICK_INTERVAL_SECS)
}

/// A COUNT of TARDIS ticks — NOT a tick VALUE (a unix-second stamp) and NOT a
/// duration in seconds. It exists as a COMPILE-TIME GUARD against the
/// tick-count-vs-tick-value confusion that has now bitten three times: most
/// recently the RECALL init window compared a seconds-difference
/// (`current_tick - completion_tick`, both unix-second stamps) directly against a
/// raw tick COUNT, so the window opened ~5× early (`TICK_INTERVAL_SECS`×) and
/// shortened the receiver's guaranteed no-recall protection.
///
/// The ONLY way to get a comparable unix-second quantity out of a `TickCount` is
/// [`TickCount::to_secs`], which routes through [`ticks_to_secs`]. Because the
/// window constants are `TickCount`, a raw `age_secs < RECALL_INIT_WINDOW_LOW` no
/// longer type-checks — the author is forced to write
/// `age_secs < RECALL_INIT_WINDOW_LOW.to_secs()`, and the mistake cannot recur.
///
/// Core-owned: this is the ELF-bound protocol surface. Nabla and the FFI import
/// the window constants AND this projection from here, so the eligibility math is
/// defined ONCE, by Core, and every enforcer agrees on the exact window.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TickCount(pub u64);

impl TickCount {
    /// Project this tick COUNT onto the unix-second scale that `tick`/`epoch`
    /// stamps live on. THE ONLY projection — delegates to [`ticks_to_secs`].
    /// Compare a tick-VALUE difference (an age in seconds) against THIS, never
    /// against [`TickCount::ticks`].
    pub const fn to_secs(self) -> u64 {
        ticks_to_secs(self.0)
    }

    /// The raw tick count, for arithmetic that legitimately stays in tick-count
    /// space (e.g. selecting a hibernation window before it is projected). Does
    /// NOT project — never compare the result against a tick-VALUE difference.
    pub const fn ticks(self) -> u64 {
        self.0
    }
}

/// THE ONE selection site for an ACCOUNT-KEYED dev/real timing value
/// (`AXIOM_DESIGN_AccountKeyedDevTiming.md`, Q4). Every account-scoped timer picks
/// its value HERE — never behind a `#[cfg(feature = "dev-mode")]` build switch, so a
/// dev account and a real account run their own clocks on ONE (mainnet) binary and a
/// logic bug in the selection is fixed in one place.
///
/// ⚠ This helper only SELECTS. It VERIFIES nothing: `is_dev_class` is the k-signed
/// `is_dev_wallet(sender)` flag bound into `receipt_commitment`, and its verification
/// stays upstream at receipt verification (a forged flag never reaches a real window —
/// `AXIOM_DESIGN_FactClassIsolation.md`). Do NOT add a class check in here, and do NOT
/// assume `dev <= real`: some pairs invert (e.g. `RECALL_INIT_WINDOW_HIGH_DEV` >
/// `RECALL_INIT_WINDOW_HIGH`). The `check_dev_timing` preflight gate fails any
/// account-scoped `_dev` read that does not go through this function.
#[inline]
pub fn dev_or_real<T>(is_dev_class: bool, dev_value: T, real_value: T) -> T {
    if is_dev_class { dev_value } else { real_value }
}

/// The SINGLE hibernation-deadline projection, shared by Core (`produced_hibernation_until`),
/// Nabla (the re-anchor register stamp), and the SDK (§15 local set). Returns
/// `base_tick + window_ticks·TICK_INTERVAL_SECS`, or `0` (not hibernating) when `window == 0`.
/// HAL and RECALL both go through this; they differ ONLY in the window value passed in — the
/// projection logic exists in one place, not per-layer/per-kind.
/// THE SINGLE SOURCE OF HIBERNATION TRUTH — kind → window → deadline, all in one function.
/// The re-anchor hibernation deadline stamped on `base_tick`: HAL and RECALL both go through
/// this and differ ONLY in the window constant selected; any other kind → 0 (not hibernating).
/// Core (`produced_hibernation_until` / the §15 state binding), Nabla (the register stamp),
/// and the SDK (the §15 local mirror) ALL call this one function — a hibernation bug is fixed
/// in exactly one place. `WINDOW` is a TICK count projected onto the unix-sec `base_tick` via
/// the `<= TICK_INTERVAL_SECS`/tick bound, so the lock holds for at least `WINDOW` ticks.
pub fn hibernation_until_for(
    base_tick: u64,
    is_hal_reanchor: bool,
    is_recall: bool,
    is_dev_class: bool,
    // §5.2.2c — the tier-2 / tier-3 subsidy stake claim kinds. A stake claim
    // hibernates by EXACTLY this path: the KIND selects the window here, as HAL's
    // and RECALL's do. Nothing else is stake-specific.
    is_foundation_stake_claim: bool,
    is_community_stake_claim: bool,
) -> u64 {
    // The dev-WALLET short window applies ONLY when `is_dev_class` is set — the k-signed
    // flag Core computes as `is_dev_wallet(sender)` and binds into `receipt_commitment`.
    // A PUBLIC wallet (is_dev_class=false) ALWAYS gets the full window below; a forged
    // is_dev_class=true is caught by Core's k-signed receipt verification. So this can
    // NEVER shorten a real (public) wallet's hibernation — it cannot touch real money.
    // All THREE callers supply the SAME authoritative flag (Core = is_dev_wallet(sender),
    // Nabla = reg.receipt.is_dev_class, SDK = wallet.is_dev_class()), keeping the §15
    // Core↔Nabla↔SDK lock-step exact.
    let window_ticks = if is_hal_reanchor {
        dev_or_real(is_dev_class, DEV_WALLET_HIBERNATION_WINDOW, HIBERNATION_WINDOW)
    } else if is_recall {
        dev_or_real(is_dev_class, DEV_WALLET_RECALL_HIBERNATION_WINDOW, RECALL_HIBERNATION_WINDOW)
    } else if is_foundation_stake_claim {
        crate::validation::protocol_gen::TIER2_STAKE_LOCK_TICKS
    } else if is_community_stake_claim {
        crate::validation::protocol_gen::TIER3_STAKE_LOCK_TICKS
    } else {
        return 0;
    };
    base_tick.saturating_add(window_ticks.saturating_mul(TICK_INTERVAL_SECS))
}

/// §5.2.2c — THE claim time cross-check, in one place so a test can drive the
/// real rule rather than re-derive it beside the code (RULE 6 §3a).
///
/// Two independent accounts of ONE moment — the claim's witness round — must
/// agree. Core reads no clock here; it checks two SUPPLIED numbers against each
/// other, which is why this does not make the design trust a wall clock. Full
/// rationale: `AXIOM_DESIGN_ValidatorJoin.md` "Why a wall clock is admissible
/// HERE".
///
/// * `hibernation_until` — k-attested, stamped at the claim SEND as
///   `tx.epoch + window_ticks x TICK_INTERVAL_SECS`, so subtracting the same
///   window recovers the CLAIMANT's declared epoch. The two sides read the same
///   register, so they cannot drift apart.
/// * `issuer_time` — the ISSUERS' `created_at` (take the max across the k
///   cheques; a single honest issuer then disagrees with a backdated claimant).
///
/// FAILS CLOSED: an absent hibernation stamp recovers 0, which disagrees with any
/// real clock and refuses the claim.
///
/// ⚠ PRIVATE ON PURPOSE — see [`stamp_stake_lock`]. A caller that can ask "do the
/// accounts agree?" separately from "what is the deadline?" can also forget to
/// ask, and nothing goes red. The only way in is through the stamp.
fn claim_time_accounts_agree(
    hibernation_until: u64,
    window_ticks: u64,
    issuer_time: u64,
) -> bool {
    let claimant_time =
        hibernation_until.saturating_sub(window_ticks.saturating_mul(TICK_INTERVAL_SECS));
    claimant_time.abs_diff(issuer_time)
        <= crate::validation::protocol_gen::STAKE_LOCK_TIME_RANGE_SECS
}

/// §5.2.2c — the wall-clock lock deadline: `base_unix + lock_secs`.
///
/// `base_unix` is the claim cheque's epoch and `lock_secs` is already a span in
/// seconds, so nothing is projected here. A tick COUNT must never be added to
/// this: a tick is a VECTOR (protocol progress) and a wall clock is a UNIT (real
/// time) — same unix encoding, different kinds (the owner, 2026-09-05).
///
/// ⚠ PRIVATE ON PURPOSE — see [`stamp_stake_lock`]. This is the value an attacker
/// wants; it must not be obtainable without the cross-check having run.
fn wall_clock_lock_deadline(base_unix: u64, lock_secs: u64) -> u64 {
    base_unix.saturating_add(lock_secs)
}

/// §5.2.2c — **THE stake-lock stamp: the cross-check and the deadline are ONE
/// operation.** This is the only way to obtain a `wall_clock_lock` value.
///
/// **Why it is shaped this way (RULE 6, 2026-09-05).** The two halves used to be
/// two public functions, and `execute_cl5` called them in sequence. Breaking the
/// RULE was caught by a unit test; *deleting the call* was not — and the call site
/// cannot be reached by a unit test at all, because a claim redeem needs a
/// `ChequeClaimProof` carrying an NBC chain rooted in the pinned
/// `NABLA_ROOT_AUTHORITY_PKS` (SPHINCS+), which no test can mint (the same wall
/// `modes.rs` records for existing tests). So the check was verified and its
/// PRESENCE was not. Fusing them removes the gap without an environment: a
/// deadline now exists only as the `Ok` of the check, so deleting the check
/// deletes the stamp and the caller stops compiling.
///
/// ⚠ Do NOT re-expose [`claim_time_accounts_agree`] or [`wall_clock_lock_deadline`],
/// and do not compute `issuer_time + lock_secs` at a call site. Either move
/// reopens exactly the hole this shape closes.
///
/// * `hibernation_until` / `window_ticks` / `issuer_time` — the cross-check's two
///   accounts of the claim's witness round; see [`claim_time_accounts_agree`].
/// * `lock_secs` — the tier's lockup SPAN in seconds (`TIER*_LOCKUP_SECONDS`),
///   added to the ISSUERS' time, never to the claimant's `epoch`.
pub fn stamp_stake_lock(
    hibernation_until: u64,
    window_ticks: u64,
    issuer_time: u64,
    lock_secs: u64,
) -> Result<u64, ValidationError> {
    if !claim_time_accounts_agree(hibernation_until, window_ticks, issuer_time) {
        return Err(ValidationError::StakeLockTimeDisagreement);
    }
    Ok(wall_clock_lock_deadline(issuer_time, lock_secs))
}

/// The absolute quorum floor (CLAUDE §16 / YP §17.1.2): every ONLINE-witnessed
/// anchor receipt must carry at least this many witness signatures, no exemption.
/// Ark k=0 endpoints relax to 1 via [`required_witness_floor`] (receiver-as-witness);
/// nothing else ever moves below this.
/// §5.2.2c — **THE INTERLOCK: is this deadline pair one the protocol could have
/// MINTED?** (KI#137)
///
/// The two deadlines are stamped TOGETHER by the claim's redeem and their
/// distance is a per-tier CONSTANT. That constant is not a new number invented
/// here — it falls out of [`stamp_stake_lock`]'s own arithmetic:
///
/// ```text
///   hibernation_until = claimant_epoch + window_ticks x TICK_INTERVAL_SECS
///   wall_clock_lock   = issuer_time    + lock_secs
///   |claimant_epoch - issuer_time| <= STAKE_LOCK_TIME_RANGE_SECS   (the stamp's own cross-check)
///
///   => |(hib - wcl) - (window_ticks x TICK_INTERVAL_SECS - lock_secs)| <= STAKE_LOCK_TIME_RANGE_SECS
/// ```
///
/// So the TOLERANCE is DERIVED, not chosen: it is exactly the disagreement the
/// stamp already tolerates between the two accounts of the claim moment. Verified
/// against the design doc's published distances — genesis 5,392,000s, tier 2
/// 1,928,000s, tier 3 964,000s — which these registers reproduce exactly.
///
/// **What it buys, given CL5 already refuses a locked redeem (KI#133).** That
/// gate answers "may this wallet redeem NOW?"; this answers "is this PAIR one the
/// protocol could have produced?". A forged deadline — in EITHER direction —
/// fails here from inputs Core already holds, reading no clock.
///
/// **The wallet's tier is not in its state**, so any of the three tier distances
/// is accepted. That is not a weakening: an attacker must still land on a real
/// tier's constant, and the three are far apart in production.
///
/// FAILS OPEN ONLY FOR `wall_clock_lock == 0` — no stake lock at all, i.e. a
/// HAL/RECALL hibernation or a released wallet. Those legitimately carry no pair,
/// and gating them here would strand every wallet mid-recovery.
///
/// ⚠ `hibernation_until` is ALWAYS the later of the two by design (the distance
/// is positive for every tier), so `hib < wcl` is not a small drift — it is a
/// shape the stamp cannot produce. Refused.
pub fn stake_lock_pair_is_mintable(hibernation_until: u64, wall_clock_lock: u64) -> bool {
    if wall_clock_lock == 0 {
        // No stake lock. HAL/RECALL hibernation and released wallets live here.
        return true;
    }
    // A stake lock without its hibernation partner is the half-present pair the
    // CL1 guard already refuses; say so here too rather than divide by nothing.
    if hibernation_until <= wall_clock_lock {
        return false;
    }
    let distance = hibernation_until - wall_clock_lock;
    // ⚠ ITS OWN REGISTER (the owner, 2026-09-06). This was
    // `STAKE_LOCK_TIME_RANGE_SECS` — mathematically the right source, since the
    // stamp bounds the claimant/issuer disagreement by it, but WRONG as
    // engineering: it coupled a forgery check to an unrelated clock register, so
    // tightening that one would silently start convicting wallets minted under
    // the old value. Fixed, generous, and floor-bound (>= the claim-time range,
    // else honest wallets are convicted — asserted by a test).
    let tol = crate::validation::protocol_gen::STAKE_LOCK_INTERLOCK_TOLERANCE_SECS;
    let tiers = [
        (crate::validation::protocol_gen::GENESIS_STAKE_LOCK_TICKS,
         crate::validation::protocol_gen::LOCKUP_SECONDS),
        (crate::validation::protocol_gen::TIER2_STAKE_LOCK_TICKS,
         crate::validation::protocol_gen::TIER2_LOCKUP_SECONDS),
        (crate::validation::protocol_gen::TIER3_STAKE_LOCK_TICKS,
         crate::validation::protocol_gen::TIER3_LOCKUP_SECONDS),
    ];
    tiers.iter().any(|(window_ticks, lock_secs)| {
        // Same projection the stamp uses. A tick COUNT times the interval is a
        // SPAN in seconds; it is never compared to a tick VALUE.
        let expected = window_ticks.saturating_mul(TICK_INTERVAL_SECS)
            .saturating_sub(*lock_secs);
        expected != 0 && distance.abs_diff(expected) <= tol
    })
}

pub const NORMAL_WITNESS_FLOOR: u8 = 3;

/// The witnessing context an anchor was produced under. Kept minimal — the ONLY
/// distinction that matters to the quorum floor is whether the anchor came from an
/// offline Ark ⟠→⟠ trade (receiver-as-witness, YPX-010 §11) or from the ordinary
/// online-witnessed pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessOp {
    /// An offline Ark ⟠→⟠ trade witnessed by the receiver's OWN Core (floor 1).
    ArkTrade,
    /// Any online-witnessed operation — send / redeem / heal / recall / settlement.
    Online,
}

/// The minimum number of witness signatures an anchor receipt must carry to be a
/// valid anchor for the next move — the Quorum Gate floor (CLAUDE §16 / YP §17.1.2).
///
/// ONE shared source for every caller (`validate_witnesses` today; any future anchor
/// check) so a floor bug is fixed in exactly one place — the `hibernation_until_for`
/// precedent. A k=0 Ark (`K_ARK`) endpoint doing an offline ⟠-trade is witnessed by
/// the RECEIVER's own Core, so its anchor carries exactly ONE signature; EVERY other
/// tier is online-witnessed and must still meet the absolute 3-witness quorum. The
/// k≥3 path provably resolves to 3: `1` is returned ONLY for the exact
/// `tier == K_ARK && op == WitnessOp::ArkTrade` pair, so any tier ≥ 3 — and any k=0
/// op that is not a ⟠-trade — falls through to `NORMAL_WITNESS_FLOOR`.
pub fn required_witness_floor(tier: u8, op: WitnessOp) -> u8 {
    if tier == crate::wallet_id::K_ARK && op == WitnessOp::ArkTrade {
        1
    } else {
        // YP §17.3.1.4 v2.19.0 (KI#150): the floor is max(tier, 3) — a k=4/5
        // anchor needs its own k witnesses. Until 2026-09-12 this DISCARDED
        // `tier` and returned 3 for every online tier.
        tier.max(NORMAL_WITNESS_FLOOR)
    }
}

impl Transaction {
    /// YPX-020: the hibernation deadline a HAL re-anchor stamps on its produced
    /// state. `HIBERNATION_WINDOW` is a TICK count; we project it onto the
    /// `epoch` unix-second stamp via `TICK_INTERVAL_SECS` (the <=5s/tick bound),
    /// so the lock holds for at least `HIBERNATION_WINDOW` ticks. `0` for any
    /// non-re-anchor tx. SINGLE SOURCE for both the state-hash binding
    /// (`compute_new_state_hash`) and `PublicOutputs.hibernation_until` — keeping
    /// these two in lock-step is load-bearing for the §15 anchor check.
    pub fn produced_hibernation_until(&self) -> u64 {
        // YPX-022 RECALL hibernates like HAL — the maturity window for the recall's
        // consume-once to converge across the mesh before the SDK's fail-closed re-verify.
        // SAME function + SAME projection for both — only the window value differs by kind
        // (HAL vs recall). No non-re-anchor tx hibernates.
        hibernation_until_for(
            self.epoch,
            self.is_hal_reanchor(),
            self.is_recall(),
            // Core's authoritative dev-class determination — the SAME check that gates
            // FACT class isolation and stamps the k-signed Receipt.is_dev_class.
            crate::wallet_id::is_dev_wallet(&self.sender_wallet_id),
            self.is_validator_foundation_stake_claim(),
            self.is_validator_community_stake_claim(),
        )
    }
}

impl Transaction {
    /// True if this TX is a CLARA wallet-recovery self-send. Pre-9B.1
    /// callers read `tx.is_heal()` (a bool field); this is the type-safe
    /// replacement that keeps call sites short.
    #[inline]
    pub fn is_heal(&self) -> bool {
        matches!(self.kind, TxKind::Heal)
    }

    /// True if this TX is a new-wallet airdrop claim. Pre-9B.1 callers
    /// read `tx.is_genesis_claim()` (a bool field); this is the type-safe
    /// replacement.
    #[inline]
    pub fn is_genesis_claim(&self) -> bool {
        matches!(self.kind, TxKind::GenesisClaim)
    }

    /// True if this TX is a validator-withdrawal mint (Step 9B+).
    #[inline]
    pub fn is_validator_withdrawal_mint(&self) -> bool {
        matches!(self.kind, TxKind::ValidatorWithdrawalMint)
    }

    /// Contribution emission claim (YP §25.2.4 v2.21.0) — a pool claim with the
    /// `ValidatorWithdrawalMint` shape. Every site that special-cases the fee
    /// claim special-cases this identically; `is_pool_claim()` names the pair.
    pub fn is_emission_claim(&self) -> bool {
        matches!(self.kind, TxKind::EmissionClaim)
    }

    /// The two attestation-pinned pool claims (fee sweep, emission share).
    pub fn is_pool_claim(&self) -> bool {
        self.is_validator_withdrawal_mint() || self.is_emission_claim()
    }

    /// True if this TX is a YPX-020 HAL dead-overlap re-anchor. Relaxes the
    /// S-ABR overlap (modes.rs CL2) ONLY — the double-spend gate moves to the
    /// Nabla wait + consumed-state bloom (must deploy together).
    #[inline]
    pub fn is_hal_reanchor(&self) -> bool {
        matches!(self.kind, TxKind::HalReanchor)
    }

    /// YPX-022 — RECALL discriminator. Not yet consulted on the consensus path
    /// (the `< k` + window gate and the wire flag land in later build-plan steps).
    #[inline]
    pub fn is_recall(&self) -> bool {
        matches!(self.kind, TxKind::Recall)
    }

    // ╔═ BOOTSTRAP SUBSIDY — REMOVE WHEN POOLS DRAIN ═══════════════╗
    // Design: AXIOM_DESIGN_ValidatorJoin.md §5.2.5
    // ╚═════════════════════════════════════════════════════════════╝

    /// §5.2.3 — tier-2 Foundation stake claim.
    #[inline]
    pub fn is_validator_foundation_stake_claim(&self) -> bool {
        matches!(self.kind, TxKind::ValidatorFoundationStakeClaim)
    }

    /// §5.2.3 — tier-3 Community stake claim.
    #[inline]
    pub fn is_validator_community_stake_claim(&self) -> bool {
        matches!(self.kind, TxKind::ValidatorCommunityStakeClaim)
    }

    /// Either subsidy claim kind. ONE predicate for the shared rules (the
    /// self-send exemption, the balance skip, the credit direction) so the two
    /// kinds cannot drift apart on anything that is common to both — the
    /// per-kind differences are the POOL and the AMOUNT, and those are
    /// dispatched explicitly via `validator_stake_claim_amount`.
    #[inline]
    /// §5.2.2d — true if this TX asks the witnesses for a certificate.
    #[inline]
    pub fn is_vbc_request(&self) -> bool {
        matches!(self.kind, TxKind::VbcRequest)
    }

    pub fn is_validator_stake_claim(&self) -> bool {
        self.is_validator_foundation_stake_claim() || self.is_validator_community_stake_claim()
    }

    /// The atoms a claim of this kind credits, or `None` if not a claim.
    /// SINGLE SOURCE for the kind→amount pin: Core's shape check, the Nabla
    /// grant routing and the SDK builder all read this, so a claim can never be
    /// validated against one floor and funded at another.
    #[inline]
    pub fn validator_stake_claim_amount(&self) -> Option<u64> {
        match self.kind {
            // PAYOUT, not the floor — see TIER*_CLAIM_ATOMS for why they differ.
            TxKind::ValidatorFoundationStakeClaim => Some(crate::types::TIER2_CLAIM_ATOMS),
            TxKind::ValidatorCommunityStakeClaim => Some(crate::types::TIER3_CLAIM_ATOMS),
            _ => None,
        }
    }

}

impl Transaction {
    /// Canonical CBOR encoding used on the SDK ↔ validator wire.
    ///
    /// Two things make this NOT serde's default `Serialize` for `Transaction`:
    ///
    /// 1. **Byte arrays as `[u8, u8, …]` not as CBOR byte strings.** The wire
    ///    format predates the canonical `Transaction` struct; switching to
    ///    serde's default byte-string emission would break every downstream
    ///    consumer (validators, Lambda, Python harness, webclient). The
    ///    decoders all accept both — but the encoder direction has to keep
    ///    emitting arrays-of-int.
    ///
    /// 2. **Field order matches the historical hand-built encoder.** CBOR maps
    ///    are keyed, so decode is order-independent and the order is kept only
    ///    for diff-legibility against the old hand-built encoder.
    ///
    ///    ⚠ **CORRECTED 2026-09-07 (RULE 0 §4).** This clause used to read
    ///    "the bytes are what `client_sig` is computed over. Changing field
    ///    order would invalidate the signing-message hash." **That was wrong**,
    ///    and it was load-bearing: it is the reason seven `is_*` discriminator
    ///    bools survived here for months and grew four hand-maintained decoders
    ///    around them, one of which put ANTIE — a carrier — in the business of
    ///    interpreting a transaction payload. `client_sig` is computed over
    ///    `validation::compute_signing_message`, which hashes EXPLICIT FIELDS;
    ///    so do `crypto::compute_txid`, `crypto::compute_receipt_commitment`
    ///    and `validation::compute_commitment_hash`. **Nothing in the protocol
    ///    hashes these bytes.** CLAUDE.md §13 says the same
    ///    ("txid/commitment hash EXPLICIT FIELDS, never the canonical CBOR").
    ///    This is a pure wire envelope: changing it invalidates in-flight
    ///    messages and nothing at rest.
    ///
    /// **Drift-prevention pattern** (mirrors the receipt-builder
    /// consolidation, see `axiom_core_logic::receipt::build_send_receipt`):
    /// this is the *only* function in the workspace that produces canonical
    /// `Transaction` CBOR. The SDK's `build_tx_cbor` and `build_tx_cbor_heal`
    /// are thin wrappers that construct a `Transaction { … }` and call this.
    /// Adding a field to `Transaction` therefore forces a decision here
    /// (emit it or leave it out, both explicit); see `INTENTIONALLY_UNEMITTED`
    /// for the current skip list.
    ///
    /// **Fields intentionally not on the wire today:** `oracle_claim` only. It
    /// defaults to `None` and is accepted by Core's decoder when missing
    /// (`#[serde(default)]`).
    ///
    /// `kind` IS emitted, as its serde representation — see the note on
    /// [`TxKind`]. It used to be decomposed into seven `is_*` bools that four
    /// separate decoders stripped and re-assembled; that is gone.
    pub fn to_canonical_cbor_value(&self) -> ciborium::Value {
        use ciborium::Value;

        fn bytes_as_int_array(bytes: &[u8]) -> Value {
            Value::Array(bytes.iter().map(|&b| Value::Integer(b.into())).collect())
        }
        fn opt_text(opt: &Option<String>) -> Value {
            match opt {
                Some(s) if !s.is_empty() => Value::Text(s.clone()),
                _ => Value::Null,
            }
        }
        fn opt_u32(opt: Option<u32>) -> Value {
            match opt {
                Some(n) => Value::Integer(n.into()),
                None => Value::Null,
            }
        }
        fn opt_bytes_as_int_array(opt: &Option<[u8; 32]>) -> Value {
            match opt {
                Some(b) => bytes_as_int_array(b),
                None => Value::Null,
            }
        }

        Value::Map(vec![
            (Value::Text("consumed_state_id".into()),
             bytes_as_int_array(&self.consumed_state_id)),
            (Value::Text("client_pk".into()),
             bytes_as_int_array(&self.client_pk)),
            (Value::Text("wallet_seq".into()),
             Value::Integer(self.wallet_seq.into())),
            (Value::Text("sender_wallet_id".into()),
             Value::Text(self.sender_wallet_id.clone())),
            (Value::Text("receiver_wallet_id".into()),
             Value::Text(self.receiver_wallet_id.clone())),
            (Value::Text("receiver_address".into()),
             opt_text(&self.receiver_address)),
            (Value::Text("amount".into()),
             Value::Integer(self.amount.into())),
            (Value::Text("reference".into()),
             Value::Text(self.reference.clone())),
            (Value::Text("nonce".into()),
             Value::Integer(self.nonce.into())),
            (Value::Text("epoch".into()),
             Value::Integer(self.epoch.into())),
            (Value::Text("client_sig".into()),
             bytes_as_int_array(&self.client_sig)),
            // `owner_proof` left the wire 2026-09-25 (KI#108) — see the field
            // comment on `Transaction`.
            (Value::Text("scar_passcode".into()),
             opt_u32(self.scar_passcode)),
            (Value::Text("burn_target_tx_id".into()),
             opt_bytes_as_int_array(&self.burn_target_tx_id)),
            (Value::Text("recall_target_tx_id".into()),
             opt_bytes_as_int_array(&self.recall_target_tx_id)),
            (Value::Text("required_k".into()),
             Value::Integer(self.required_k.into())),
            (Value::Text("proof_type".into()),
             Value::Integer(self.proof_type.into())),
            (Value::Text("core_version".into()),
             Value::Text(self.core_version.clone())),
            (Value::Text("core_id".into()),
             bytes_as_int_array(&self.core_id)),
            // THE discriminant, carried whole. Serialized through serde so the
            // bytes are BY CONSTRUCTION what the typed `Transaction` decoder
            // accepts — there is no second name table to drift from it, which
            // is what a hand-written `match` here would reintroduce (RULE 1).
            //
            // ⚠ This replaced SEVEN parallel `is_*` bools on 2026-09-07. Their
            // failure mode is worth remembering: `Transaction` is
            // `deny_unknown_fields`, so every consumer had to STRIP each bool
            // before the typed decode, and a bool left unstripped rejected EVERY
            // transaction — not just the new kind. The mirror-image miss (strip
            // but forget to reconstruct) was quieter and worse: `kind` degraded
            // to `Normal`, so a claim was DEBITED instead of credited and
            // HAL/RECALL lost their overlap relaxation with no error at all.
            // Do not reintroduce a per-kind bool for "just one more" kind.
            (Value::Text("kind".into()),
             Value::serialized(&self.kind)
                 .expect("TxKind is a unit-variant enum; serialization cannot fail")),
        ])
    }

    /// CBOR-encoded bytes via the canonical encoder. Used by the SDK's
    /// `build_tx_cbor` callers that need a `Vec<u8>` rather than a
    /// `ciborium::Value`.
    pub fn to_canonical_cbor_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&self.to_canonical_cbor_value(), &mut buf)
            .expect("Transaction canonical CBOR encode (in-memory writer cannot fail)");
        buf
    }

    /// Fields on the struct that the canonical encoder intentionally
    /// does NOT emit on the wire. Used by the test below to assert
    /// that every newly-added field is either emitted or explicitly
    /// listed here — closing the §13 drift class mechanically.
    #[cfg(test)]
    const INTENTIONALLY_UNEMITTED: &'static [&'static str] = &[
        // The only unemitted field. `kind` WAS listed here while it was
        // decomposed into per-discriminant bools; it is emitted directly now,
        // so the list is one entry long and should stay that way — an entry
        // here is a field the wire cannot carry, which is how the discriminator
        // sprawl started.
        "oracle_claim",
    ];
}

/// A single validator's slot in `Receipt.fee_breakdown`.
///
/// Receiver-pays-only fee model (post v2.11.6): each entry attributes a fee
/// amount to one of the receiver's witnessing validators. The aggregate sum is
/// the total fee the receiver pays out of `amount`. Empty `fee_breakdown` means
/// no fee (heal, genesis claim, or operator-zero-rate paths).
///
/// Bound into `receipt_commitment` via `compute_receipt_commitment` so a
/// post-hoc edit of any slot invalidates the k witnessing Ed25519 signatures.
/// Each Lambda verifies its own slot before signing (`fee_breakdown[i].amount
/// == fee_config.rate_bps * amount / 10_000`); the cap rules
/// (`validate_fee_breakdown`) are enforced independently by Core CL5 and Nabla
/// at `/register` so a colluding k-set cannot mint over-cap fees.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct FeeShare {
    /// Validator's stable identifier: `blake3(sphincs_pk)`. Same value
    /// `WitnessSig.validator_id` carries and the same key `Nabla.validator_earnings`
    /// indexes by.
    pub validator_id: [u8; 32],
    /// Fee amount in atoms allocated to this validator.
    pub amount: u64,
}

/// OODS health flag (YPX-021 §8.2) — the network-view health annotation a
/// witnessing round stamps onto the wallet's receipt. Carries forward with
/// the wallet's state so the NEXT validator knows whether the previous step
/// happened under a healthy view of the network.
///
/// `tick` — when it was stamped; `oods_size` — the (rounded) network size
/// the attesting Nabla saw; `healthy` — `true` iff `oods_size` is in range
/// of the Nabla's NBC baseline (§7; see `validation::oods_healthy`).
///
/// Set by Core (`modes::execute_cl3` / `execute_cl5`) from a verified
/// `NablaOodsAttestation` and bound into `receipt_commitment`, so an
/// eclipsed Nabla cannot forge `healthy = true` post-hoc. `healthy = false`
/// on the previous state blocks FACT-chain compression on the next TX
/// (the §8 wash-out gate) — NOT a scar, an orthogonal health annotation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct OodsFlag {
    /// TARDIS tick at stamp time.
    pub tick: u64,
    /// Rounded OODS network-size estimate the attesting Nabla held.
    pub oods_size: u32,
    /// `oods_size` within range of the Nabla's NBC baseline (§7/§9).
    pub healthy: bool,
}

/// A receipt proving a transaction was processed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// Transaction ID (BLAKE3 hash of CB_core)
    pub txid: [u8; 32],
    
    /// State hash after transaction (SHA3-256)
    pub state_hash: [u8; 32],
    
    /// Produced state ID
    pub produced_state_id: [u8; 32],
    
    /// New wallet sequence number
    pub new_wallet_seq: u64,
    
    /// Commitment hash that validators signed
    /// BLAKE3("AXIOM_WITNESS_V2" || consumed_state_id || client_pk || ...)
    /// Core verifies: each witness_sig.signature is valid over this hash
    /// Note: serde(default) for backward compat — production receipts MUST have this
    #[serde(default)]
    pub commitment_hash: [u8; 32],
    
    /// Settlement Domain ID — identifies which worldline this receipt belongs to.
    /// BLAKE3("AXIOM_SDID" || genesis_hash). Prevents cross-worldline receipt replay.
    /// See Yellow Paper §23.9.2, §23.11.2.
    #[serde(default)]
    pub sdid: [u8; 32],
    
    /// Lineage hash — BLAKE3 chain of core upgrades from genesis.
    /// Must be an ancestor of the verifier's current lineage.
    /// See Yellow Paper §23.11.2.
    #[serde(default)]
    pub lineage_hash: [u8; 32],
    
    /// Core version that produced this receipt (e.g., "2.5.0").
    /// Must be from the verifier's known upgrade path.
    /// See Yellow Paper §23.11.2.
    #[serde(default)]
    pub core_version: String,

    /// BLAKE3 of the Core ELF that produced this receipt. Companion to
    /// `Transaction.core_id`: when a future TX references this receipt
    /// in `prev_receipts`, Lambda's chain walk can fast-reject if the
    /// receipt's core_id doesn't match the current local core_id —
    /// without re-running DMAP verify on the embedded execution proofs
    /// (which would fail anyway with WrongCore).
    ///
    /// Covered by `receipt_commitment`, so the witnessing validators
    /// are cryptographically attesting "we verified under THIS core_id."
    /// Empty (all-zero) accepted for backward compat with receipts
    /// built before this field existed.
    #[serde(default)]
    pub core_id: [u8; 32],

    /// Witness signatures (k=3 minimum)
    pub witness_sigs: Vec<WitnessSig>,
    
    /// Epoch when processed
    pub epoch: u64,
    
    /// FACT proof: zkVM execution receipt proving Core accepted this transaction.
    /// None in dev mode (no zkVM). MANDATORY in production mode.
    /// Per Yellow Paper Section 26.17: "No proof, no money."
    pub fact_proof: Option<FactProof>,

    /// k required by the original TX's receiver tier (3/4/5).
    /// Used by validate_witnesses to compute sabr_overlap for heal floor:
    /// a heal's prev_receipts may have as few as sabr_overlap(required_k)
    /// sigs (the partial-commit shape). Normal sends still require >=3.
    /// Defaults to 3 for receipts built before this field existed.
    pub required_k: u8,

    /// Receipt commitment — see `crypto::compute_receipt_commitment` for the
    /// exact pre-image. `produced_state_id` and `fee_breakdown` are NOT bound
    /// (they depend on aggregate fee math only known after all k WitnessSigs;
    /// crypto.rs explains why). Corrected 2026-09-13: this comment claimed
    /// "binds ALL receipt fields including fee_breakdown" — false, and a
    /// false comment is how a ghost check stays alive (RULE 3). The per-slot
    /// fee cross-check `verify_receipt_fee_breakdown` was DELETED (KI#156
    /// item 2, 2026-09-21 — it had 0 callers); what runs on fees is CL5's
    /// cheque-derived total + `ConservationViolation` and Nabla /register's
    /// caps, plus each WitnessSig's own `verify_slot_math` at sign time.
    #[serde(default)]
    pub receipt_commitment: [u8; 32],

    /// Receiver-pays-only fee allocation. Each entry attributes a fee amount
    /// to one of the receiver's witnessing validators (post v2.11.6 cashier's
    /// cheque model). Empty on heal / genesis-claim / zero-rate paths.
    ///
    /// NOT bound into `receipt_commitment` (see above). Cap-enforced by
    /// `validate_fee_breakdown` at Nabla `/register` (with a slot-count ==
    /// signature-count check); CL5 judges fees from the signed cheques.
    pub fee_breakdown: Vec<FeeShare>,

    /// Dev-class flag (`AXIOM_DESIGN_FactClassIsolation.md`).
    ///
    /// `true` when this TX's `sender_wallet_id` matches the
    /// `@axiom.internal` domain (per `is_dev_wallet`). Receiver class
    /// is identical by Rule R1 (`check_domain_isolation`), so the
    /// flag captures the class of BOTH ends of the TX.
    ///
    /// Core attests this at every CL that validates the TX (CL1
    /// client self-check, CL2 validator pre-sign, CL3 Lambda
    /// re-validation, CL5 redeem). Bound into `receipt_commitment`
    /// so the k=3 witness sigs cryptographically cover it — a
    /// forged or post-hoc-edited flag invalidates the sigs.
    ///
    /// Routing consequence (Nabla `/register`): when `true`, fees +
    /// DEED are credited to the dev-side pools (`DevDeedPool`,
    /// `ValidatorDevNetLedger`) instead of the public pools. The
    /// validator-withdrawal mint path reads the source-pool flag to
    /// gate the mint type, so dev fees can ONLY mint dev-AXC.
    /// Multi-layer defense: Core enforces the flag is recomputable
    /// from `sender_wallet_id`; Nabla routes by it; the mint path
    /// gates by it. Any one layer alone closes the leak; the three
    /// together make a leak structurally impossible.
    #[serde(default)]
    pub is_dev_class: bool,

    /// OODS health flag (YPX-021 §8.2). `Some` when the witnessing round
    /// carried a verified `NablaOodsAttestation`; `None` on paths with no
    /// Nabla reading (heal, genesis claim — Phase 1; Phase 2 makes the
    /// attestation mandatory on send/redeem). Bound into
    /// `receipt_commitment` (presence AND values), so it cannot be added,
    /// removed, or edited after the k witnesses sign.
    ///
    /// NO `serde(default)` — deliberate hard format break per CLAUDE.md
    /// §13; pre-flag receipts do not load.
    pub oods_flag: Option<OodsFlag>,

    /// YPX-010 §11.6 / P3.6 — the Core-computed Confidence Index factors, stamped by
    /// Core into the sender's k=3 receipt during ordinary online activity (`Some` on a
    /// k=3 send, `None` on redeem / heal / genesis / k=0 paths). Bound into
    /// `receipt_commitment` (presence AND factor values) so the k witnesses cryptographically
    /// attest the factors — the offline receiver reads this Core-signed evidence,
    /// verifies the receipt's k-witness signatures, then recomputes the factors from the
    /// sender's FACT chain (`ark::compute_ci_factors`) to confirm they match and scores
    /// locally with `evaluate_ci`. Replaces the retired Lambda-issued CI credential. NO
    /// `serde(default)` — same hard format break as `oods_flag`.
    pub confidence_index: Option<ConfidenceIndex>,

    /// YP §32.3 — the sender's `state_id` this redeem's funds derive from
    /// (`received_from:state_id`, the FACT `sender_anchor`). `Some` on a
    /// redeem, `None` on send / heal / genesis / recall. Core CL5 stamps it
    /// and folds it into `receipt_commitment` so the k witnesses attest the
    /// lineage; Nabla reads it (via `K3Receipt.sender_state`) to set
    /// `NablaEntry.received_from`, the edge §32.4 merge-quarantine taint
    /// propagation walks. NO `serde(default)` — same hard format break as
    /// `oods_flag` (CLAUDE.md §13).
    pub sender_state: Option<[u8; 32]>,
}



/// FACT proof — cryptographic evidence that Core verified this state transition.
/// Contains the zkVM receipt (STARK proof) that Core.bin executed and accepted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactProof {
    /// RISC Zero receipt bytes (STARK proof)
    pub zkvm_receipt: Vec<u8>,
    
    /// Program digest of Core.bin that produced this proof
    pub core_digest: [u8; 32],
    
    /// Hash of the public inputs fed to Core
    pub public_inputs_hash: [u8; 32],
    
    /// Hash of the public outputs Core produced
    pub public_outputs_hash: [u8; 32],
}

// ============================================================================
// FACT CHAIN — Money Provenance (YPX-001)
// ============================================================================
//
// Every wallet carries a FACT chain proving its money traces back to genesis.
// Same trust model as VBC: genesis validators are the root of trust.
//
// Compression proposes at FACT_PROPOSE_TRIGGER (4) links and retains FACT_KEEP (3)
// after a checkpoint FINALIZES; MAX_FACT_DEPTH (16) is the depth bound. The old
// "triggers at 8 / 5 retained" wording predated SEC-07 and both numbers were wrong.
// Scarred links (no Nabla confirmation) block compression until healed or burned.

/// Default required_k for deserialization of old FACT links without the field.

/// A single FACT link — proves one state transition happened, witnessed by k validators.
/// Like VBC links prove validator legitimacy, FACT links prove money legitimacy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactLink {
    /// Transaction ID (BLAKE3 of commitment)
    pub tx_id: [u8; 32],
    
    /// Sender's state before this transaction
    pub previous_state_id: [u8; 32],
    
    /// Sender's state after this transaction (= produced_state_id)
    pub new_state_id: [u8; 32],
    
    /// Amount transferred in this link
    pub amount: u64,
    
    /// TARDIS tick when TX occurred (0 if TARDIS not yet active)
    #[serde(default)]
    pub tick: u64,
    
    /// Required k for this TX — how many witnesses were needed for full commit.
    /// Extracted from receiver_wallet_id at TX time. Used for scar detection:
    /// witnesses.len() < required_k = partial commit = real scar.
    /// NOT for S-ABR overlap (that uses PREVIOUS TX's k).
    ///
    /// **Bound into `compute_fact_commitment` since 2026-09-28** (Fork Settlement
    /// R4, wave 2b-ii): three Core decisions read it — the Ark inheritance filter
    /// (`required_k == 0` ⇒ not inherited), the k=0 receiver-witness path
    /// selector (`== K_ARK`) and the quorum threshold — so an edit after signing
    /// (5 → 3, or → 0 to launder inherited taint) invalidates every witness
    /// `fact_signature`. Before that date it was an UNSIGNED field.
    pub required_k: u8,

    /// Compact witness references (validator_id + signature)
    /// Full VBC verification happens at witness time; FACT carries the proof
    /// that k=3 real validators (VBC-verified) signed this transition.
    pub witnesses: Vec<FactWitness>,
    
    /// Nabla confirmation (None = SCAR — blocks checkpoint compression)
    /// Can be healed later if Nabla confirmation obtained.
    /// Can be burned if owner chooses to destroy the tainted amount.
    pub nabla_confirmation: Option<NablaConfirmation>,

    /// Burn proof (YPX-001 §1.5.4) — proves a scarred link was resolved by burning.
    /// When present, this link is considered resolved (like nabla_confirmation)
    /// and becomes eligible for checkpoint compression.
    ///
    /// The proof is ONLY meaningful together with `burn_target_tx_id` on the
    /// burn TX's own link — see that field. `BurnProof.validator_sigs` is a
    /// clone of the burn link's own witnesses and binds nothing by itself.
    pub burn_proof: Option<BurnProof>,

    /// YPX-001 §1.5.4 — set ONLY on a BURN TX's own link: the tx_id of the
    /// scarred link this burn destroyed (mirrors `Transaction.burn_target_tx_id`,
    /// which Core already validates via `validate_burn_target`).
    ///
    /// **Bound into `compute_fact_commitment`**, so the k=3 witnesses attest the
    /// linkage and the sender cannot re-point a burn at a different scar without
    /// invalidating every Dilithium `fact_signature`. `verify_fact_link` then
    /// requires a burned link's `burn_proof.burn_tx_id` to name a link in the
    /// same chain that (a) targets it and (b) destroyed its exact amount.
    ///
    /// Closes the burn-proof COPY forge (2026-07-17): `BurnProof.validator_sigs`
    /// is only a clone of the burn link's own witnesses (`build_fact_link`), and
    /// `compute_burn_commitment` — the binding the BurnProof doc-comment claimed —
    /// was never called in production. So a proof lifted off a genuinely-burned
    /// 1-atom link and pasted onto a 1000-atom scar passed every check and read
    /// `is_resolved() == true`. Proven by
    /// `fact::tests::burn_proof_copied_from_another_link_rejected`.
    pub burn_target_tx_id: Option<[u8; 32]>,

    /// YPX-022 RECALL (2026-07-06 forward redesign) — resolves a scarred link whose
    /// sub-quorum send was RECALLED. When present + valid (Nabla-signed attestation
    /// whose `txid == this link's tx_id`), the link counts as resolved, exactly like
    /// `burn_proof`/`nabla_confirmation`: the send never moved value (it was reclaimed),
    /// so its scar no longer blocks compression. Lambda attaches it to the failed link
    /// when finalizing the recall self-send. NOT in `compute_fact_commitment` (a
    /// post-round resolution, like the other two), so the link's witness sigs stay valid.
    #[serde(default)]
    pub recall_proof: Option<RecallAttestation>,

    /// KI#59 (RULED b, 2026-09-21) — resolves this link's OWN scar OUT OF ORDER.
    /// When present + valid (a Nabla-signed `OutOfOrderConfirmation` whose
    /// `txid == this link's tx_id` AND `new_state_id == this link's new_state_id`),
    /// the link counts as resolved — exactly like `nabla_confirmation`/`recall_proof`
    /// — so a lagging/dead link earlier in an Ark batch no longer blocks it clearing
    /// its scar (head-of-line blocking). The wallet fetches it from Nabla by
    /// submitting the k-witnessed link itself; the SDK splices it in. NOT in
    /// `compute_fact_commitment` (a post-round resolution, like the other two), so the
    /// link's witness sigs stay valid. Anti-rollback stays with the sequential SMT head
    /// advance — this only decouples the scar marker from head-ordering.
    #[serde(default)]
    pub out_of_order_confirmation: Option<OutOfOrderConfirmation>,

    /// YPX-001 §1.5.1a SCAR INHERITANCE (CORE RULE, 2026-07-12). Tx_ids of
    /// the SENDER-chain links that were unresolved when this CROSS-WALLET
    /// redeem link was built — transitively including the sender's own
    /// unresolved inherited txids, so taint survives any number of hops.
    /// Sorted ascending (BTreeSet order): every one of the k signers
    /// derives the identical set from the same client-carried chain.
    /// BOUND into `compute_fact_commitment` — stripping the taint
    /// invalidates every witness Dilithium signature. Empty on send /
    /// heal / burn / self-redeem links and clean-provenance redeems.
    /// Consent (scar_passcode) is NOT cleansing: the receiver agreed to
    /// inherit, and the next hop's receiver consents in turn until the
    /// ORIGIN txid resolves.
    pub inherited_scar_txids: Vec<[u8; 32]>,

    /// Client-carried resolutions for the inherited set: `NablaTxidAttestation`s
    /// for the source txids above. Post-round attachments — NOT in the
    /// commitment (witness sigs stay valid; recall_proof precedent) — but
    /// verified HARD by `verify_fact_link` (txid ∈ inherited set, Ed25519 over
    /// the ONE payload incl. `origin` + `sender_registered_at_tick`, mandatory
    /// NBC anchor): an invalid attestation rejects the chain.
    ///
    /// A VALID attachment does not by itself CLEAR anything (YPX-001 §1.5.1a/b,
    /// KI#221, 2026-09-28): a source txid clears ONLY when an attached
    /// attestation shows its origin SETTLED — `fact::origin_settled_link`
    /// (a registered Send-kind origin whose preimage recomputes to that txid,
    /// held ≥ the settle floor by the attesting node). `REDEEMED` (consumed ≠
    /// backed) and `BURNED` (would launder downstream) never clear. ~~ANY
    /// validly-signed attestation resolves~~ / ~~REDEEMED or BURNED resolves
    /// (KI#180)~~ — both superseded 2026-09-28. The link counts as SCARRED
    /// (gate fires, compression blocked) until every source txid has cleared.
    #[serde(default)]
    pub inherited_scar_resolutions: Vec<NablaTxidAttestation>,

    /// Sender's chain-tip state_id at send time, populated on REDEEM links.
    /// Lets the receiver's chain anchor to the sender's verified provenance
    /// without needing a separate "bridge" link. Replaces the pre-A2
    /// double-link-per-redeem pattern.
    ///
    /// Required on every redeem link; CL5 verifies it equals
    /// `cheque.sender_fact_chain.tip().new_state_id`. None on send / heal /
    /// burn links. Bound into the FACT commitment (see AXIOM_FACT_v2).
    pub sender_anchor: Option<[u8; 32]>,

    /// Sticky class lock — `true` iff this wallet's first AXC came from
    /// `DevTreasuryPool` (i.e. `@axiom.internal`). Set ONCE at genesis
    /// and inherited unchanged on every subsequent link.
    ///
    /// Bound into `compute_fact_commitment` so k validators' Dilithium
    /// `fact_signature`s cryptographically attest to the value — a
    /// tampered flag invalidates every witness signature.
    /// `verify_fact_link` enforces TWO invariants:
    ///   (1) Sticky chain:  link[i].is_dev_class == link[i-1].is_dev_class
    ///   (2) Chain-vs-TX:   link.is_dev_class == is_dev_wallet(tx.sender_wallet_id)
    ///
    /// Used by Nabla `/register` for credit routing (replaces the
    /// SDK-tamperable `K3Receipt.is_dev_class` read) and by Lambda's
    /// `validator_earned` ledger for the dev-vs-public sum (replaces
    /// the per-TX `redeem_proof.outputs.is_dev_class` read).
    ///
    /// See `AXIOM_DESIGN_FactChainClassLock.md`.
    #[serde(default)]
    pub is_dev_class: bool,

    /// YPX-010 §11 — the receiver-as-witness attestation, present ONLY on a k=0
    /// Ark ⟠→⟠ trade link (`None` on EVERY online-witnessed link — send / redeem /
    /// heal / recall / settlement). It is the k=0 link's sole witness: the receiver's
    /// own Ed25519 wallet key signing this link's `compute_fact_commitment`. Attached
    /// OUTSIDE the commitment (it signs it), so it survives Phase-4 settlement
    /// re-registration in place. No `serde(default)` — every producer sets it (to
    /// `None` for online links); the CoreID-rotating format break invalidates any
    /// pre-Ark client chain regardless.
    pub receiver_witness: Option<ReceiverWitness>,
}

impl FactLink {
    /// Number of inherited source txids still lacking a CLEARING attestation.
    /// Signature validity is enforced by `verify_fact_link` (an invalid
    /// attachment rejects the chain); whether an attachment CLEARS is judged
    /// here by the ONE Core predicate `fact::origin_settled_link` — the
    /// LINK-LEVEL form of YPX-001 §1.5.1b [ForkSettlement R20]: a settled
    /// REGISTERED Send origin whose preimage recomputes to the inherited txid,
    /// under this link's own k-signed `is_dev_class` floor. REDEEMED / BURNED
    /// never clear (KI#221, superseding KI#180's rule).
    pub fn inherited_unresolved(&self) -> usize {
        self.inherited_unresolved_txids().count()
    }

    /// WHICH inherited txids are still unresolved — the ONE filter behind
    /// `inherited_unresolved()` (its count), the transitive loop in
    /// `fact::compute_inherited_scar_txids`, and the SDK's inherited-scar sweep
    /// (`axiom_sdk_core::inherited_sweep::wanted_origins`, ForkSettlement wave 5).
    /// An inherited txid is resolved only by a stored resolution for which
    /// `fact::origin_settled_link` holds under this link's own k-signed class
    /// (YPX-001 §1.5.1b). RULE 1: no consumer re-states this filter.
    pub fn inherited_unresolved_txids(&self) -> impl Iterator<Item = &[u8; 32]> + '_ {
        self.inherited_scar_txids.iter()
            .filter(move |t| !self.inherited_scar_resolutions.iter().any(|r| {
                crate::fact::origin_settled_link(r, t, self.is_dev_class)
            }))
    }

}

impl FactLink {
    /// Whether this link is resolved (not a scar).
    ///
    /// Three resolution paths, and they treat inherited taint differently
    /// (YPX-001 §1.5.1a + §1.5.4 + YPX-022):
    ///
    /// - **Burn** (`burn_proof` present) resolves the link UNCONDITIONALLY,
    ///   including any inherited taint. Burning destroys the link's exact
    ///   amount (the §1.5.4 binding, verified in `verify_fact_chain` before any
    ///   link is trusted here), so the tainted value no longer exists to
    ///   launder. This is the holder's escape hatch when the ORIGIN of an
    ///   inherited scar (typically a banned double-spender) will never resolve
    ///   it: the holder burns the tainted money, takes the loss, and un-sticks
    ///   their wallet. It is NOT a laundering path — clearing inherited taint
    ///   costs the full tainted amount, so an accomplice who burns to "get
    ///   healthy" ends up with zero, not clean money.
    ///
    /// - **Nabla confirmation** resolves only the link's OWN transition, so it
    ///   still requires every inherited scar to carry a clearing attestation
    ///   (the ORIGIN's registration SETTLED — `fact::origin_settled_link`,
    ///   YPX-001 §1.5.1b; an upstream burn never clears it). A confirmed-but-tainted
    ///   link stays scarred — the §1.5.1a wash-out defence in depth: consent is
    ///   not cleansing, only destruction-of-value or origin-resolution is.
    ///
    /// - **Recall** (`recall_proof` present, YPX-022) resolves like a Nabla
    ///   confirmation — the sub-quorum send here was reclaimed, no value moved —
    ///   and is likewise gated on inherited taint. This is the STRUCTURAL form;
    ///   the attestation's Nabla Ed25519 + NBC-root signature is verified by
    ///   `fact::link_is_resolved` inside `verify_fact_chain_inner`, which ALWAYS
    ///   runs before any consumer of this method (compression, scar-cap, Ark CI),
    ///   so a forged proof is already rejected upstream. Kept in lockstep with
    ///   `link_is_resolved` by `fact::tests::is_resolved_matches_link_is_resolved`.
    ///
    /// Scars are never healed by time.
    pub fn is_resolved(&self) -> bool {
        if self.burn_proof.is_some() {
            return true;
        }
        (self.nabla_confirmation.is_some()
            || self.recall_proof.is_some()
            || self.out_of_order_confirmation.is_some())
            && self.inherited_unresolved() == 0
    }
}

/// Proof that a scarred FACT link was resolved by burning the tainted amount.
/// The burn TX sends the exact scarred amount to BURN_ADDRESS.
/// k=3 validators sign the burn commitment to attest the burn is legitimate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnProof {
    /// TX ID of the burn transaction (sent to BURN_ADDRESS)
    pub burn_tx_id: [u8; 32],

    /// k=3 validator signatures over the burn commitment
    /// Signs: BLAKE3("AXIOM_BURN" || scarred_tx_id || wallet_pk || amount)
    pub validator_sigs: Vec<FactWitness>,
}


/// Compact witness proof within a FACT link.
/// We don't carry full VBC bundles in every link (too large).
/// Instead: validator_id (derived from VBC) + signature over the transition.
/// The VBC was verified at witness time — this is the receipt of that verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactWitness {
    /// Validator ID = BLAKE3(sphincs_pk) — ties to VBC
    pub validator_id: [u8; 32],
    
    /// Validator's Dilithium (ML-DSA-65) public key (1,952 bytes)
    /// FACT uses Dilithium (not SPHINCS+) because FACT is operational:
    /// signed every transaction, needs speed (~1ms vs ~100ms).
    /// Still quantum-resistant. VBC keeps SPHINCS+ for ceremonial signing.
    pub validator_pk: Vec<u8>,
    
    /// Dilithium signature over BLAKE3("AXIOM_FACT" || tx_id || previous_state_id || new_state_id || amount)
    /// 3,309 bytes (ML-DSA-65)
    pub signature: Vec<u8>,

    /// YP §26.17.6.5 B2 (2026-09-11, KI#145) — the REFERENCE to the certificate
    /// that certifies this witness: `vbc::vbc_reference_hash(&bundle.target_vbc)`.
    /// Core resolves it against `PublicInputs.fact_certificates` and binds the
    /// witness only when that verified certificate's SPHINCS+ key hashes to
    /// `validator_id` and its Dilithium key IS `validator_pk`. A zero reference
    /// (every pre-amendment chain) resolves to nothing: `FactWitnessUncertified`.
    /// Replaces `vbc_genesis_anchor`, a bare public-key list that bound nothing.
    #[serde(default)]
    pub vbc_hash: [u8; 32],
}

/// YPX-010 §11 — the RECEIVER-as-witness attestation on a k=0 Ark ⟠→⟠ trade link.
///
/// A k=0 (`K_ARK`) offline trade has NO validators. Its single "witness" is the
/// RECEIVER's own wallet key, run by the receiver's own Core at trade time: the
/// receiver signs the link's fact commitment with its Ed25519 wallet key, and that
/// signature IS the quorum-floor-1 witness `validate_witnesses` accepts (P3.1) via the
/// receiver-eligibility branch (P3.2).
///
/// Deliberately NOT `FactWitness`: that type is Dilithium/ML-DSA-65-shaped
/// (`validator_pk`/`signature` are variable-length `Vec<u8>` ~1952/3309 B), which
/// would leave §13 length ambiguity between a real validator witness and a 32/64-byte
/// wallet-key one. This is a FIXED-width, Ed25519-only struct — a wallet key
/// (`receiver_pk`, 32 B) and its detached signature (64 B), nothing else. It is
/// attached OUTSIDE `compute_fact_commitment` (it signs the commitment; it cannot be
/// part of it), so it rides the link unchanged through Phase-4 settlement in place.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiverWitness {
    /// The receiver's Ed25519 wallet public key — pk-matched to `receiver_wallet_id`
    /// at verify time (exclusivity, §11.7): the ONLY key eligible to witness a k=0
    /// trade is the trade's own receiver.
    pub receiver_pk: [u8; 32],
    /// Ed25519 signature by `receiver_pk` over this link's fact commitment
    /// (`compute_fact_commitment`), the same bytes the k=3 Dilithium witnesses would
    /// sign on an online link. Serialized as a compact CBOR byte string.
    #[serde(with = "sig64_serde")]
    pub signature: [u8; 64],
}

/// Serde for a fixed 64-byte Ed25519 signature (serde has no auto impl for `[u8; N]`
/// beyond N=32). Encodes as a single CBOR byte string — compact and unambiguous —
/// with a seq fallback for any format that emits an array. no_std-clean, zero deps.
mod sig64_serde {
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use core::fmt;

    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    struct Sig64Visitor;
    impl<'de> Visitor<'de> for Sig64Visitor {
        type Value = [u8; 64];
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("64 raw signature bytes")
        }
        fn visit_bytes<E: Error>(self, b: &[u8]) -> Result<[u8; 64], E> {
            <[u8; 64]>::try_from(b).map_err(|_| E::invalid_length(b.len(), &self))
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<[u8; 64], A::Error> {
            let mut arr = [0u8; 64];
            for (i, slot) in arr.iter_mut().enumerate() {
                *slot = seq
                    .next_element()?
                    .ok_or_else(|| Error::invalid_length(i, &self))?;
            }
            Ok(arr)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        d.deserialize_bytes(Sig64Visitor)
    }
}

/// Nabla confirmation stub — full definition in YPX-002.
/// Proves this transaction was registered and verified by the Nabla network.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NablaConfirmation {
    /// Nabla node that confirmed this transaction.
    ///
    /// This is the Nabla node's Ed25519 public key — the same key
    /// used to verify `nabla_signature`. Despite the field name "id"
    /// (kept for wire-format stability), it is a public key.
    #[serde(with = "conf_bytes32")]
    pub nabla_node_id: [u8; 32],

    /// Nabla node's signature over the confirmation
    #[serde(with = "conf_bytes")]
    pub nabla_signature: Vec<u8>,

    /// Merkle root at time of confirmation
    #[serde(with = "conf_bytes32")]
    pub root_hash: [u8; 32],

    /// TARDIS tick at confirmation time
    pub synced_to_tick: u64,

    /// Nabla TARDIS tick at the moment the writer's SMT committed
    /// `new_state_id` for this wallet.  Signed by the writer as part
    /// of `nabla_signature` (the signing payload is V2 — see
    /// `nabla/src/crypto.rs::fact_confirm_payload` / Core's matching
    /// recompute in `fact.rs::verify_fact_link`).
    ///
    /// **Used by CL5 redeem:** the redeem of any cheque whose sender
    /// FACT-chain tip carries a `NablaConfirmation` MUST satisfy
    /// `current_tick > committed_at_tick` (≥ 1 tick gap).  This
    /// closes the same-tick "commit-and-immediately-redeem" race
    /// where a receiver could redeem before the sender's commit
    /// had propagated through Nabla's mesh.  See YP §17.10.5.3.
    ///
    /// Scarred links (no Nabla confirmation at all) carry no such
    /// field — the check doesn't apply and Ark-mode operation
    /// continues unchanged.
    #[serde(default)]
    pub committed_at_tick: u64,

    // ── NBC trust-anchor (KI#8 strengthening, 2026-05-15) ──
    //
    // Three fields that bind `nabla_node_id` to a `NABLA_ROOT_AUTHORITY_PKS`
    // issuer via a SPHINCS+ NBC signature. Mirrors the pattern used by
    // `NablaTxidAttestation`, `ChequeClaimProof`, and `ClaraAttestation`
    // (see `validation.rs::verify_nbc_for_*`). Without these, Core's
    // `verify_fact_link` can only check the math on the Ed25519 sig but
    // NOT that the signer is an authorized Nabla node — a compromised
    // SDK could synthesize confs from arbitrary keypairs and pass.
    //
    // **Pre-mainnet:** `#[serde(default)]` keeps legacy wallet.cbor files
    // loading (empty bytes default). `verify_fact_link` treats all-empty
    // NBC fields as "out-of-band trust" (the conf came from a real
    // Nabla TCP session via register_with_nabla; SDK never synthesizes)
    // and proceeds. **Mainnet:** flip the hard-reject on NBC absence —
    // tracked in `AXIOM_REPORT_KnownIssues.md` KI#8.
    /// SPHINCS+ public key of the root authority that issued the NBC.
    /// MUST be in `NABLA_ROOT_AUTHORITY_PKS` when NBC verification fires.
    #[serde(default, with = "conf_bytes", skip_serializing_if = "Vec::is_empty")]
    pub nbc_issuer_pk: Vec<u8>,

    /// SPHINCS+ signature by `nbc_issuer_pk` over `BLAKE3(nbc_commitment)`.
    #[serde(default, with = "conf_bytes", skip_serializing_if = "Vec::is_empty")]
    pub nbc_signature: Vec<u8>,

    /// Canonical pre-image bytes signed by the NBC issuer. The Nabla
    /// node's Ed25519 pubkey (`nabla_node_id` in this struct) MUST
    /// appear as a 32-byte window inside this blob — that binding
    /// catches Ed25519 substitution attacks where the attacker reuses
    /// a legit NBC commitment but swaps the signing key (Phase 5f
    /// fix pattern; see `validation.rs::verify_nbc_for_txid_attestation`).
    #[serde(default, with = "conf_bytes", skip_serializing_if = "Vec::is_empty")]
    pub nbc_commitment: Vec<u8>,
}

// Byte-serde shims for `NablaConfirmation` so ciborium emits canonical CBOR
// byte-strings (major type 2) for the node id / signature / root hash / NBC
// blobs instead of an Array<Integer> (major type 4). Without these, serde's
// default `[u8; 32]` / `Vec<u8>` handling produces a u8 array — bloating the
// FACT chain and forcing every consumer (SDK / Nabla) to hand-coerce.
//
// `NablaConfirmation` is EXCLUDED from every cryptographic hash — it is not in
// `compute_fact_commitment`, nor in the Ed25519 confirm payload — so changing
// only its on-wire byte representation is crypto-transparent (no CoreID-bearing
// commitment moves).
//
// Both shims keep the decode forgiving (accept Bytes OR Array-of-int) so a
// chain serialized by an older binary — or a Nabla response that still emits an
// integer array — round-trips cleanly. Mirrors the bundled `serde_bytes` shim
// in `envelope.rs`.
mod conf_bytes {
    use alloc::vec::Vec;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str("a byte string or array of bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, b: &[u8]) -> Result<Self::Value, E> {
                Ok(b.to_vec())
            }
            fn visit_byte_buf<E: serde::de::Error>(self, b: Vec<u8>) -> Result<Self::Value, E> {
                Ok(b)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(b) = seq.next_element::<u8>()? { out.push(b); }
                Ok(out)
            }
        }
        d.deserialize_byte_buf(V)
    }
}

mod conf_bytes32 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    fn fill32<E: serde::de::Error>(b: &[u8]) -> Result<[u8; 32], E> {
        if b.len() != 32 {
            return Err(E::invalid_length(b.len(), &"exactly 32 bytes"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(b);
        Ok(out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = [u8; 32];
            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str("a 32-byte string or array of 32 bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, b: &[u8]) -> Result<Self::Value, E> {
                fill32(b)
            }
            fn visit_byte_buf<E: serde::de::Error>(self, b: alloc::vec::Vec<u8>) -> Result<Self::Value, E> {
                fill32(&b)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; 32];
                let mut n = 0usize;
                while let Some(b) = seq.next_element::<u8>()? {
                    if n < 32 { out[n] = b; }
                    n += 1;
                }
                if n != 32 {
                    return Err(serde::de::Error::invalid_length(n, &"exactly 32 bytes"));
                }
                Ok(out)
            }
        }
        d.deserialize_byte_buf(V)
    }
}

/// FACT checkpoint — compressed history signed by k=3 validators.
/// Replaces N verified links with a single hash commitment.
/// Scarred links CANNOT be included in a checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactCheckpoint {
    /// Hash of all compressed links: BLAKE3(link_1 || link_2 || ... || link_n)
    pub root_hash: [u8; 32],
    
    /// Number of links compressed into this checkpoint
    pub compressed_count: u64,
    
    /// State ID at the end of the compressed section
    /// (= new_state_id of the last compressed link)
    pub final_state_id: [u8; 32],
    
    /// Genesis state ID (= previous_state_id of the first link ever)
    /// Proves the chain starts at genesis
    pub genesis_state_id: [u8; 32],
    
    /// Total amount that flowed through the compressed links
    /// (for audit: sum of all link amounts)
    pub total_amount: u64,
    
    /// Genesis fact hash (YPX-011): BLAKE3 of FACT #0.
    /// Propagated through every compression — never dropped.
    /// Proves this money traces back to the genesis headlines.
    #[serde(default)]
    pub genesis_fact_hash: [u8; 32],

    /// k=3 validator signatures over the checkpoint commitment
    /// BLAKE3("AXIOM_FACT_CHECKPOINT" || root_hash || compressed_count || final_state_id || genesis_state_id)
    pub validator_sigs: Vec<FactWitness>,

    /// SEC-07 travel-model: number of leading links in `chain.links` that this
    /// checkpoint covers and is still RETAINING (provisional state). While
    /// `pending_links > 0`, the covered links are physically present and the
    /// checkpoint is a proposal accumulating distinct validator co-signatures;
    /// the chain verifies through the real links, not the summary. When the
    /// proposal reaches `CHECKPOINT_SIG_THRESHOLD` distinct sigs, those links are
    /// deleted and `pending_links` becomes 0 (finalized) — only then is the k=5
    /// sig gate enforced. Deliberately NOT folded into `compute_checkpoint_commitment`:
    /// the committed bytes (root_hash, sigs) MUST stay identical across the
    /// provisional→finalized transition. Not forgeable — the committed `root_hash`
    /// pins the covered links, so a lying `pending_links` fails the
    /// `compute_checkpoint_root(links[0..pending_links]) == root_hash` check.
    pub pending_links: u64,
}

/// Complete FACT chain carried by a wallet/cheque.
/// Proves money provenance from genesis to current holder.
///
/// Structure: [checkpoint?] → [link_0] → [link_1] → ... → [link_n]
/// Max 5 uncompressed links. Checkpoint covers everything before.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FactChain {
    /// Compressed history (None for wallets with ≤5 transactions)
    pub checkpoint: Option<FactCheckpoint>,
    
    /// Recent uncompressed links (max 5)
    /// Ordered oldest→newest. Last link = most recent transaction.
    #[serde(default)]
    pub links: Vec<FactLink>,
}

impl FactChain {
    /// Create empty FACT chain (for genesis wallets)
    pub fn new() -> Self {
        Self { checkpoint: None, links: Vec::new() }
    }
    
    /// Current chain depth (uncompressed links only)
    pub fn depth(&self) -> usize {
        self.links.len()
    }
    
    /// ⚠ THIS IS NOT THE SCAR DEFINITION THE REST OF THE SYSTEM USES, AND UNDER
    /// THE QUORUM GATE IT CANNOT FIRE. Read before relying on it.
    ///
    /// There are TWO definitions of "scarred" in this tree (RULE 1 — one rule,
    /// two implementations):
    ///
    ///   `fact::link_is_resolved`  no nabla_confirmation / burn_proof /
    ///     (and its inverse        recall_proof, plus inherited taint.
    ///      link_is_scarred)       Used by the SDK's `count_scars`, by
    ///                             `compute_inherited_scar_txids`, and by
    ///                             compression blocking (YPX-001 §1.5).
    ///
    ///   THIS one + scar_count()   the same, AND `witnesses.len() < required_k`.
    ///
    /// That extra clause is the problem. The Quorum Gate (YP §17.1.2, §15) means
    /// a wallet's state advances ONLY on k fresh witnesses — a sub-quorum set is
    /// a no-op, not a partial — so every link that EXISTS in a committed chain
    /// has `witnesses.len() >= required_k`. The clause is therefore never true
    /// in production and this predicate is effectively a constant `false`.
    ///
    /// Lambda reached the same conclusion independently and moved off it: see
    /// `lambda/src/consensus.rs` — "the old `chain.scar_count()` needed
    /// witnesses < required_k, unreachable under the Quorum Gate" — which is why
    /// the YPX-001 §1.5.1 scar-consent trigger was reworked onto the
    /// unresolved-link definition.
    ///
    /// ⚠ KI#197 RULED + BUILT (the owner 2026-09-21, commit 062583ee): the Ark-unload
    /// gate (§11.9.3, `ArkUnloadScarred`) NO LONGER calls this — it moved to
    /// `ark_sender_chain_unclean` → `fact::link_is_scarred` (DEFINITION A), the
    /// predicate that CAN see a fully-witnessed-but-unregistered link. So this
    /// method now has NO live money-path caller (only tests + the compression
    /// properties). It is kept, not deleted, as the witnesses-aware definition;
    /// do NOT wire it back onto a security gate — use `fact::link_is_scarred`.
    ///
    /// Whether this chain has any scarred (unconfirmed and unburned) links
    /// Check for real scars. A link is scarred only if it has no
    /// nabla_confirmation AND fewer witnesses than its required_k.
    /// A link with witnesses.len() >= required_k was fully committed —
    /// the missing confirmation is from chain replacement, not a partial.
    pub fn has_scars(&self) -> bool {
        self.links.iter().any(|l| {
            l.nabla_confirmation.is_none()
                && l.burn_proof.is_none()
                && l.witnesses.len() < l.required_k as usize
        })
    }

    /// Whether compression is needed (depth > 5)
    pub fn needs_compression(&self) -> bool {
        self.links.len() > 5
    }

    /// Count real scars. witnesses.len() < required_k = partial = real scar.
    ///
    /// ⚠ SAME CAVEAT AS `has_scars` ABOVE — this is the witnesses-aware
    /// definition and returns 0 for every production chain under the Quorum
    /// Gate. It is NOT what `wallet.scar_count` reports: that is the SDK's
    /// `heal::count_scars`, which counts unresolved links with no witness
    /// clause, so the two disagree on exactly the common case — a link that was
    /// fully witnessed but whose Nabla registration failed. Measured 2026-09-17:
    /// such a wallet reads scar_count=1 from the SDK and 0 from here.
    ///
    /// Live callers today are tests and compression properties (KI#197 moved the
    /// Ark-unload gate to `fact::link_is_scarred`, commit 062583ee). If you are
    /// choosing one, the unresolved-link definition is the one the protocol acts
    /// on (inheritance, compression blocking, heal policy).
    pub fn scar_count(&self) -> usize {
        self.links.iter().filter(|l| {
            l.nabla_confirmation.is_none()
                && l.burn_proof.is_none()
                && l.recall_proof.is_none()  // YPX-022: a recalled link is resolved
                && l.witnesses.len() < l.required_k as usize
        }).count()
    }
    
    /// The latest state_id in the chain (tip of provenance)
    pub fn tip_state_id(&self) -> Option<[u8; 32]> {
        self.links.last().map(|l| l.new_state_id)
    }
    
    /// The genesis origin state_id
    pub fn genesis_state_id(&self) -> Option<[u8; 32]> {
        if let Some(ref cp) = self.checkpoint {
            Some(cp.genesis_state_id)
        } else {
            self.links.first().map(|l| l.previous_state_id)
        }
    }
}


// ============================================================================
// CHEQUE MODEL - Correct 6-validator implementation
// ============================================================================
//
// Flow:
// 1. Sender contacts k validators (V_A, V_B, V_C)
// 2. Each validator sends ONE ValidatorCheque to receiver
// 3. Receiver collects k ValidatorCheques into a ChequeBundle
// 4. Receiver brings ChequeBundle to THEIR k validators (V_X, V_Y, V_Z)
// 5. Receiver's validators verify bundle and sign new state
// 6. Receiver sends ACK + ConfirmationCheque back to sender's validators
// 7. (v3.x): validator fees settle direct-deposit at CL5 redeem; per-validator
//    earnings live on Nabla. See docs/AXIOM_DESIGN_ValidatorFeeLedger.md.
//
// Total: 6 validators involved (k=3 case)
// ============================================================================

/// A single validator's cheque
/// 
/// Each validator who witnesses the sender's transaction creates ONE of these
/// and sends it to the receiver (via ANTIE/email).
/// 
/// The receiver must collect k of these (from k different validators) before
/// they can redeem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorCheque {
    /// Transaction ID this cheque is for
    pub txid: [u8; 32],
    
    /// Validator's unique identifier (derived from VBC)
    pub validator_id: [u8; 32],
    
    /// The validator who issued this cheque
    pub validator_pk: Vec<u8>,
    
    /// Validator's signature over the cheque commitment.
    /// Signs: BLAKE3("AXIOM_CHEQUE" || txid || state_hash || produced_state_id
    ///        || receiver_wallet_id || amount || epoch || rate_bps_le
    ///        || dmap_input_hash || dmap_output_hash || optional ORACLE block).
    ///
    /// `rate_bps` is bound into the commitment so the receiver's Core CL5
    /// can read each cheque's authoritative rate at redeem time and
    /// compute `total_fee` deterministically without trusting any
    /// client-supplied proposal (closes the
    /// `E_RECEIPT_COMMITMENT_MISMATCH` class — see commit landing
    /// 2026-06-05 PM). Pre-mainnet, the cheque commitment has no
    /// version tag; there is exactly one format — CLAUDE.md §13.
    pub signature: Vec<u8>,
    
    /// Execution proof (deterministic or ZKP)
    pub execution_proof: Vec<u8>,
    
    /// Validator Birth Certificate bundle
    #[serde(default)]
    pub vbc_bundle: Option<VBCProofBundle>,
    
    /// Carrier type (how to reach this validator)
    /// e.g., "email", "swift", "https"
    pub carrier_type: String,
    
    /// Carrier address (endpoint for this validator)
    /// e.g., "validator-alpha@axiom.network", "AXIOMVAL1XXX"
    pub carrier_address: String,
    
    /// Sender's wallet_id (for reference)
    pub sender_wallet_id: String,
    
    /// Receiver's wallet_id (who can redeem this)
    pub receiver_wallet_id: String,
    
    /// Amount in atoms
    pub amount: u64,

    /// This validator's receiver-pays fee rate, in basis points.
    /// Capped at `MAX_VALIDATOR_FEE_BPS` (30) by Core CL5 via
    /// `expected_fee_slot_amount`. Bound into the cheque commitment
    /// signature — clients cannot tamper with it post-issuance.
    ///
    /// Core CL5 sums `expected_fee_slot_amount(c.amount, c.rate_bps)`
    /// across the k cheques in a bundle to derive `total_fee` →
    /// `new_balance` → `state_hash` / `produced_state_id` deterministically.
    /// The pre-2026-06-05 design routed the proposal through the
    /// client (`RedeemRequestEnvelope.fee_breakdown`), which let a
    /// stale client `validators.list` create a divergence between
    /// the receipt's NET binding and the validator's signed
    /// slot_amount — closed in this commit.
    pub rate_bps: u32,

    /// Payment reference
    pub reference: String,
    
    /// Transaction epoch
    pub epoch: u64,
    
    /// When this cheque was created
    pub created_at: u64,
    
    /// State hash from validator's witness
    pub state_hash: [u8; 32],
    
    /// Produced state ID (sender's new state)
    pub produced_state_id: [u8; 32],
    
    /// Sender's FACT chain — money provenance (YPX-001 §1.6)
    /// Each validator independently attaches the sender's FACT chain to
    /// the cheque they send to the receiver. All 3 cheques carry the same
    /// chain (redundant for survivability). Receiver can cross-verify that
    /// all 3 copies match as additional client-side security.
    /// Core verifies chain integrity at redeem time (CL5).
    pub sender_fact_chain: Option<FactChain>,

    /// ZKP nonce used during proof generation (for receiver-side replay check)
    #[serde(default)]
    pub zkp_nonce: Option<[u8; 32]>,

    /// Proof type discriminator: 0 = ZKP (STARK), 1 = DMAP (attestation)
    /// Defaults to 0 for backward compatibility with existing cheques.
    #[serde(default)]
    pub proof_type: u8,

    /// DMAP input hash — BLAKE3 of serialized PublicInputs at proof production time.
    /// Used by receiver to verify attestation binds to the correct transaction (GAP-B fix).
    /// Cheque signature covers this field — tampering invalidates the cheque.
    #[serde(default)]
    pub dmap_input_hash: [u8; 32],

    /// DMAP output hash — BLAKE3 of serialized PublicOutputs at proof production time.
    #[serde(default)]
    pub dmap_output_hash: [u8; 32],

    /// YPX-022 RECALL (2026-07-06 forward redesign): `Some(T)` when this cheque is the
    /// recall cheque re-issuing failed send `T`'s amount back to the sender. Lambda
    /// stamps it (from the verified recall) at witness time and it is BOUND into the
    /// cheque commitment (non-zero suffix), so a client cannot forge it. Core CL5 reads
    /// it to exempt the genesis-claim replay guard (a recall cheque of exactly
    /// GENESIS_CLAIM_AMOUNT is NOT an airdrop), and it is the SDK's `is_recall_cheque`
    /// discriminator. `None` for every non-recall cheque → commitment byte-identical.
    #[serde(default)]
    pub recall_target_tx_id: Option<[u8; 32]>,

    /// YPX-012: Oracle claim data (if this cheque is for an oracle TX).
    /// Presence triggers 48h maturity check at CL5 redeem.
    #[serde(default)]
    pub oracle_claim: Option<OracleClaimData>,

    /// YP §26.17.6.5 B4 (2026-09-11) — the certificates this validator verified
    /// `sender_fact_chain` against when it issued the cheque, so the receiver's
    /// validators can present them to their own Core (the money sender's
    /// witnesses are strangers to the receiver). Outside the cheque signature,
    /// exactly like `sender_fact_chain` and `vbc_bundle`.
    #[serde(default)]
    pub fact_certificates: Vec<VBCProofBundle>,

    /// Nabla hint — sender's preferred Nabla node for receiver verification (YPX-003 §2.16.5).
    /// Optional performance hint: receiver tries this node first before querying random 3.
    /// Not signed, not verified — purely informational. If node is dead, receiver falls back.
    /// Sender includes this after S-ABR round 1, before final validator witnesses.
    #[serde(default)]
    pub nabla_hint: Option<NablaHint>,

    /// YPX-002 §4.6 — sender's raw Ed25519 wallet public key.
    ///
    /// This is the 32-byte value the sender registered with Nabla (Nabla's SMT
    /// is keyed on it), and it is the `wallet_pk` query parameter the receiver
    /// hands to `/query` when running the §4.6 verification routine. The
    /// existing `sender_wallet_id` field is the email-format identifier used
    /// by Lambda for storage and Ark rule enforcement; it is NOT a valid Nabla
    /// lookup key, so a receiver that has only `sender_wallet_id` cannot run
    /// §4.6 at all. This field closes that gap.
    ///
    /// Pass-through only: Core never validates it and the cheque commitment
    /// signature does not cover it (the same unsigned-advisory contract as
    /// `nabla_hint`). Lambda stamps it from `transaction.client_pk` at witness
    /// issuance. `Option` so pre-§4.6 cheques still deserialize; receivers
    /// MUST fall back to best-effort behaviour when the field is absent.
    #[serde(default)]
    pub sender_wallet_pk: Option<[u8; 32]>,
}

/// Fan-out diffusion message for CL10 verification (§18.8).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FanOutMessage {
    pub diffusion_id: [u8; 32],
    pub content_type: u16,
    pub content: Vec<u8>,
    pub originator_pk: [u8; 32],
    pub originator_sig: Vec<u8>,
    pub timestamp: u64,
    pub ttl_original: u8,
    pub fanout: u8,
    pub ttl_current: u8,
}

/// Signed proof of validator stake for CL8 VBC approval (§25.5.4).
/// Two components: Nabla attestation (state is current) + k=3 receipt (balance at state).
/// Core verifies both independently. No Lambda in the trust chain.
///
/// Nabla txid attestation — proves a txid has NOT been redeemed globally.
///
/// The CLIENT queries Nabla before submitting a redeem request.
/// Nabla responds with a signed attestation: "this txid is not in my index."
/// The client includes this attestation in the redeem request.
/// Lambda VERIFIES the signature (never queries Nabla directly).
///
/// Architecture: Client fetches, validator verifies. Same pattern as NablaStakeProof.
/// Lambda MUST NOT talk to Nabla directly (except TARDIS requests via Core).
///
/// Freshness: the `nabla_tick` field lets Lambda reject stale attestations.
/// A txid could be registered between the attestation and the redeem — but the
/// LOCAL try_mark_cheque_redeemed() catches same-validator replays, and the
/// attestation catches cross-validator replays with bounded staleness.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NablaTxidAttestation {
    /// The txid being attested.
    pub txid: [u8; 32],
    /// Attestation status: "NOT_REDEEMED" or "REDEEMED".
    pub status: String,
    /// If REDEEMED: which wallet registered it. Empty if NOT_REDEEMED.
    #[serde(default)]
    pub registered_by: Vec<u8>,
    /// Nabla node's Ed25519 public key (for signature verification).
    pub nabla_node_pk: [u8; 32],
    /// Nabla node's signature over the ONE builder `crypto::txid_attest_payload`:
    /// BLAKE3("AXIOM_TXID_ATTEST" || txid || status_bytes || tick_le
    ///        || origin_bytes || sender_registered_at_tick_le
    ///        || oods_size_le || oods_healthy_u8 || origin_status_u8)
    pub nabla_signature: Vec<u8>,
    /// The attesting node's wall-clock seconds (`virtual_secs`) at signing time.
    /// The settle floor (YPX-001 §1.5.1b) is measured from
    /// `sender_registered_at_tick` to THIS value — both the SAME node's clock.
    pub nabla_tick: u64,
    /// YPX-001 §1.5.1b / ForkSettlement §3.2 [R11] — the origin leg this node
    /// vouches for: its own TXID RECORD of the registration whose txid is
    /// `txid`. `None` = the node does not vouch — WHY is `origin_status`
    /// (`Held` / `Unknown`, ForkSettlement §9p). SIGNED (in the payload).
    /// No `serde(default)` (§13): every producer states it.
    pub origin: Option<OriginRecord>,
    /// The attesting node's wall-clock seconds at which it began holding
    /// `origin` uncontested while listening (`max(first_seen, boot)`, design
    /// §2.4 [R9/R13]); `0` = not registered / contested. SIGNED (in the
    /// payload). Core's `fact::origin_settled_link` requires
    /// `nabla_tick >= sender_registered_at_tick + scar_settle floor`.
    /// No `serde(default)` (§13).
    pub sender_registered_at_tick: u64,
    /// Txid service mode of the attesting node ("bloom" or "hashmap").
    #[serde(default)]
    pub txid_service: String,
    /// NBC issuer SPHINCS+ public key (32 bytes for SLH-DSA-SHA2-128s).
    /// Extracted from the Nabla node's NBC issuer_set[0].
    /// Core checks: is_nabla_root_authority(pk) → must be in NABLA_ROOT_AUTHORITY_PKS.
    #[serde(default)]
    pub nbc_issuer_pk: Vec<u8>,
    /// NBC SPHINCS+ signature over the VBC commitment (7,856 bytes for SLH-DSA-SHA2-128s).
    /// Extracted from the Nabla node's NBC signatures[0].
    /// Core verifies: verify_sphincs(issuer_pk, commitment, signature) → valid.
    #[serde(default)]
    pub nbc_signature: Vec<u8>,
    /// VBC signing payload — 32-byte BLAKE3 hash (pre-computed by Nabla).
    /// Computed by crypto::compute_vbc_signing_payload(&nbc):
    ///   BLAKE3("AXIOM_VBC_V1" || validator_id || sphincs_pk || dilithium_pk
    ///          || ed25519_pk || version || role || chain_depth || issuer_count
    ///          || issued_at || expires_at || max_tx || founding_vbc_hash)
    /// The ed25519_pk is included — this binds the commitment to the attester's key.
    /// If an attacker substitutes a different Ed25519 PK, the commitment won't match.
    #[serde(default)]
    pub nbc_commitment: Vec<u8>,
    /// ForkSettlement §9h [R53] (Core W7a, 2026-09-28) — the attesting node's
    /// OWN OODS network-size estimate (YPX-021 §8.2 `oods_size`) at signing
    /// time. SIGNED (in the payload). Carried for audit beside
    /// `oods_healthy`; Core's settle predicate reads the flag, not this.
    /// No `serde(default)` (§13).
    pub oods_size: u32,
    /// ForkSettlement §9h [R53] — the node's own OODS verdict at signing time,
    /// YPX-021 semantics (`validation::oods_healthy(oods_size, NBC baseline)`,
    /// i.e. `oods_size·3 ≥ baseline`). SIGNED (in the payload). Core's
    /// `fact::origin_settle_ready_at` (and so `origin_settled_link` /
    /// `origin_settled_cl5`) requires `true`: an eclipsed / partitioned node
    /// sees < 1/3 of its baseline and must not vouch "settled". A colluding
    /// node can lie about the flag — the accepted residual (§9h). `false` in
    /// `Default` (fail-closed). No `serde(default)` (§13).
    pub oods_healthy: bool,
    /// ForkSettlement §9p (KI#221 residual 1) — the node's SIGNED statement
    /// about the origin: `Vouched` (⇔ `origin` is `Some`), `Held` or `Unknown`
    /// (both with `origin = None`). SIGNED (in the payload, one byte after
    /// `oods_healthy`). Core refuses a mismatch with `origin`
    /// (`fact::txid_attestation_origin_consistent`) and settles ONLY under
    /// `Vouched` (`fact::origin_settle_ready_at`); the SDK reads `Held` to stop
    /// waiting (liveness only). `Unknown` in `Default` (fail-closed). No
    /// `serde(default)` (§13).
    pub origin_status: OriginVouchStatus,
}

/// Nabla-signed OODS reading (YPX-021 §8.2) — carries the attesting node's
/// CURRENT network-size estimate plus its NBC baseline to Core, which
/// verifies it and stamps the derived `OodsFlag` into the receipt.
///
/// Trust model (Phase 1): the reading is Ed25519-signed by a Nabla whose
/// NBC chains to a `NABLA_ROOT_AUTHORITY_PKS` issuer (same anchor pattern
/// as `NablaTxidAttestation`), and the claimed baseline is bound into that
/// NBC's issuer-signed pre-image (suffix check — see
/// `validation::verify_oods_attestation`). An honestly-eclipsed Nabla
/// therefore cannot report a healthy size; a MALICIOUS Nabla lying about
/// its live estimate is priced by the Phase-2 §5 recomputation (CL14,
/// blocked on Core-mediated tick signing) — Phase 1 closes the wash-out
/// for the honest-but-eclipsed case.
// PartialEq/Eq/Hash added 2026-08-09 (FOB): NablaOodsAttestation rides
// GossipMessage::FobTranche, which derives Hash+Eq for the gossip dedup set.
// Behaviour-neutral — no guest compute uses Eq/Hash on this type, so no CoreID
// impact (all fields are u32/u64/[u8;32]/Vec<u8>).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct NablaOodsAttestation {
    /// Rounded current OODS network-size estimate of the attesting node.
    pub oods_size: u32,
    /// TARDIS tick of the reading.
    pub tick: u64,
    /// The attesting node's NBC baseline (§7). 0 = genesis-exempt cert.
    pub baseline_size: u32,
    /// Tick at which the baseline was stamped by the NBC issuer.
    pub baseline_tick: u64,
    /// Nabla node's Ed25519 public key (verifies `nabla_signature`).
    pub nabla_node_pk: [u8; 32],
    /// Ed25519 signature over `compute_oods_attestation_payload(...)`:
    /// BLAKE3("AXIOM_OODS_ATTEST" || oods_size || tick || baseline_size
    ///        || baseline_tick).
    pub nabla_signature: Vec<u8>,
    /// NBC issuer SPHINCS+ public key — must be in NABLA_ROOT_AUTHORITY_PKS.
    pub nbc_issuer_pk: Vec<u8>,
    /// NBC SPHINCS+ signature over BLAKE3(nbc_commitment).
    pub nbc_signature: Vec<u8>,
    /// The NBC signing-payload PRE-IMAGE bytes
    /// (`compute_vbc_signing_payload_bytes`). Binds `nabla_node_pk` (window
    /// check) and, when `baseline_size != 0`, the baseline (suffix check).
    pub nbc_commitment: Vec<u8>,
}

/// YPX-007 §9.2 (KI#125) — the `ZkpQualify` request half (`PublicInputs.zkq_request`).
/// The "before" reading T0 is `PublicInputs.oods_attestation` (field reused).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZkpQualifyRequest {
    /// T1 — the Nabla reading fetched AFTER the proof was produced and host-verified.
    pub att_after: NablaOodsAttestation,
    /// zkVM IMAGE_ID of the proven guest (host-supplied; Core cannot know it).
    pub program_digest: [u8; 32],
    /// `ZkpCheckpointOutputs.zkp_nonce_hash` from the host-VERIFIED receipt's journal.
    pub journal_nonce_hash: [u8; 32],
}

/// YPX-007 §9.2 (KI#125) — the Core-signed qualification record, carried in VSP.
/// What it proves and what it does NOT (Core never verifies the STARK): §9.4.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZkpQualificationRecord {
    /// BLAKE3(sphincs_pk) — the VSP identity.
    pub validator_id: [u8; 32],
    /// The signer key, EMBEDDED: no verifier binds it to the validator's VBC
    /// (YPX-007 §9.4 trust label — preference-only).
    pub dilithium_pk: Vec<u8>,
    /// The Core that judged and signed.
    pub core_id: [u8; 32],
    /// The zkVM guest that was proven.
    pub program_digest: [u8; 32],
    pub att_before: NablaOodsAttestation,
    pub att_after: NablaOodsAttestation,
    /// Journal binding of `compute_zkq_challenge(.., att_before.nabla_signature)`.
    pub zkp_nonce_hash: [u8; 32],
    /// Dilithium over `compute_zkq_record_payload(self)`.
    pub signature: Vec<u8>,
}

/// YPX-022 RECALL — Nabla-writer-signed proof that a `register_recall` landed for
/// this txid (the consume-once completed). Core CL2 requires it on a RECALL self-send
/// before restoring the sender's pre-send balance. It proves ONLY "this txid was
/// recalled"; the restore TARGET (the failed send's pre-send state) is bound separately
/// by Core via the txid hash (§2.1), never by this attestation — a hostile Nabla can
/// withhold a recall but can never forge a favourable restore.
///
/// Domain tag: `BLAKE3("AXIOM_RECALL_ATTEST" || txid || recall_tick_le)`.
/// PartialEq/Eq/Hash: carried inside `GossipMessage::Recall` (YPX-025 A2), whose
/// enum derives them for the dedup `seen` set; all fields are Eq/Hash-capable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RecallAttestation {
    /// The recalled txid (the failed sub-quorum send being reclaimed).
    pub txid: [u8; 32],
    /// The pre-send state the recalled send consumed (= its `consumed_state_id`).
    /// Nabla stamps this AFTER verifying `hash(failed_send_tx) == txid` at
    /// `register_recall`, so it is authoritatively bound to the recalled txid (the
    /// sender cannot substitute a higher-balance state — it wouldn't hash to `txid`).
    /// Core CL2 restores the wallet to EXACTLY this state (§2.1), blocking over-reclaim.
    pub presend_state_hash: [u8; 32],
    /// The failed send's amount `A`, Nabla-stamped from `failed_send_tx.amount` at
    /// `register_recall` (after verifying `hash(failed_send_tx) == txid`). Bound into
    /// the attestation signature, so the recall cheque's value cannot be inflated:
    /// Core CL2 pins `tx.amount == att.amount` (2026-07-06 forward redesign, §2).
    pub amount: u64,
    /// TARDIS tick at which Nabla registered the recall (consume-once landed).
    pub recall_tick: u64,
    /// Nabla node's Ed25519 public key (verifies `nabla_signature`).
    pub nabla_node_pk: [u8; 32],
    /// Ed25519 signature over `compute_recall_attestation_payload(txid, recall_tick)`.
    pub nabla_signature: Vec<u8>,
    /// NBC issuer SPHINCS+ public key — must be in `NABLA_ROOT_AUTHORITY_PKS`.
    pub nbc_issuer_pk: Vec<u8>,
    /// NBC SPHINCS+ signature over `BLAKE3(nbc_commitment)`.
    pub nbc_signature: Vec<u8>,
    /// The NBC signing-payload PRE-IMAGE bytes; binds `nabla_node_pk` (window check).
    pub nbc_commitment: Vec<u8>,
}

/// KI#59 (RULED b, 2026-09-21) — a Nabla-writer-signed proof that a root-anchored
/// Nabla node SAW and MARKED a FACT link's `(txid, new_state_id)` OUT OF ORDER,
/// i.e. WITHOUT advancing its SMT head. It resolves the link's OWN scar per-txid
/// (a third scar-resolution path beside `nabla_confirmation` and `recall_proof`),
/// so an Ark batch stops head-of-line blocking on one lagging/dead link.
///
/// It proves ONLY "a Nabla saw+marked this txid→new_state"; it is NOT a claim that
/// Nabla's SMT reached `new_state_id` (that stays the head-gated `nabla_confirmation`).
/// Nabla stamps `new_state_id` after verifying the SUBMITTED LINK's k-witness quorum
/// (`txid`/`new_state` come straight off the k-signed link, not a lone sig), so a
/// wallet cannot substitute a different state — it would not match a real link. A
/// hostile Nabla can only WITHHOLD; Core re-verifies the link (RULE 5). Anti-rollback
/// is untouched: the SMT head advance stays sequential; only the scar marker is
/// decoupled from head-ordering.
///
/// Domain tag: `BLAKE3("AXIOM_OOO_CONFIRM" || txid || new_state_id || nabla_tick_le)`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct OutOfOrderConfirmation {
    /// The link's tx_id being confirmed out of order.
    pub txid: [u8; 32],
    /// The state the link produced (= `link.new_state_id`). The state binding —
    /// what closes the fork objection. Nabla reads it off the k-witnessed link.
    pub new_state_id: [u8; 32],
    /// TARDIS tick at which Nabla marked this txid (no head advance).
    pub nabla_tick: u64,
    /// Nabla node's Ed25519 public key (verifies `nabla_signature`).
    pub nabla_node_pk: [u8; 32],
    /// Ed25519 signature over `compute_ooo_confirmation_payload(txid, new_state_id, nabla_tick)`.
    pub nabla_signature: Vec<u8>,
    /// NBC issuer SPHINCS+ public key — must be in `NABLA_ROOT_AUTHORITY_PKS`.
    pub nbc_issuer_pk: Vec<u8>,
    /// NBC SPHINCS+ signature over `BLAKE3(nbc_commitment)`.
    pub nbc_signature: Vec<u8>,
    /// The NBC signing-payload PRE-IMAGE bytes; binds `nabla_node_pk` (window check).
    pub nbc_commitment: Vec<u8>,
}

/// §10.0 FOB fee-claim attestation — a hashmap Nabla's signed statement that
/// `BoundedFee[validator_id, is_dev]` is FULL at exactly `amount`, and that the
/// SPHINCS+-registered pool linkage names `linked_wallet_id` (the validator's
/// attached STAKE wallet) as the ONLY authorized claimant. Fetched by the SDK
/// before the fee-claim self-send (the RECALL-attestation pattern) and carried
/// client-side into the ordinary k=3 round; Core's CL2 gate verifies the
/// Ed25519 signature + NBC root-authority anchor and pins the tx against it
/// (`tx.amount == att.amount` — full sweep, wrong amount = hard reject;
/// `tx.sender_wallet_id == att.linked_wallet_id` — only the stake wallet;
/// `is_dev_wallet(sender) == att.is_dev` — the §10.2a last-mile class gate).
/// Payload: `compute_fob_claim_attestation_payload` (ONE builder, Pattern 1).
/// `FobClaimAttestation.pool` — which pool the attested amount comes from.
/// The fee sweep and the emission share share ONE attestation type and ONE
/// Core gate; the discriminator is hashed into the payload and pinned against
/// the tx kind at CL2 (`modes.rs::fob_claim_tx_pins`), so a fee attestation
/// can never be presented as an emission claim or vice versa.
pub const FOB_CLAIM_POOL_BOUNDED_FEE: u8 = 0;
/// `AXIOM_DESIGN_ValidatorEmission.md` — the contribution emission pools. Two
/// instances of the airdrop pool gear (one PoolSync counter each = one claim
/// count per group), one process: validators and Nabla nodes.
pub const FOB_CLAIM_POOL_EMISSION: u8 = 1;
pub const FOB_CLAIM_POOL_EMISSION_NABLA: u8 = 2;

/// Is this `FobClaimAttestation.pool` one of the emission pools?
pub const fn is_emission_pool(pool: u8) -> bool {
    pool == FOB_CLAIM_POOL_EMISSION || pool == FOB_CLAIM_POOL_EMISSION_NABLA
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FobClaimAttestation {
    /// Which pool (`FOB_CLAIM_POOL_BOUNDED_FEE` / `FOB_CLAIM_POOL_EMISSION`).
    /// Hashed into the payload; pinned against the tx kind at CL2.
    pub pool: u8,
    /// The validator whose Bounded-Fee pool this claim sweeps — or, for an
    /// emission claim, the claiming identity (certificate id or Nabla node id).
    pub validator_id: [u8; 32],
    /// Pool class (§10.2a): dev fund vs real fund. Must match the claimant's
    /// wallet class — Core rejects any cross.
    pub is_dev: bool,
    /// The pool's FULL balance — the claim must sweep exactly this
    /// (withdraw-full-only, §4.1).
    pub amount: u64,
    /// The registered pool linkage's wallet id STRING — the only wallet allowed
    /// to claim (exact-match pinned against `tx.sender_wallet_id`).
    pub linked_wallet_id: alloc::string::String,
    /// TARDIS tick at which Nabla issued this attestation.
    pub claim_tick: u64,
    /// Nabla node's Ed25519 public key (verifies `nabla_signature`).
    pub nabla_node_pk: [u8; 32],
    /// Ed25519 signature over `compute_fob_claim_attestation_payload(..)`.
    pub nabla_signature: Vec<u8>,
    /// NBC issuer SPHINCS+ public key — must be in `NABLA_ROOT_AUTHORITY_PKS`.
    pub nbc_issuer_pk: Vec<u8>,
    /// NBC SPHINCS+ signature over `BLAKE3(nbc_commitment)`.
    pub nbc_signature: Vec<u8>,
    /// The NBC signing-payload PRE-IMAGE bytes; binds `nabla_node_pk` (window check).
    pub nbc_commitment: Vec<u8>,
    /// YP §25.2.4 — the emission epoch this share is for (0 for the §10.0 fee
    /// sweep). Core admits the claim only if it exceeds the sender's
    /// `emission_claimed_epoch` (design §4.2a). Bound into the attestation payload.
    pub epoch: u64,
}

/// Nabla-writer-signed proof that the receiver successfully registered a
/// `register_cheque_claim` for this cheque.  Closes the concurrent-replay
/// window the older `NablaTxidAttestation` path leaves open:
/// `register_cheque_claim` is enforced single-writer on Nabla, so the
/// second concurrent attempt fails with CONFLICT and never gets a signed
/// proof.  Core CL5 requires this proof on every redeem.
///
/// See `nabla/src/bin/nabla_node.rs::register_cheque_claim_core` and
/// `docs/AXIOM_DESIGN_PublicMailCarriers.md` (Stream B follow-up).
///
/// The Nabla signature is over `compute::redeem_claim_nabla_payload(cheque_id,
/// claim_tick, claim_sig)` = `BLAKE3("AXIOM_REDEEM_CLAIM" || cheque_id ||
/// "CLAIMED" || tick_le || claim_sig)` — it COVERS the claimant's own
/// `claim_sig` (YPX-022 §2.1.2a item 5, KI#205, RULED 2026-09-25), so a redeem
/// cannot rest on a claim the receiver's key did not make. Core CL5 Step 3.5b
/// verifies BOTH signatures: `claim_sig` by `client_pk` over
/// `compute::cheque_claim_signing_payload`, then `nabla_signature` by
/// `nabla_node_pk` over the payload above.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChequeClaimProof {
    /// The cheque txid being claimed.  Must match the redeem's bundle txid.
    pub cheque_id: [u8; 32],
    /// Ed25519 pubkey of the receiving wallet — bound by the claim
    /// signature.  Must match the redeem's `receiver_pk`.
    pub client_pk: [u8; 32],
    /// YPX-022 §2.1.2a — the claimant's STATE-CLASS k (YPX-010 §14), as carried
    /// on `RegisterChequeClaimRequest::k_tier`. Bound into `claim_sig`.
    /// No `#[serde(default)]` (KI#160 / §13): an absent tier is a decode error.
    pub k_tier: u8,
    /// YPX-022 §2.1.2a — the claimant's wallet address, as carried on
    /// `RegisterChequeClaimRequest::wallet_address`. With `client_pk` and
    /// `k_tier` it identifies the receiver. Bound into `claim_sig`.
    pub wallet_address: String,
    /// YPX-022 §2.1.2a — the claimant's Ed25519 signature (by `client_pk`)
    /// over `compute::cheque_claim_signing_payload(cheque_id, client_pk, k_tier,
    /// wallet_address)`. Nabla verified it before storing the claim; Core
    /// re-verifies it at CL5 (`ChequeClaimProofUnauthenticated` on failure) and
    /// the Nabla signature below covers it, so it cannot be swapped.
    pub claim_sig: Vec<u8>,
    /// TARDIS tick at which the claim was registered (freshness signal).
    pub claim_tick: u64,
    /// Nabla writer node's Ed25519 pubkey.
    pub nabla_node_pk: [u8; 32],
    /// Ed25519 signature over `compute::redeem_claim_nabla_payload(cheque_id,
    /// claim_tick, claim_sig)` — see the struct doc; it covers `claim_sig`.
    pub nabla_signature: Vec<u8>,
    /// NBC issuer SPHINCS+ pubkey (root authority binding).
    #[serde(default)]
    pub nbc_issuer_pk: Vec<u8>,
    /// NBC SPHINCS+ signature over the VBC commitment.
    #[serde(default)]
    pub nbc_signature: Vec<u8>,
    /// VBC signing payload — pre-image bytes binding the Nabla writer's
    /// Ed25519 pubkey to the root authority's SPHINCS+ signature.
    /// Same shape as `NablaTxidAttestation::nbc_commitment` (Phase 5f
    /// wire format).
    #[serde(default)]
    pub nbc_commitment: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NablaStakeProof {
    // KI#249 (2026-10-02, CoreID rotation): the "Nabla attestation" block —
    // `nabla_node_pk`, `nabla_signature` (always EMPTY since KI#247 deleted the
    // unverified role signature it copied), `attested_state_id`, `nabla_tick`,
    // `nabla_role` — was DELETED. Core never read any of it (step 3e reads
    // `balance` + `scar_count` only; CL8 reads no stake proof since KI#168), and
    // no code ever verified it: a Nabla attestation nothing signs or checks is
    // a RULE 3 ghost on a Core input. An oracle that wants Nabla's word on the
    // stake state needs a real, Core-verified attestation first (SEC-09
    // GAP-O1..O4) — not these fields back.

    // ── Balance proof (proves balance at that state) ──
    /// Candidate's wallet Ed25519 PK
    pub wallet_pk: [u8; 32],
    /// Balance at the attested state
    pub balance: u64,
    /// k=3 validator signatures over the state transition
    pub receipt_signatures: Vec<WitnessSig>,
    /// produced_state_id from the k=3 receipt. UNREAD by Core (KI#249 — the
    /// `attested_state_id` it was once to be matched against is deleted).
    pub receipt_state_id: [u8; 32],
    /// Number of scarred (unresolved) FACT links on this wallet at attestation time.
    /// Core rejects oracle witnessing if scar_count > 0.
    /// Reference: YPX-012 §1.2, Yellow Paper §34, YPX-001 §1.5
    #[serde(default)]
    pub scar_count: u32,
    /// The k of the receipt `receipt_signatures` came from (YP §17.3.1.4
    /// v2.19.0, KI#150): CL8 judges the signature count against
    /// max(required_k, 3), never a literal 3. Appended LAST (wire order).
    pub required_k: u8,
}

/// §6b VBC REGISTRATION — Nabla's stamp that makes a certificate usable.
///
/// Issuance produces a CANDIDATE certificate; this stamp is what makes it
/// usable (`AXIOM_DESIGN_ValidatorJoin.md` §6b.2, ruled 2026-09-08). Same gear
/// as a transaction: not settled until its `NablaConfirmation` lands.
///
/// DELIBERATELY OUTSIDE the issuer signatures (§6b.3): the issuers sign before
/// it exists, so `compute_vbc_signing_payload_bytes` MUST NOT commit it. What
/// protects it instead is the same NBC anchor `NablaOodsAttestation` carries —
/// `nabla_node_pk` bound into an issuer-signed NBC pre-image, issuer ∈
/// `NABLA_ROOT_AUTHORITY_PKS`. A stamp verified against a key the candidate
/// supplied would reproduce the hole §6b exists to close.
///
/// Signed payload: `compute_vbc_register_payload` (ONE builder, Pattern 1):
/// `BLAKE3("AXIOM_VBC_REGISTER" || vbc_hash || validator_id || wallet_pk
///        || balance || tick)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NablaVbcStamp {
    /// `compute_vbc_signing_payload(vbc)` of the certificate stamped — the
    /// issuer-signed commitment, so the stamp names exactly one document and
    /// cannot be lifted onto another. Also the consume-once key at Nabla.
    pub vbc_hash: [u8; 32],
    /// The stake wallet Nabla checked — must equal `subject_pubkey_ed25519`.
    pub wallet_pk: [u8; 32],
    /// The balance Nabla verified at its registered head (>= the tier floor).
    pub balance: u64,
    /// TARDIS tick at which Nabla stamped.
    pub tick: u64,
    /// Nabla node's Ed25519 public key (verifies `nabla_signature`).
    pub nabla_node_pk: [u8; 32],
    /// Ed25519 signature over `compute_vbc_register_payload(..)`.
    pub nabla_signature: Vec<u8>,
    /// NBC issuer SPHINCS+ public key — must satisfy `nabla_proof_issuer_is_authorized`.
    pub nbc_issuer_pk: Vec<u8>,
    /// NBC SPHINCS+ signature over `BLAKE3(nbc_commitment)`.
    pub nbc_signature: Vec<u8>,
    /// The NBC signing-payload PRE-IMAGE bytes; binds `nabla_node_pk` (window check).
    pub nbc_commitment: Vec<u8>,
}

// =====================================================================
// YPX-018 — CLARA & Tiered Bloom Memory (v2.11.15)
// =====================================================================

/// Three-state result of a Nabla txid lookup (YPX-018 §4.6).
///
/// Replaces the original YPX-014 String status. Distinguishes:
/// - `NotRedeemed` — txid is fresh, redeem may proceed
/// - `Redeemed` — txid is in the txid bloom chain, double-redeem rejected
/// - `PhasedOut` — the bloom era containing this txid was retired by Console action,
///   the cheque is irrevocably dead and the lookup is paired with a `phase_out_cert`
///
/// This enum is wire-stable. Encoded as a small integer in CBOR (0/1/2).
/// Phase 1 introduces the type; Phase 4 wires it into modes.rs and the codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TxidStatus {
    NotRedeemed = 0,
    Redeemed = 1,
    PhasedOut = 2,
}

impl TxidStatus {
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::NotRedeemed),
            1 => Some(Self::Redeemed),
            2 => Some(Self::PhasedOut),
            _ => None,
        }
    }
}

/// CLARA — Client-Led Attested Reality Alignment (YPX-018 §2.2).
///
/// Carries a Nabla-signed proof that a wallet has healed past one or more
/// poisoned states. Allows previously poisoned validators to roll their
/// stored state forward and resume normal witness service.
///
/// **Security model:**
/// - The Nabla signature is verified against the embedded NBC trust anchor
///   (SPHINCS+ root authority — same pattern as `NablaTxidAttestation`).
/// - The `wallet_pk` is bound into the signed message — replay across wallets
///   is impossible.
/// - The receiving validator's stored state for the wallet MUST equal
///   `healed_to_state_id` (KI#260 — the ONLY eligibility rule); otherwise
///   `E_CLARA_STATE_NOT_GARBAGE`. No validator state is rewritten: the
///   `healed_from` / `garbage_state_ids` / `healed_balance` fields are signed
///   and carried, but no Core decision reads them.
///
/// Spec: `docs/AXIOM_YPX-018_HEAL_AND_TIERED_MEMORY.md` §2
/// Yellow Paper: §17.10.14
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaraAttestation {
    /// Healing wallet's public key (Ed25519, 32 bytes).
    /// Bound into the signed message — replay across wallets is impossible.
    pub wallet_pk: [u8; 32],

    /// State the wallet is healing FROM (the pre-broken-TX state, last
    /// known-good state shared by the wallet and Nabla).
    pub healed_from_state_id: [u8; 32],

    /// State the wallet is healing TO (the produced_state_id of the heal
    /// cheque). CL2 eligibility: the validator's stored state must equal it.
    pub healed_to_state_id: [u8; 32],

    /// Wallet sequence at heal point (signed; no Core decision reads it).
    pub healed_at_seq: u64,

    /// YPX-018 Phase 5f Finding 4: canonical post-heal balance. Since KI#260
    /// it is INERT in Core and Lambda (no roll-forward, no rewrite reads it —
    /// `ki256_cl2_anchor_attestation_balance_is_inert`); Nabla checks it.
    ///
    /// **Cryptographic binding:** the heal cheque's `state_hash` field is
    /// `BLAKE3(wallet_pk || healed_balance || healed_at_seq)` — see
    /// `crypto::compute_state_hash`. The cheque is k=3-witnessed, so each
    /// fresh validator has signed `state_hash` over the canonical post-heal
    /// (balance, seq) pair the wallet declared at heal time. Nabla recomputes
    /// the hash from `(wallet_pk, healed_balance, healed_at_seq)` and verifies
    /// it equals `cheque.state_hash`. If they match, `healed_balance` is
    /// trusted (cryptographically committed by the witnessing validators).
    /// Mismatch → reject the registration.
    #[serde(default)]
    pub healed_balance: u64,

    /// txid of the heal cheque (TX_HEAL self-cheque).
    pub heal_txid: [u8; 32],

    /// Abandoned states declared garbage by this heal (signed; since KI#260
    /// no Core decision reads the entries — only non-empty is checked).
    pub garbage_state_ids: Vec<[u8; 32]>,

    /// Bloom era at heal time (for tier resolution).
    pub bloom_era_id: u64,

    /// Bloom-chain commitment at heal time. Allows the validator to verify
    /// the attestation is anchored to a real era (not a forged era_id).
    pub bloom_era_root: [u8; 32],

    /// Nabla TARDIS tick at attestation time (freshness).
    pub nabla_tick: u64,

    /// Attesting Nabla node's Ed25519 public key.
    pub nabla_node_pk: [u8; 32],

    /// Nabla signature over `compute_clara_message(self)`.
    pub nabla_signature: Vec<u8>,

    // === NBC trust anchor (mirrors NablaTxidAttestation, no_std-compatible) ===
    /// NBC issuer SPHINCS+ public key. Must be in `NABLA_ROOT_AUTHORITY_PKS`.
    #[serde(default)]
    pub nbc_issuer_pk: Vec<u8>,
    /// NBC SPHINCS+ signature over the VBC commitment.
    #[serde(default)]
    pub nbc_signature: Vec<u8>,
    /// VBC signing payload binding `nabla_node_pk`.
    #[serde(default)]
    pub nbc_commitment: Vec<u8>,
}

/// Status of a single bloom era in the Bloom Age Index (YPX-018 §3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EraStatus {
    /// Currently accepting writes. Exactly one era is Active at any time.
    Active,
    /// Closed; bloom file is immutable. Can be queried but not modified.
    Frozen,
    /// Console-approved phase-out scheduled. Queries return real answers
    /// during the grace period, tagged with a phase-out warning.
    ScheduledPhaseOut {
        effective_tick: u64,
        console_cert_hash: [u8; 32],
    },
    /// Phase-out has taken effect. Archive nodes are FREE to drop the era's
    /// full hash records. The age-index entry remains forever for auditability.
    PhasedOut {
        effective_tick: u64,
        console_cert_hash: [u8; 32],
    },
}

/// One era in the bloom chain (YPX-018 §3.3).
///
/// Each era covers a TARDIS tick range (default 90 days = quarterly).
/// Both the txid bloom and the garbage state bloom share the same era
/// metadata, so an era is the unit of phase-out for both chains.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloomEra {
    /// Monotonic era id. Increments when an era closes and the next opens.
    pub era_id: u64,

    /// First TARDIS tick in this era's range (inclusive).
    pub start_tick: u64,

    /// First TARDIS tick of the *next* era (exclusive).
    /// `end_tick - start_tick == ERA_DURATION_TICKS` for all eras.
    pub end_tick: u64,

    /// BLAKE3 root of the txid bloom file at era close (zero if Active).
    pub txid_bloom_root: [u8; 32],

    /// BLAKE3 root of the garbage state bloom file at era close (zero if Active).
    pub garbage_bloom_root: [u8; 32],

    /// Exact entry counts at era close (for FPR computation by light nodes).
    pub txid_count: u64,
    pub garbage_count: u64,

    /// Era status — drives query semantics and Console phase-out lifecycle.
    pub status: EraStatus,

    /// Optional list of archive node IDs known to hold this era's full
    /// hash records. Used as a routing hint when bloom hits need archive
    /// resolution. Not authoritative — any node may volunteer to archive.
    #[serde(default)]
    pub archive_nodes: Vec<[u8; 32]>,
}

/// Console proposal payload for a `BLOOM_PHASE_OUT` action (YPX-018 §4.2,
/// YPX-013 §5.5).
///
/// Validated by Core CL11 against the constitutional limits in
/// `console::MIN_PHASE_OUT_AGE_TICKS` and `console::MIN_PHASE_OUT_GRACE_TICKS`.
/// The Console cannot override those limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleProposalBloomPhaseOut {
    /// Bloom eras scheduled for phase-out. Each must satisfy the
    /// constitutional minimum age check in CL11 §6.2.3.
    pub era_ids: Vec<u64>,

    /// TARDIS tick at which phase-out becomes effective.
    /// Must be at least `MIN_PHASE_OUT_GRACE_TICKS` after proposal approval.
    pub effective_tick: u64,

    /// Human-readable rationale (storage pressure, archive coverage, etc.).
    /// Not validated by Core; surfaced in Console UI.
    pub rationale: String,
}

// === Fan-Out Protocol Constants (§18.8) ===

pub const FANOUT_MAX_TTL: u8 = 10;
pub const FANOUT_MAX_FANOUT: u8 = 3;
pub const FANOUT_MAX_CONTENT_BYTES: usize = 65536;
pub const FANOUT_MAX_AGE_SECS: u64 = 86400;
pub const FANOUT_FUTURE_TOLERANCE_SECS: u64 = 60;

// Fan-out content type constants (§18.8)
pub const FANOUT_JFP_FREEZE_REQUEST: u16 = 0x0001;
pub const FANOUT_JFP_VOTE: u16 = 0x0002;
pub const FANOUT_JFP_RESULT: u16 = 0x0003;
pub const FANOUT_DWP_QUERY: u16 = 0x0010;
pub const FANOUT_DWP_RESPONSE: u16 = 0x0011;
pub const FANOUT_DWP_STAMP: u16 = 0x0012;
pub const FANOUT_CONSOLE_APPOINTMENT: u16 = 0x0100;
pub const FANOUT_CONSOLE_RESIGNATION: u16 = 0x0101;
/// YPX-013: Console election announcement — "Election open, submit nominations"
pub const FANOUT_CONSOLE_ELECTION: u16 = 0x0102;
/// YPX-013: Console election result — new ConsoleCertificate or dissolution
pub const FANOUT_CONSOLE_RESULT: u16 = 0x0103;
/// C1: Canonical Reality Attestation — 2-of-3 Genesis Root Authority declares canonical chain.
pub const FANOUT_REALITY_ATTESTATION: u16 = 0x0200;

/// C1: Reality Attestation — resolves mirror worldline forks.
/// Signed by Root Authority SPHINCS+ keys (same keys that signed genesis VBCs).
/// 2-of-3 attestations constitute consensus on which genesis chain is canonical.
/// Broadcast via CL10 Fan-Out. Validators verify against ROOT_AUTHORITY_PKS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealityAttestation {
    /// BLAKE3 hash of the canonical FACT #0 (proves which genesis is real).
    pub canonical_genesis_hash: [u8; 32],
    /// Root Authority index (0, 1, or 2) — which of the 3 root keys signed this.
    pub root_authority_index: u8,
    /// Root Authority SPHINCS+ public key (32 bytes, must match ROOT_AUTHORITY_PKS).
    pub root_authority_pk: Vec<u8>,
    /// SPHINCS+ signature over BLAKE3("AXIOM_CANONICAL" || canonical_genesis_hash || tick).
    pub signature: Vec<u8>,
    /// TARDIS tick when attestation was produced.
    pub tick: u64,
}

// H4: VBC renewal cartel is not a real problem at scale. If a validator is rejected
// by some validators, they try others from their hint table or discover new ones
// via VSP. Hundreds of validators exist. No genesis special authority needed.
pub const FANOUT_VALIDATOR_GOSSIP: u16 = 0x0201;
pub const FANOUT_VBC_ANNOUNCEMENT: u16 = 0x0202; // AUDIT-FIX: was 0x0201 (collision with VALIDATOR_GOSSIP)

// ── Validator stake (YP §25.5.1, v2.20.0) — registers in protocol_core.toml ──
// ⚠ RULED 2026-09-13: there are no stake TIERS. ~~TIER1/2/3_MIN_STAKE =
// 1,000,000 / 500,000 / 500~~ are gone: ONE floor for every validator, and the
// Genesis 1,000,000 is a ceremony opening balance, not a floor
// (docs/AXIOM_REF_BootstrapEconomics.md §3.1, KI#161).
/// The ONE validator stake floor, whole AXC. Checked at registration (the Nabla
/// stamp) and at renewal (CL8) — never on each witness (ruled 2026-09-13).
pub const VALIDATOR_STAKE_FLOOR: u64 = crate::validation::protocol_gen::VALIDATOR_STAKE_FLOOR_AXC;
/// Each genesis validator's ceremony-minted opening balance, whole AXC.
pub const GENESIS_VALIDATOR_GRANT: u64 = crate::validation::protocol_gen::GENESIS_VALIDATOR_GRANT_AXC;
/// What a Foundation stake claim must land at after its worst-case witness fee.
pub const FOUNDATION_STIMULUS_LANDED: u64 =
    crate::validation::protocol_gen::FOUNDATION_STIMULUS_LANDED_AXC;

// ── THE SAME NUMBERS IN ATOMS (2026-09-02) ────────────────────────────────
//
// ⚠ The constants above are denominated in WHOLE AXC, as their doc
// comments say. Balances, pool budgets and `Transaction.amount` are all in
// ATOMS (`axc(1) == 10^10`). Comparing one to the other is off by ten orders
// of magnitude and FAILS OPEN on a stake floor — a wallet holding 500 ATOMS
// (0.00000005 AXC) satisfied `balance < VALIDATOR_STAKE_FLOOR` and passed as a
// tier-3 validator. That is the KI#47 unit-bug class, in money.
//
// Fix direction per KI#47: NAME THE UNIT, never hand-convert at the call
// site. Every atoms-context comparison uses these; the bare AXC constants are
// for display and for the slot arithmetic in `genesis_integrity`, which is
// self-consistently in AXC.
pub const GENESIS_VALIDATOR_GRANT_ATOMS: u64 = axiom_denomination::axc(GENESIS_VALIDATOR_GRANT);
pub const VALIDATOR_STAKE_FLOOR_ATOMS: u64 = axiom_denomination::axc(VALIDATOR_STAKE_FLOOR);
pub const FOUNDATION_STIMULUS_LANDED_ATOMS: u64 = axiom_denomination::axc(FOUNDATION_STIMULUS_LANDED);

// ── WHAT A SUBSIDY CLAIM PAYS — NOT THE SAME NUMBER AS THE FLOOR ──────────
//
// RULED (the owner, 2026-09-04). A claim is an ordinary transaction, so the
// receiver pays the witness fee out of the amount: paying exactly the floor
// delivered 498.5 AXC against a 500 AXC bar, and the candidate could never
// clear the very floor it had just been funded to reach. Measured on the live
// mesh that day.
//
// The fix is the SIMPLE one — pay a little more, not exempt the fee. A fee
// exemption would have needed a new money rule in Core plus a matching rule in
// Lambda; this needs no mechanism at all, only a different number and a pool
// sized to match it.
//
// ⚠ THE FLOOR AND THE PAYOUT ARE NOW DIFFERENT QUESTIONS, and one constant
// used to answer both. Before changing either, know which you mean:
//   - `TIER*_MIN_STAKE_ATOMS` — what a validator must HOLD (§7.1 stake gate).
//   - `TIER*_CLAIM_ATOMS`     — what the pool PAYS OUT (kind→amount pin, the
//                               CL5 lock's shape test, Nabla's grant routing,
//                               and the pool drain arithmetic).
// Each claim is its target plus a 1 % fee allowance (505 = floor 500 + 5;
// 6,060 = Foundation stimulus 6,000 + 60), so it lands at or above the target
// after the worst-case k=3 fee.
//
// ⚠ The pools are sized to divide EXACTLY by these (85 x 505 = 42,925;
// 5 x 6,060 = 30,300 — registers in protocol_core.toml, checked by build.rs),
// and those balances are part of FACT #0 — changing one changes the genesis
// fact hash. `genesis_integrity` asserts it.
pub const TIER2_CLAIM_AXC: u64 = crate::validation::protocol_gen::TIER2_CLAIM_AXC;
pub const TIER3_CLAIM_AXC: u64 = crate::validation::protocol_gen::TIER3_CLAIM_AXC;
pub const TIER2_CLAIM_ATOMS: u64 = axiom_denomination::axc(TIER2_CLAIM_AXC);
pub const TIER3_CLAIM_ATOMS: u64 = axiom_denomination::axc(TIER3_CLAIM_AXC);

/// KI#152 — A CLAIM MUST OUTLIVE ITS OWN WITNESS FEE. Compile-time, because the
/// inputs live in three files and nothing else couples them.
///
/// A subsidised claim is receiver-pays like any other transfer: the witnesses
/// take their slots out of the amount in transit, and the candidate keeps what
/// lands. The aggregate fee cap is `k × MAX_VALIDATOR_FEE_BPS`
/// (`validation::validate_fee_breakdown`), so what a claim pays scales with the
/// receiver's tier k.
///
/// RULED (b) by the owner, 2026-09-13: Core PINS a subsidised claim to the
/// claimant's Standard-tier (k=3) address (`validation.rs`,
/// `E_STAKE_CLAIM_TIER_INVALID`), and the SDK refuses to build one to any other
/// address. So the worst case a claim can meet is `K_DEFAULT` slots at the
/// per-validator cap, and the 1 % allowance (505 / 505,000) clears the floor
/// with every witness paid in full: 505 × (1 − 0.009) = 500.45 ≥ 500. The
/// 2026-09-12 alternative (a) — 508 / 508,000 sized for K_MAX — was merged
/// and then reverted for (b): it moved five genesis registers and the White
/// Paper line to guard a path no shipped client can build.
///
/// ⚠ This is a REAL const assertion, not the `const _X: () = {}` shape RULE 3
/// calls a ghost — it evaluates the arithmetic and fails the build. If the tier
/// pin is ever lifted, change `K_DEFAULT` below back to `K_MAX` and re-size.
const _CLAIM_SURVIVES_WORST_CASE_WITNESS_FEE: () = {
    // bps arithmetic in u64, no floats: landed = claim * (DIV - k*rate) / DIV.
    const WORST_BPS: u64 =
        (crate::wallet_id::K_DEFAULT as u64) * (MAX_VALIDATOR_FEE_BPS as u64);
    assert!(
        WORST_BPS < FEE_BPS_DIVISOR,
        "KI#152: the worst-case aggregate fee is 100% or more of the transfer"
    );
    const KEPT: u64 = FEE_BPS_DIVISOR - WORST_BPS;
    assert!(
        TIER3_CLAIM_AXC * KEPT / FEE_BPS_DIVISOR >= VALIDATOR_STAKE_FLOOR,
        "KI#152: the Community claim lands BELOW the stake floor after K_DEFAULT witness          slots at MAX_VALIDATOR_FEE_BPS. Raise tier3_claim_axc in          protocol_core.toml to at least ceil(floor * 10000 / KEPT) — and then          pool_bootstrap_axc and the market row move with it."
    );
    // Re-pointed 2026-09-13: the Foundation claim is a stimulus, not a floor —
    // it must land at its target (foundation_stimulus_landed_axc), which is
    // also above the one floor.
    assert!(
        TIER2_CLAIM_AXC * KEPT / FEE_BPS_DIVISOR >= FOUNDATION_STIMULUS_LANDED,
        "KI#152: the Foundation claim lands BELOW foundation_stimulus_landed_axc after          K_DEFAULT witness slots at MAX_VALIDATOR_FEE_BPS. Raise tier2_claim_axc in          protocol_core.toml — pool_foundation_bootstrap_axc and the market          row move with it."
    );
    assert!(
        FOUNDATION_STIMULUS_LANDED >= VALIDATOR_STAKE_FLOOR,
        "the Foundation stimulus must at least fund the one stake floor"
    );
};

/// The two subsidy pool totals, in WHOLE AXC — `slots x claim`, straight from
/// the genesis distribution table (`protocol_core.toml`), which `build.rs`
/// refuses to compile unless it adds up to the declared supply.
///
/// Exported so NABLA reads the same number Core declares in FACT #0 instead of
/// keeping its own copy in `protocol_nabla.toml`. That copy is what let a claim
/// be minted at 505 while the pool was debited 500 (2026-09-04).
pub const POOL_BOOTSTRAP_AXC: u64 = crate::validation::protocol_gen::POOL_BOOTSTRAP_AXC;
/// The airdrop pool (§17.11) and the dev-AXC treasury, same single source.
/// Nabla read both from its OWN tuning file until 2026-09-05 — a second copy
/// of a number Core declares in FACT #0.
pub const POOL_AIRDROP_AXC: u64 = crate::validation::protocol_gen::POOL_AIRDROP_AXC;
pub const POOL_DEV_TREASURY_AXC: u64 = crate::validation::protocol_gen::POOL_DEV_TREASURY_AXC;
pub const POOL_FOUNDATION_BOOTSTRAP_AXC: u64 =
    crate::validation::protocol_gen::POOL_FOUNDATION_BOOTSTRAP_AXC;
/// Contribution emission pool opening balance (FACT #0 carve of Market,
/// `AXIOM_DESIGN_ValidatorEmission.md`) — Nabla opens its emission pools from it.
pub const POOL_VALIDATOR_EMISSION_AXC: u64 =
    crate::validation::protocol_gen::POOL_VALIDATOR_EMISSION_AXC;

// ── Subsidised validator-join slots (AXIOM_DESIGN_ValidatorJoin.md §2) ──
//
// Each pool must divide EXACTLY by its grant. A remainder is either supply
// that can never be spent or supply that can be over-granted; both are
// silent conservation failures, so the counts are pinned by test
// (`genesis_integrity::tests::join_pools_drain_to_exactly_zero`) rather
// than by comment. Frozen at G1 — changing one after the ceremony changes
// the genesis fact hash, hence the CoreID, hence it is a fork.
//
// Pool exhaustion removes a SUBSIDY, never permission: once these are
// claimed, candidates join by holding the same floor themselves.

/// Foundation seats funded from `SubPoolId::FoundationBootstrap` (register
/// `foundation_subsidised_slots`). Foundation is a title, not a tier; the first
/// 5 validators that join with their own AXC also earn the name (ruled 2026-09-13).
pub const FOUNDATION_SUBSIDISED_SLOTS: u64 =
    crate::validation::protocol_gen::FOUNDATION_SUBSIDISED_SLOTS;

/// Community slots funded from `SubPoolId::Bootstrap` (register
/// `community_subsidised_slots`).
pub const COMMUNITY_SUBSIDISED_SLOTS: u64 =
    crate::validation::protocol_gen::COMMUNITY_SUBSIDISED_SLOTS;

/// Check whether a content type is a known fan-out content type.
pub fn is_known_fanout_content_type(ct: u16) -> bool {
    matches!(ct, 0x0001..=0x0003 | 0x0010..=0x0012 | 0x0100..=0x0103 | 0x0200..=0x0202)
}

/// Sender's preferred Nabla node hint for receiver cheque verification.
/// Contains both IP:port (fast, works across partitions) and node name
/// (permanent NBC identity, fallback when IP changes — citizen nodes have dynamic IPs).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NablaHint {
    /// Node name from NBC (permanent identity, e.g. "nabla-tokyo-42")
    pub node_name: String,
    /// Current IP:port at registration time (e.g. "85.123.45.67:6225")
    pub address: String,
}

/// A bundle of k ValidatorCheques
/// 
/// Receiver collects these from sender's validators, then brings the
/// entire bundle to their own validators for redemption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChequeBundle {
    /// The k cheques (one from each of sender's validators)
    /// All must have same: txid, receiver_wallet_id, amount, epoch
    pub cheques: Vec<ValidatorCheque>,
    
    /// Sender's FACT chain — money provenance (YPX-001)
    /// 
    /// AUTHORITATIVE SOURCE: Each ValidatorCheque.sender_fact_chain carries
    /// the sender's FACT chain independently (redundant for survivability).
    /// This field is a CONVENIENCE copy extracted by the receiver when
    /// assembling the bundle. Core CL5 uses this field for verification.
    /// 
    /// Client-side security note: Receivers MAY cross-verify that all 3
    /// ValidatorCheque.sender_fact_chain copies are identical. Mismatch
    /// indicates validator corruption. (Not protocol-enforced — future
    /// client implementation.)
    pub fact_chain: Option<FactChain>,
}

impl ChequeBundle {
    /// Verify bundle consistency (all cheques match AND from distinct validators)
    pub fn verify_consistency(&self) -> bool {
        if self.cheques.is_empty() {
            return false;
        }

        let first = &self.cheques[0];

        // Check all cheques have matching fields.
        //
        // YPX-018 Phase 5f Finding 5: also check sender_wallet_id consistency.
        // The cheque commitment binds `receiver_wallet_id` but not
        // `sender_wallet_id`. Without this consistency check, an attacker
        // could splice cheques from different senders into the same bundle
        // (the per-cheque signatures still verify; only the cross-cheque
        // consistency catches it). For CLARA specifically, the authoritative
        // tx-binding (compute_txid match) closes the exploit, but adding the
        // consistency check here is defense-in-depth and harmless to all
        // existing flows (every legitimate bundle already has matching
        // sender_wallet_id across cheques). If the cheque commitment is
        // ever extended to include `sender_wallet_id`, this consistency
        // check becomes redundant; until then, keep it.
        let fields_match = self.cheques.iter().all(|c| {
            c.txid == first.txid
                && c.sender_wallet_id == first.sender_wallet_id
                && c.receiver_wallet_id == first.receiver_wallet_id
                && c.amount == first.amount
                && c.epoch == first.epoch
                // KI#146 (2026-09-11): the redeem chain is chosen by the bundle's
                // (txid, produced_state_id) — every cheque must name the same state.
                && c.produced_state_id == first.produced_state_id
        });

        if !fields_match {
            return false;
        }

        // Check all cheques are from DISTINCT validators
        // This prevents replay attacks where same validator's cheque is duplicated
        self.has_distinct_validators()
    }
    
    /// Check that all cheques are from distinct validators
    /// Uses validator_id (derived from VBC) for uniqueness
    pub fn has_distinct_validators(&self) -> bool {
        use alloc::collections::BTreeSet;
        
        let mut seen_validators: BTreeSet<[u8; 32]> = BTreeSet::new();
        
        for cheque in &self.cheques {
            // If we've seen this validator_id before, not distinct
            if !seen_validators.insert(cheque.validator_id) {
                return false;
            }
        }
        
        true
    }
    
    /// Get the common txid
    pub fn txid(&self) -> Option<[u8; 32]> {
        self.cheques.first().map(|c| c.txid)
    }
    
    /// Get the receiver wallet_id
    pub fn receiver_wallet_id(&self) -> Option<&str> {
        self.cheques.first().map(|c| c.receiver_wallet_id.as_str())
    }
    
    /// Get the amount
    pub fn amount(&self) -> Option<u64> {
        self.cheques.first().map(|c| c.amount)
    }
    
    /// Check if we have k cheques
    pub fn has_k_cheques(&self, k: usize) -> bool {
        self.cheques.len() >= k
    }
}

/// Request to redeem a cheque bundle
/// 
/// Receiver submits this to THEIR validators (not sender's validators)
/// to update their wallet state with the received funds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedeemRequest {
    /// The bundle of k cheques from sender's validators
    pub cheque_bundle: ChequeBundle,
    
    /// Receiver's public key (must match cheques' receiver_wallet_id)
    pub receiver_pk: Vec<u8>,
    
    /// Receiver's current wallet state (balance before redemption)
    pub current_state: Option<WalletState>,
    
    /// Signature proving ownership of receiver_pk
    /// Signs: BLAKE3("AXIOM_REDEEM" || txid || receiver_pk)
    pub receiver_sig: Vec<u8>,
    
    /// Request ID for correlation
    pub request_id: String,
}

/// ACK envelope (sent by sender to their validators).
///
/// v3.x (YP §20.8): no per-TX fee promise — validator fees settle at CL5
/// via fee_breakdown direct-deposit, not at sender ACK time. The ACK
/// remains as the trigger for state finalization (PENDING → CONFIRMED,
/// mark consumed_state_id, prune superseded S-ABR records). The struct
/// name retains "WithFee" only to avoid wire-type churn; the field is gone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckWithFee {
    /// Transaction ID being acknowledged
    pub txid: [u8; 32],

    /// Which validator this ACK is for
    pub validator_pk: Vec<u8>,

    /// Sender's signature authorizing finalization
    /// Signs: BLAKE3("AXIOM_ACK_v3" || txid || validator_pk)
    pub sender_sig: Vec<u8>,
}

/// Confirmation cheque (sent by receiver to sender's validators)
/// 
/// After receiver successfully redeems, they send this to sender's validators
/// to confirm receipt of payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmationCheque {
    /// Original transaction ID
    pub txid: [u8; 32],
    
    /// Which validator this confirmation is for
    pub validator_pk: Vec<u8>,
    
    /// Receiver's signature confirming receipt
    /// Signs: BLAKE3("AXIOM_CONFIRM" || txid || validator_pk || receiver_pk)
    pub receiver_sig: Vec<u8>,
    
    /// Receiver's public key
    pub receiver_pk: Vec<u8>,
}

// ============================================================================
// FEE CHEQUE MODEL
// 
// Validators collect fees through the same cheque system as normal payments.
// Each validator receives TWO cheques per witnessed transaction:
// 1. Fee cheque (issued when witnessing sender's TX) - contains the fee amount
// 2. Confirmation cheque (issued when receiver redeems) - proves TX completed
// 
// Validator must have BOTH cheques to redeem their fee.
// Fee redemption requires k=3 witnesses (who were NOT original TX witnesses).
// ============================================================================


/// Calculate DEED allocation from validator fee
/// 
/// # Rules
/// - DEED receives 10% of validator fee
/// - Minimum 1 atom (if fee > 0)
/// - Only during DEED period (first 10 years from genesis)
/// 
/// # Parameters
/// - `validator_fee`: The gross fee amount
/// - `years_since_genesis`: Years elapsed since network genesis
/// 
/// # Returns
/// DEED allocation in atoms
pub fn calculate_deed_allocation(validator_fee: u64, years_since_genesis: u64) -> u64 {
    const DEED_PERIOD_YEARS: u64 = 10;
    const DEED_PERCENTAGE: u64 = 10;  // 10%
    
    if years_since_genesis >= DEED_PERIOD_YEARS {
        return 0;  // DEED period expired
    }
    
    if validator_fee == 0 {
        return 0;
    }
    
    // AUDIT-FIX v2.11.14: Use checked/saturating math to prevent overflow
    // when validator_fee is near u64::MAX. Division by 100 always brings
    // the result back into range, so saturating_mul is safe here.
    let deed_amount = validator_fee.saturating_mul(DEED_PERCENTAGE) / 100;
    
    // Minimum 1 atom if any fee exists
    if deed_amount == 0 {
        1
    } else {
        deed_amount
    }
}

/// Calculate receiver amount after fee deduction
/// 
/// # Formula
/// receiver_amount = sender_amount - (k × fee_per_validator)
/// 
/// # Returns
/// Ok(receiver_amount) or Err if insufficient funds for fees
pub fn calculate_receiver_amount(
    sender_amount: u64,
    k: u8,
    fee_per_validator: u64,
) -> Result<u64, ValidationError> {
    let total_fees = (k as u64).checked_mul(fee_per_validator)
        .ok_or(ValidationError::InternalError)?;
    
    sender_amount.checked_sub(total_fees)
        .ok_or(ValidationError::InsufficientBalance)
}

/// Default fee per validator in atoms
pub const DEFAULT_FEE_PER_VALIDATOR: u64 = 10;

/// Current core version string for lineage binding
/// Full version string embedded in every Receipt.
///
/// RECONCILED 2026-08-01 (design decision). This was a SECOND, independent
/// version identity: `version.rs` documented `{name}/{build}/{phase}` as "the
/// full version string — embedded in every Receipt", while receipts actually
/// carried this bare `"2.12.0"`. Both constants were live, in different places,
/// disagreeing. The `{name}/{build}/{phase}` form is canonical, and the build
/// component carries the 2.12.0 value — so the one true string is
/// `Kyoto/2.12.0/GENESIS`. This is now an alias, not a duplicate: change the
/// value in `version.rs` only.
pub const CORE_VERSION: &str = crate::version::CORE_VERSION_TAG;

/// Genesis SDID — Settlement Domain ID for the primary AXIOM worldline.
/// BLAKE3("AXIOM_SDID_GENESIS_V1"). Fixed at genesis, never changes.
/// See Yellow Paper §23.9.2.
pub fn genesis_sdid() -> [u8; 32] {
    *blake3::hash(b"AXIOM_SDID_GENESIS_V1").as_bytes()
}

/// Genesis lineage hash — starting point for the lineage chain.
/// BLAKE3("AXIOM_LINEAGE_GENESIS_V1"). Evolves with each core upgrade.
/// See Yellow Paper §23.11.2.
pub fn genesis_lineage_hash() -> [u8; 32] {
    *blake3::hash(b"AXIOM_LINEAGE_GENESIS_V1").as_bytes()
}

/// A witness signature from a validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessSig {
    /// Validator's unique identifier (derived from VBC)
    pub validator_id: [u8; 32],
    
    /// Validator's public key
    pub validator_pk: Vec<u8>,
    
    /// Validator Birth Certificate bundle
    /// Full VBC chain proof — Core verifies back to genesis root keys.
    #[serde(default)]
    pub vbc_bundle: Option<VBCProofBundle>,
    
    /// Carrier type (how to reach this validator)
    /// e.g., "email", "swift", "https"
    pub carrier_type: String,
    
    /// Carrier address (endpoint for this validator)
    /// e.g., "validator-alpha@axiom.network", "AXIOMVAL1XXX"
    pub carrier_address: String,
    
    /// Signature over commitment_hash
    pub signature: Vec<u8>,
    
    /// Execution proof bytes (ZKP STARK receipt or DMAP attestation)
    pub execution_proof: Vec<u8>,

    /// Proof type discriminator: 0 = ZKP (STARK), 1 = DMAP (attestation)
    /// Default 0 (ZKP) for backward compatibility with existing wire format.
    #[serde(default)]
    pub proof_type: u8,

    /// Availability attestation (optional)
    pub availability_attestation: Option<AvailabilityAttestation>,
    
    /// Validator hints for organic discovery (MANDATORY: 1-3 hints)
    /// Per Yellow Paper Section 27.5: Validators MUST include hints in replies
    /// Core enforces: 1 <= hints.len() <= 3
    pub validator_hints: Vec<ValidatorHint>,
    
    /// FACT commitment signature (YPX-001)
    /// Signs: BLAKE3("AXIOM_FACT" || tx_id || previous_state_id || new_state_id || amount)
    /// Used to build FACT links with k=3 witnesses for money provenance.
    /// Each validator signs the FACT commitment alongside the witness commitment.
    /// Client/overlapped validator collects k=3 and assembles the FactLink.
    pub fact_signature: Option<Vec<u8>>,

    /// SEC-07 checkpoint endorsement: this validator's Dilithium signature
    /// (carried as a `FactWitness` so it ships its own validator_id + pk)
    /// over the DETERMINISTIC FACT checkpoint commitment for THIS round.
    ///
    /// Present only when this TX's `sender_fact_chain` crosses the FACT
    /// compression trigger — every witness in that round signs the identical
    /// checkpoint (the compressed set is deterministic given the same input
    /// chain), and the finalizer merges the k endorsements into the
    /// checkpoint's `validator_sigs` (see `fact::merge_checkpoint_endorsements`).
    /// This is the carrier that lets a checkpoint carry k=3 DISTINCT sigs
    /// minted in the one round that created it — no validator-to-validator
    /// talk, no over-rounds accumulation. `None` when no compression triggers.
    /// See `docs/security_review_20260612/SEC-07_RESOLUTION.md`.
    pub checkpoint_sig: Option<FactWitness>,

    /// Nabla register receipt signature.
    ///
    /// Each validator signs `wallet_id || consumed_state_id ||
    /// produced_state_id || tick_le` with their Ed25519 key. Nabla's
    /// `/register` TCP path verifies k=3 of these signatures (see
    /// nabla/src/registration.rs:120 and nabla/src/crypto.rs::receipt_sign_payload).
    /// The SDK forwards this byte string verbatim into the Nabla
    /// `K3Receipt.signatures[].signature` field — the SDK has no
    /// validator key and cannot re-sign.
    ///
    /// This is a SEPARATE signature from `signature` (which is over
    /// the Core commitment_hash for witness consensus) and
    /// `fact_signature` (Dilithium over the FACT commitment for
    /// receiver-side audit). All three pin the same TX from
    /// different oracle perspectives. Always present — serde(default)
    /// removed so any wire that omits this field decodes as an error
    /// rather than silently producing an unsigned receipt.
    pub receipt_signature: Option<Vec<u8>>,

    /// Receipt commitment signature — Ed25519 over BLAKE3("AXIOM_RECEIPT_v1"
    /// || txid || state_hash || produced_state_id || new_wallet_seq ||
    /// commitment_hash || epoch || rate_bps || slot_amount). Each validator
    /// signs this to prove k validators agreed on the SAME receipt fields.
    /// Core verifies on next TX: recompute commitment from receipt fields,
    /// check k sigs. Prevents receipt fabrication by clients or malicious-
    /// validator collusion (honest validators sign different commitment →
    /// mismatch).
    ///
    /// The rate_bps + slot_amount additions (2026-06-03) bind the
    /// validator's signature to its OWN fee claim — without them, the
    /// SDK could swap slot amounts post-witness without breaking the sig.
    #[serde(default)]
    pub receipt_commitment_sig: Option<Vec<u8>>,

    // ── v3.x fee-self-attestation (2026-06-03) ─────────────────────
    // Move the fee-slot authority OUT of the SDK and INTO each
    // validator's own Core. Every WitnessSig now carries the
    // validator's rate AND the slot it produced; both are signed
    // over by `signature` and `receipt_commitment_sig` above. Any
    // Core that processes this WitnessSig — Lambda witness-time
    // pre-sign check, client CL1 redeem-build, receiver CL5 — runs
    // `validation::verify_slot_math(amount, rate_bps, slot_amount)`
    // and rejects on mismatch. This removes the SDK from the fee
    // trust chain: it can't propose a slot, can't lie about a
    // validator's rate, and can't swap one slot for another after
    // the fact.

    /// The validator's advertised fee rate in basis points (1 bps =
    /// 0.01%) at witness time, from its own `lambda.toml [fees]
    /// rate_bps` (capped at `MAX_VALIDATOR_FEE_BPS = 30`). Signed by
    /// `signature` and `receipt_commitment_sig`. 0 is a valid value
    /// for zero-fee validators.
    #[serde(default)]
    pub rate_bps: u32,

    /// The slot atoms this validator earns from this TX, computed by
    /// its own Core as `min(rate_bps, MAX_VALIDATOR_FEE_BPS) × amount
    /// / FEE_BPS_DIVISOR` and signed before returning. Every
    /// downstream Core re-derives the value and rejects if it
    /// doesn't match. Receipt `fee_breakdown[i].amount` MUST equal
    /// `witness_sigs[i].slot_amount`.
    #[serde(default)]
    pub slot_amount: u64,
}

/// Validator hint for organic network discovery
/// Per Yellow Paper Section 27.5
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValidatorHint {
    /// Validator's stable identifier: `blake3(sphincs_pk)` — the same
    /// 32-byte ID `crypto::compute_validator_id` produces. CBOR-encoded
    /// as a 32-byte bytestring; JSON-facing surfaces (admin endpoints)
    /// hex-encode for display. Pre-2026-05-24 this was `String` and
    /// some Lambda code paths populated it with
    /// `"alpha@axiom/abcd1234"`-shape labels — those literals are now
    /// a type error.
    pub validator_id: [u8; 32],
    
    /// Human-friendly display name (e.g., "axiom-first-penguin-alpha")
    pub name: String,
    
    /// Carrier URIs — one or more ways to reach this validator
    /// e.g., ["email:alpha@axiom.local", "uncle:192.168.1.100:9001"]
    /// A validator MAY be reachable via multiple carrier types (ANTIE, UNCLE, COUSIN)
    pub carriers: Vec<String>,

    /// YPX-007: Proof capability — "dmap" (default) or "zkvm"
    #[serde(default)]
    pub proof_cap: Option<String>,

    /// When validator was last seen responding (Unix timestamp)
    pub last_seen: Option<u64>,

    /// Ed25519 transport public key for this validator. `None` when
    /// the hint pre-dates a key binding (e.g., remote response from a
    /// peer that hadn't yet correlated the validator with its
    /// `approved_validators` row, or older Lambda builds that didn't
    /// emit this field). SDK clients treat this as a **first-guess
    /// hint** — the authoritative key for any given validator is the
    /// one extracted from a Core-verified VBC in a prev_receipt
    /// (`sdk/core/src/hints.rs::cross_check_vbc_keys` REPLACES a
    /// disagreeing hint key when VBC evidence arrives).
    #[serde(default)]
    pub ed25519_pk: Option<[u8; 32]>,

    /// Operator's encryption public key (e.g., PGP/GPG armoured public
    /// key block, or base64). Travels alongside the carrier URIs so a
    /// client that just discovered this validator can encrypt to it
    /// without a separate VSP round. Empty string = no encryption
    /// advertised (clients fall back to plain transport).
    #[serde(default)]
    pub encryption_public_key: String,

    /// Encryption scheme tag matching `OperatorConfig.supported_encryption`
    /// ("PGP", "GPG", "none", …). Lets clients decide whether to attempt
    /// encryption with the bundled key.
    #[serde(default)]
    pub supported_encryption: String,
}

/// Attestation that data is available from overlap witness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailabilityAttestation {
    /// Witness that attests to availability
    pub witness_pk: Vec<u8>,
    
    /// Signature over the data hash
    pub signature: Vec<u8>,
    
    /// Hash of the available data
    pub data_hash: [u8; 32],
}

/// Current state of a wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletState {
    /// Wallet's public key
    pub public_key: Vec<u8>,
    
    /// Current balance in atoms
    pub balance: u64,
    
    /// Current wallet sequence number
    pub wallet_seq: u64,
    
    /// Current state ID
    pub state_id: [u8; 32],
    
    /// Ed25519 public key derived from the wallet private key
    /// (`SHA3-256("AXIOM_OWNER_KEY" || private_key)`), STORED by Lambda via
    /// `set_auth_hash` (KI#107) and READ BY NOTHING in Core since 2026-09-25:
    /// the `owner_proof` it verified was deleted (KI#108 — a second signature
    /// under a key derived from the same private key proves nothing
    /// `client_sig` does not). It was never stolen-key protection. Retained
    /// only because it is a Lambda storage column; removing it is a
    /// storage-schema change (reported, not done).
    pub auth_hash: Option<[u8; 32]>,

    /// Canonical wallet_id bound to this public key (identity binding).
    /// Set on the first transaction and immutable thereafter.
    /// Core enforces: tx.sender_wallet_id must match this value when Some.
    /// Prevents lockup bypass and Ark policy spoofing — identity is
    /// cryptographically bound via the first signed transaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_id: Option<String>,

    /// Group wallet members (optional — None for personal wallets)
    /// When Some: this is a group wallet with percentage-based distribution.
    /// Every member holds the group wallet's private key (shared).
    /// Withdrawals are restricted: destination must be a member's wallet_id,
    /// amount must not exceed the member's available balance.
    /// Members list is immutable after creation.
    /// Max 32 members. sum(share_bps) must equal 10000.
    pub group_members: Option<Vec<GroupMember>>,

    /// YPX-020 — HIBERNATION: tick until which this wallet is "out of work".
    /// While `tx.tick < hibernation_until`, Core CL2 rejects every tx for this
    /// wallet (CL1 is exempt — a first tx has no prior state to hibernate on).
    /// Bound into `compute_state_hash` so it is witnessed + tamper-evident. A
    /// general primitive (timelocks, vesting, dispute windows); HAL sets it to
    /// `now + W` on a re-anchor so a concurrent spend can't race the wait.
    /// `0` = not hibernating (the normal case).
    #[serde(default)]
    pub hibernation_until: u64,
    /// ╔═ VALIDATOR STAKE LOCK — AXIOM_DESIGN_ValidatorJoin.md §5.2.2c ═══╗
    /// A DUAL GATE: the wallet may send only when BOTH deadlines have passed.
    /// `0`/`0` = not staked (the normal case, and every self-funded joiner).
    /// Bound into `compute_state_hash`, so k-witnessed and tamper-evident
    /// exactly like `hibernation_until` beside it.
    ///
    /// ⚠ DISTINCT FROM `hibernation_until` ON PURPOSE — that is the HAL/RECALL
    /// recovery lock, binary and CLEARED by the completion self-redeem.
    /// Overloading it would make "staked" and "mid-heal" the same state, and
    /// the claim's own redeem would clear the stake lock as the stake landed.
    ///
    /// Two deadlines because a tick is accurate in DIRECTION, not TIME, while
    /// the wall-clock half reads the CLIENT-SUPPLIED `tx.epoch` and is
    /// escapable alone. Under AND neither weakness bites.
    /// ╚═════════════════════════════════════════════════════════════════╝
    /// The wall-clock half — RENAMED from `stake_locked_until_unix` 2026-09-05
    /// (the owner). It is deliberately NOT named for the stake: it is a PERMANENT
    /// primitive — *this wallet cannot send before T* — generalising the
    /// hardcoded genesis lockup (`GENESIS_VALIDATORS` + `lockup_seconds`), and it
    /// is NEVER RETIRED. A stake wallet may lie dormant for years past its
    /// release, so a field scoped for deletion when the pools drain would either
    /// break that wallet or force permanent compat code (RULE 13 forbids it).
    ///
    /// It also SEALS the HAL/RECALL hibernation escape hatch: see the gate in
    /// `validation.rs`. An action-released lock (hibernation) needs a hatch; a
    /// time-released lock must not have one.
    #[serde(default)]
    pub wall_clock_lock: u64,
    /// YP §25.2.4 / design §4.2a — the emission epoch this wallet last claimed
    /// its contribution share for (0 = never). Bound into the §15 state hash so
    /// once-per-epoch is a MESH fact Core enforces at every writer: an
    /// `EmissionClaim` is admitted only if `attestation.epoch` exceeds it, and
    /// the claim's post-state carries the attestation's epoch. Carried unchanged
    /// by every other transaction (KI#166).
    #[serde(default)]
    pub emission_claimed_epoch: u64,
    /// ValidatorJoin §6b.13 (KI#225, RULED 2026-10-01) — the STAKE FLOOR: tick
    /// VALUE (unix-second encoding, the unit of `VBC.expires_at`) until which a
    /// debit may not take this wallet below `VALIDATOR_STAKE_FLOOR_ATOMS`. `0` =
    /// no floor. The seventh §15 state-hash field, so it is k-witnessed exactly
    /// like the lock beside it. SET by Core on an admitted `VbcRequest` whose
    /// post-state balance is at or above the floor
    /// (`max(prev, tx.epoch + VBC_VALIDITY_TICKS)`), CARRIED unchanged by every
    /// other transaction (send and redeem alike), and lowered by NONE. Gated at
    /// every debit in `validate_transaction` (`E_STAKE_FLOOR`); read by Nabla at
    /// stamp time (§6b.4 check 5). Mandatory — no `serde(default)` (RULE 13).
    pub stake_floor_until: u64,
    /// §6b.13 — the wallet-format block (`wallet_version` + three `ext_bytes`
    /// + three `ext_u64`), the LAST fields of the §15 state hash. Core requires
    /// it to equal [`WalletFormat::CURRENT`] in every state it consumes and
    /// every state it produces (`E_WALLET_FORMAT_INVALID`). Mandatory.
    pub wallet_format: WalletFormat,
}

impl WalletState {
    /// The OPENING (first-time) shape of a declared wallet state — the ONE
    /// predicate for "this state has nothing to anchor" (Fable review
    /// 2026-10-01, F-1). True when the state is the wallet's OPENING state as
    /// Core derives it from the key alone: `wallet_seq == 0`, every
    /// history-bearing §15 term zero (`hibernation_until`, `wall_clock_lock`,
    /// `emission_claimed_epoch`, `stake_floor_until`), `balance ==
    /// genesis::genesis_opening_balance(pk)` (0 for every wallet but a genesis
    /// stake wallet), and `state_id` either the opening id
    /// `genesis::opening_state_id_for(pk, k, proof_type)` or the zero label.
    /// (`wallet_format` is not history — CL5 requires `WalletFormat::CURRENT`
    /// on every state.) `pk` is the key the state is DECLARED for (the
    /// redeeming receiver's `receiver_pk`), never `self.public_key`, which is
    /// client-supplied; `(k, proof_type)` is that wallet's tier (the cheque's
    /// receiver wallet id).
    ///
    /// ⚠ WRONG READING, corrected 2026-10-01 (RULE 0 §4). The first F-1(a)
    /// build named this `is_first_time_zero` and required `state_id == 0`,
    /// reading CLAUDE.md §15's "first-time receivers ship a zero-valued
    /// WalletState". The SDK does not: a fresh wallet's `state_id` is its
    /// OPENING id (`sdk/core/src/wallet.rs::create_with_key`, §10.5/§6c), and a
    /// genesis stake wallet opens with its grant as balance. Under the zero
    /// reading EVERY first-time receive declared "history" and was refused at
    /// every validator (none holds a row for an unseen wallet). The opening
    /// state is self-certifying — Core derives it from the key and the
    /// compiled-in genesis table — so it needs no receipt; anything else does.
    ///
    /// What the opening exemption admits is exactly CL2's first-TX exemption
    /// (`wallet_seq == 1 && prev_seq == 0`, no receipt): a wallet that HAS
    /// history may still declare its opening state, which is a REWIND to the
    /// opening state — a self-fork of the wallet (its opening state consumed
    /// twice) for Nabla's consume-once / fork machinery. No value escapes it:
    /// the balance is pinned to the opening balance, so a floored / locked
    /// wallet that rewinds leaves its floored balance behind on its real branch.
    pub fn is_opening_state(&self, pk: &[u8], k: u8, proof_type: u8) -> bool {
        if self.wallet_seq != 0
            || self.hibernation_until != 0
            || self.wall_clock_lock != 0
            || self.emission_claimed_epoch != 0
            || self.stake_floor_until != 0
            || self.balance != crate::genesis::genesis_opening_balance(pk)
        {
            return false;
        }
        if self.state_id == [0u8; 32] {
            return true;
        }
        match <[u8; 32]>::try_from(pk) {
            Ok(pk) => crate::crypto::ct_eq(
                &self.state_id,
                &crate::genesis::opening_state_id_for(&pk, k, proof_type),
            ),
            Err(_) => false,
        }
    }
}

/// §6b.13 (the owner 2026-10-01) — the wallet version every produced state carries.
pub const WALLET_VERSION: u32 = 1;

/// ValidatorJoin §6b.13 — the wallet-format fields, ONE definition read by
/// every layer (`WalletState`, the declared-state wire shapes, Lambda storage,
/// the SDK wallet). Purpose (the owner, 2026-10-01): *"for future function
/// expansion without changing the wallet version."*
///
/// Grouped in one type so the §15 builder and every declared-state carrier
/// take the block as ONE value — the field set, its order and its hash bytes
/// live here and in [`crate::crypto::compute_state_hash`] only. The order is
/// the state-hash order: `wallet_version`, `ext_bytes_1..3`, `ext_u64_1..3`.
///
/// ⚠ RESERVED, NOT FREE. Until a later ruling gives an ext field a meaning,
/// Core refuses any state whose block is not [`WalletFormat::CURRENT`]
/// (version = [`WALLET_VERSION`], every ext field zero). A reserved field any
/// value could pass through would be a ghost (RULE 3). Giving one a meaning is
/// a Core change (CoreID rotation); it does not change the wallet shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletFormat {
    pub wallet_version: u32,
    pub ext_bytes_1: [u8; 32],
    pub ext_bytes_2: [u8; 32],
    pub ext_bytes_3: [u8; 32],
    pub ext_u64_1: u64,
    pub ext_u64_2: u64,
    pub ext_u64_3: u64,
}

impl WalletFormat {
    /// The ONLY block Core admits today.
    pub const CURRENT: WalletFormat = WalletFormat {
        wallet_version: WALLET_VERSION,
        ext_bytes_1: [0u8; 32],
        ext_bytes_2: [0u8; 32],
        ext_bytes_3: [0u8; 32],
        ext_u64_1: 0,
        ext_u64_2: 0,
        ext_u64_3: 0,
    };

    /// `true` iff this block is [`WalletFormat::CURRENT`] — THE predicate
    /// Core's format gate reads (one owner, RULE 1).
    pub fn is_current(&self) -> bool {
        *self == Self::CURRENT
    }
}

/// Maximum number of members in a group wallet
pub const MAX_GROUP_MEMBERS: usize = 32;

/// Total basis points must equal this (100.00%)
pub const TOTAL_SHARE_BPS: u16 = 10000;

/// A member of a group wallet
/// 
/// Members are identified by their public key. The wallet_id is derived from
/// the public key (deterministic). Members can only withdraw to their own
/// wallet, and only up to their available balance.
/// 
/// share_bps is in basis points: 100 bps = 1%, 10000 bps = 100%.
/// available tracks atoms allocated but not yet withdrawn.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroupMember {
    /// Member's public key (identity — wallet_id derived from this)
    pub member_pk: Vec<u8>,
    
    /// Member's share in basis points (10000 = 100%)
    pub share_bps: u16,
    
    /// Atoms allocated to this member but not yet withdrawn
    pub available: u64,
}

/// Genesis wallet definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisWallet {
    /// Wallet's public key
    pub public_key: [u8; 32],
    
    /// Initial balance in atoms
    pub balance: u64,
    
    /// Genesis state ID: H("AXIOM_GENESIS" || pk || balance)
    pub genesis_state_id: [u8; 32],
    
    /// Initial wallet_seq (always 0)
    pub wallet_seq: u64,
}

/// VBC Proof Bundle for validator authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VBCProofBundle {
    /// The VBC being verified
    pub target_vbc: VBC,
    
    /// Supporting VBCs for chain verification
    pub supporting_vbcs: Vec<VBC>,

    /// §5.2.2e (2026-09-08) — the candidate's own YPX-009 Pulse proof, carried
    /// on a PROVISIONAL certificate request and verified by CL8
    /// (`pulse::verify_candidacy_pulse`). OUTSIDE the issuer pre-image, like
    /// `supporting_vbcs`: an input to the issuers' decision, not a field of
    /// the credential. Appended LAST with `serde(default)` — bincode is
    /// positional and every existing bundle decodes as `None`.
    #[serde(default)]
    pub candidacy_pulse: Option<crate::wire_client::PulseProofRequest>,

    /// Q2-b (the owner ruled 2026-09-21) — the renewal PROOF-OF-VALIDATION.
    /// `Some` on a VBC RENEWAL request: one k-signed receipt the renewing
    /// validator co-signed during its CURRENT cert's term, proving the identity
    /// did real witnessing work (CL8 `verify_renewal_work_receipt`). `None` on a
    /// FIRST issuance (no prior cert of the same subject in `supporting_vbcs`),
    /// where the gate is skipped. Like `candidacy_pulse` it is OUTSIDE the issuer
    /// pre-image — an input to the issuers' decision, not a field of the
    /// credential — and appended LAST with `serde(default)` so every existing
    /// bundle decodes as `None`. Client-carried + verified in-guest; no Nabla
    /// (RULE 7). A universal reality/Sybil FLOOR: makes N Sybil identities
    /// expensive (each must actually participate to renew). Orthogonal to the
    /// per-key candidacy Pulse (machine cost) above.
    #[serde(default)]
    pub renewal_work_receipt: Option<Receipt>,
}

/// ╔═════════════════════════════════════════════════════════════╗
/// ║  ONE ISSUER'S CL8 SIGNATURE OVER A REQUESTED CERTIFICATE     ║
/// ║  Design: AXIOM_DESIGN_ValidatorJoin.md §5.2.2d               ║
/// ╚═════════════════════════════════════════════════════════════╝
/// What a witness returns for a `TxKind::VbcRequest` round INSTEAD of a
/// payment cheque. Three of these — from three distinct issuers — combine
/// into the `signatures` of a `VBCProofBundle` (`VBC_REQUIRED_ISSUERS = 3`,
/// an EXACT count, never a threshold).
///
/// ⚠ THIS IS NOT A CHEQUE AND CARRIES NO VALUE. A holder that files it in a
/// cheque store would show a certificate as pending money and, worse, could
/// try to redeem it. The SDK must recognise the artifact by its own field and
/// never by "the cheque slot happened to be empty" —
/// `AXIOM_DESIGN_ValidatorJoin.md` §5.2.2d.
///
/// `commitment` is CORE's own signing payload, returned so the candidate can
/// verify each signature independently instead of trusting the issuer that
/// sent it. Rebuilding it locally would be a second definition of what was
/// signed (RULE 1) — verify against this, or against
/// `compute::compute_vbc_signing_payload` on the assembled cert, never a
/// hand-rolled preimage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VbcIssuerSignature {
    /// SPHINCS+ signature produced inside Core CL8.
    pub signature: Vec<u8>,
    /// The issuing validator's SPHINCS+ public key.
    pub signer_sphincs_pk: Vec<u8>,
    /// Core's signing payload — what the signature actually covers.
    pub commitment: [u8; 32],
}

/// 30 days — minimum VBC age before validator can approve new validators.
/// Genesis validators (in GENESIS_VALIDATORS) are exempt.
pub const VBC_APPROVAL_MATURITY_SECS: u64 = 30 * 86_400;

/// Meta-Validator Inheritance Binding (MVIB) — Yellow Paper §10.
///
/// When a validator joins the network, it publishes a signed binding to its
/// upstream admission set: the k=3 validators who signed its VBC. This binding
/// allows JFP voting responsibility to pass to meta-validators when a validator
/// disappears.
///
/// The commitment is: BLAKE3("AXIOM_MVIB" || validator_id || admission_set || tick)
/// The signature is Ed25519 over that commitment, using the validator's operational key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MvibBinding {
    /// The new validator's ID (BLAKE3 of SPHINCS+ PK)
    pub validator_id: [u8; 32],

    /// The k=3 validator IDs who signed this validator's VBC (admission set)
    pub admission_set: Vec<[u8; 32]>,

    /// Tick at which the binding was published
    pub binding_tick: u64,

    /// Ed25519 signature over BLAKE3("AXIOM_MVIB" || validator_id || admission_set || tick)
    pub signature: Vec<u8>,
}

// ── YPX-013: Console Engine ──────────────────────────────────────────────────

/// Console size: 15 validators (White Paper §7.4, Yellow Paper §21.10.2).
pub const CONSOLE_SIZE: usize = 15;

/// Ticks per year: 365 days × 86400 s/day ÷ 5 s/tick = 6,311,520.
pub const CONSOLE_TICKS_PER_YEAR: u64 = 6_311_520;

/// Election nomination window: 1 week = 120,960 ticks.
pub const CONSOLE_ELECTION_WINDOW_TICKS: u64 = 120_960;

/// Election retry cooldown: ~1 month = 525,960 ticks.
pub const CONSOLE_ELECTION_RETRY_TICKS: u64 = 525_960;

/// Maximum election attempts before permanent dissolution.
/// After this many failures, Console is gone for this Core version.
/// No restart mechanism. No override. New Core ELF required.
pub const CONSOLE_MAX_ELECTION_ATTEMPTS: u8 = 3;

/// Number of random selectors chosen from current Console for election.
pub const CONSOLE_SELECTOR_COUNT: usize = 3;

/// Each selector picks this many validators from nomination list.
pub const CONSOLE_PICKS_PER_SELECTOR: usize = 5;

/// Chain depth: keep this many generations in full, compress older ones.
pub const CONSOLE_CHAIN_DEPTH: u32 = 30;

/// Console compensation: 1 AXC per full service year (White Paper §G.4).
pub const CONSOLE_COMPENSATION_AXC: u64 = 1;

// ── YPX-018: BLOOM_PHASE_OUT constitutional limits ───────────────────────────
//
// These constants live in Core and are validated in CL11 when Core signs a
// `BloomPhaseOut` Console certificate. The Console **cannot** override them
// — only a new Core ELF (a worldline change, per YPX-013) can.
//
// Combined effect: any cheque issued in tick T cannot become unreachable
// before tick T + 55 years, no matter what the Console decides.

/// Minimum age of any era before it may be phased out.
/// 50 years = 50 × 6,311,520 = 315,576,000 ticks.
/// Set to span a full adult lifetime — anyone who received a cheque as a
/// young adult can still redeem it as an old person.
/// Reference: YPX-018 §4.3, YPX-013 §1.2.
pub const MIN_PHASE_OUT_AGE_TICKS: u64 = 50 * CONSOLE_TICKS_PER_YEAR;

/// Minimum grace period from proposal approval to effective phase-out.
/// 5 years = 5 × 6,311,520 = 31,557,600 ticks.
/// Reference: YPX-018 §4.3, YPX-013 §1.2.
pub const MIN_PHASE_OUT_GRACE_TICKS: u64 = 5 * CONSOLE_TICKS_PER_YEAR;

/// YPX-013: Console Certificate — Core-signed generational governance artifact.
///
/// Each Console term produces one certificate. The chain of certificates
/// traces Console authority back to genesis, like FACT traces money provenance.
/// All Console operations pass through the Console group wallet (DWP/ prefix).
///
/// The certificate hash (chain link) is:
/// BLAKE3("AXIOM_CONSOLE_CHAIN" || generation || seats || term_start || term_end || prev_hash)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleCertificate {
    /// Generation number (0 = genesis, increments each term)
    pub generation: u32,

    /// The 15 validator seats (validator_id for each)
    pub seats: Vec<[u8; 32]>,

    /// Term start (TARDIS tick)
    pub term_start_tick: u64,

    /// Term end (term_start_tick + TICKS_PER_YEAR)
    pub term_end_tick: u64,

    /// BLAKE3 hash of the previous ConsoleCertificate (all zeros for genesis)
    pub previous_link_hash: [u8; 32],

    /// Which election attempt produced this certificate (0-indexed)
    pub election_attempt: u8,

    /// Console group wallet address (DWP/CONSOLE/{generation})
    pub group_wallet_id: String,

    /// Core Ed25519 signature over the certificate hash
    pub core_signature: Vec<u8>,
}

/// A selector's picks during Console election.
/// Each of the 3 randomly-chosen selectors picks 5 validators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectorPick {
    /// The selector's validator_id (= BLAKE3(sphincs_pk), must be in current Console)
    pub selector_id: [u8; 32],

    /// The 5 validator_ids this selector chose from the nomination list
    pub picks: Vec<[u8; 32]>,

    /// Ed25519 signature over `console::compute_pick_signing_payload` =
    /// BLAKE3("AXIOM_CONSOLE_PICK" || selector_id || picks || election_tick_le_u64)
    /// (YP Appendix domain-tag table). ~~"… || generation"~~ — that layout was a
    /// dead builder's, never the verifier's (KI#245, corrected 2026-10-02).
    /// An empty signature is refused in every build.
    pub signature: Vec<u8>,

    /// AUDIT-FIX v2.11.14: Selector's Ed25519 public key (from VBC.subject_pubkey_ed25519).
    /// Required for signature verification. validator_id = BLAKE3(sphincs_pk) ≠ ed25519_pk.
    #[serde(default)]
    pub selector_ed25519_pk: [u8; 32],
}

/// Validator Birth Certificate (VBC) v0.9
///
/// The VBC is a validator's identity document, signed by 3 issuers.
/// Chain verification walks issuer_set → issuer VBCs → ... → root PKs.
/// Root PKs are hardcoded in Core — the trust anchor of the entire network.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(Default))]
pub struct VBC {
    /// ╔═══════════════════════════════════════════════════════════════╗
    /// ║  §5.3 GENESIS LINEAGE — which genesis family this validator    ║
    /// ║  belongs to. ONE root, never a set.                            ║
    /// ╚═══════════════════════════════════════════════════════════════╝
    /// The SPHINCS+ PUBLIC KEY of the genesis validator this certificate
    /// descends from — the same value space as `GENESIS_VALIDATORS`, which
    /// holds public keys and NOT validator ids.
    ///
    /// `[0u8; 32]` means UNSET. A genesis validator's own certificate carries
    /// zero and its lineage is DERIVED from its subject key
    /// (`vbc::effective_genesis_lineage`), so the twenty deployed genesis
    /// certificates keep a byte-identical signing pre-image and stay valid.
    ///
    /// **Exactly one, deliberately.** Inheriting the UNION of the three
    /// issuers' lineages decays to nothing within two generations: a
    /// first-generation validator would carry {α, β, γ}, so three of them could
    /// each point at a different member of that same set and satisfy "three
    /// different lineages" while being the same cohort admitted by the same
    /// three. With one inherited root, every validator speaks for exactly one
    /// family forever, so growing any family always needs two others to agree.
    ///
    /// Set at issuance to the lineage of the THIRD issuer — which is
    /// CANDIDATE-DECLARED and issuer-consented, not sequence-derived: all three
    /// issuers sign identical bytes, so the certificate records nothing about
    /// who finalised. See `AXIOM_DESIGN_ValidatorJoin.md` §5.3.4.
    pub genesis_lineage: [u8; 32],

    /// VBC format version (0x09 = v0.9)
    pub version: u8,
    
    /// Subject validator's unique ID (BLAKE3 hash of SPHINCS+ PK)
    pub validator_id: [u8; 32],
    
    /// Subject's SPHINCS+ public key — primary VBC identity (32 bytes)
    /// Used for VBC chain signatures. Quantum-resistant.
    pub subject_pubkey_sphincs: Vec<u8>,
    
    /// Subject's Dilithium (ML-DSA-65) public key — backup identity (1,952 bytes)
    /// Stored in VBC for algorithm-independence; covered by issuers' SPHINCS+ signatures.
    /// If SPHINCS+ ever breaks, this provides an authenticated fallback identity.
    pub subject_pubkey_dilithium: Vec<u8>,
    
    /// Subject's Ed25519 public key — witness signing + encryption (32 bytes)
    /// This is the key used for day-to-day transaction witnessing.
    /// Can be converted to X25519 for encrypted communication.
    pub subject_pubkey_ed25519: Vec<u8>,
    
    /// PGP fingerprint (optional, 20 bytes)
    /// Links AXIOM identity to real-world PGP web of trust.
    /// Empty if validator prefers anonymity.
    #[serde(default)]
    pub pgp_fingerprint: Vec<u8>,

    /// Human-readable node name chosen by operator.
    /// Authenticated: covered by issuers' SPHINCS+ signatures.
    /// Same concept as pgp_fingerprint — optional identity metadata.
    /// Max 64 bytes UTF-8. Supports any language (English, Chinese, Japanese, etc).
    /// Empty string if operator doesn't set a name.
    #[serde(default)]
    pub node_name: String,

    /// Proof capability at onboarding: "dmap" or "zkvm"
    /// Determined by benchmark. Covered by issuer SPHINCS+ signatures.
    #[serde(default)]
    pub proof_cap: String,

    /// Issued timestamp (Unix epoch seconds)
    pub issued_at: u64,
    
    /// Expires timestamp (Unix epoch seconds)
    pub expires_at: u64,
    
    /// Chain depth: 0 = signed by root keys, 1 = signed by genesis validators, etc.
    /// Maximum allowed depth defined by MAX_VBC_CHAIN_DEPTH.
    pub chain_depth: u8,
    
    /// Issuer SPHINCS+ public keys (exactly 3)
    /// For genesis VBCs: 3 root authority PKs
    /// For new validators: 3 existing validator SPHINCS+ PKs
    pub issuer_set: Vec<Vec<u8>>,
    
    /// Issuer SPHINCS+ signatures over VBC commitment (7,856 bytes each)
    /// Signs: BLAKE3("AXIOM_VBC_V1" || all fields above)
    pub signatures: Vec<Vec<u8>>,
    
    /// Maximum transaction (registration) budget for this NBC/VBC.
    /// Peers track registrations processed by this node and reject once past max_tx.
    /// On renewal, counter resets (new NBC = new budget).
    /// 0 means unlimited (backward compat with pre-budget NBCs).
    /// Covered by issuer SPHINCS+ signatures.
    #[serde(default)]
    pub max_tx: u64,

    /// Founding VBC hash — BLAKE3 hash of this validator's FIRST-EVER VBC.
    /// Set to [0; 32] on initial VBC (self-referential: hash of this VBC).
    /// Carried forward unchanged on every renewal.
    /// Allows anyone to verify founding date and original signing lineage.
    /// Committed into the signing payload when NON-ZERO (`crypto.rs`), so a
    /// renewal cannot fabricate its founding date. An initial cert's [0;32]
    /// is excluded — committing it would be self-referential.
    #[serde(default)]
    pub founding_vbc_hash: [u8; 32],

    /// OODS baseline (YPX-021 §7) — the issuer's PROVEN network-size view,
    /// stamped into the certificate at issuance/renewal. The subject node is
    /// "born with a baseline" inherited through the genesis-rooted cert
    /// chain: to hand a node a fake baseline you need a colluding issuer
    /// whose own cert chains to genesis.
    ///
    /// `0` = no baseline — genesis certs are the root of trust and are
    /// EXEMPT (their baseline is a ceremony concern, deferred per §7).
    /// When non-zero, the value is bound into the issuer signatures: see
    /// `compute_vbc_signing_payload_bytes`, which appends
    /// `network_size_baseline || baseline_tick` to the signing pre-image
    /// ONLY when the baseline is non-zero, keeping genesis/pre-baseline
    /// cert signatures byte-identical.
    #[serde(default)]
    pub network_size_baseline: u32,

    /// TARDIS tick at which `network_size_baseline` was measured by the
    /// issuer. `0` when no baseline (genesis exemption).
    #[serde(default)]
    pub baseline_tick: u64,

    /// §6b — Nabla's registration stamp. `None` = a CANDIDATE certificate:
    /// issued, not yet usable. Set by the operator's registration leg after
    /// Nabla verified the stake wallet against ITS OWN state (§6b.4).
    ///
    /// ⚠ NOT in the issuer-signed pre-image, by construction (§6b.3) — the
    /// issuers sign before it exists. ⚠⚠ NEVER append it to
    /// `compute_vbc_signing_payload_bytes`: the OODS suffix binding there is
    /// `cfg(not(dev-mode))`, so a dev fleet cannot catch that regression.
    ///
    /// Added LAST with `serde(default)`: the 20 deployed certificates decode
    /// unchanged and keep VALID ISSUER SIGNATURES. Only ENFORCEMENT
    /// (`validation::verify_vbc_stamp` at the verify path) refuses them, and
    /// that is the §6b.7 flag day, deliberately.
    #[serde(default)]
    pub nabla_registration: Option<NablaVbcStamp>,
}

/// Public inputs to Core.bin (what goes into the zkVM)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(Default))]
pub struct PublicInputs {
    /// Which mode to execute
    pub mode: CoreLogicMode,
    
    /// The transaction to validate (CL1-CL4)
    pub transaction: Transaction,
    
    /// Previous receipts (for balance/seq verification)
    pub prev_receipts: Vec<Receipt>,
    
    /// Current wallet state (if known)
    pub current_state: Option<WalletState>,
    
    /// VBC bundle for validator verification (CL2/CL3)
    pub vbc_bundle: Option<VBCProofBundle>,
    
    // === CL5 Redeem fields ===
    
    /// Cheque bundle for redemption (CL5 only)
    pub cheque_bundle: Option<ChequeBundle>,
    
    /// Receiver's public key (CL5 only)
    pub receiver_pk: Option<Vec<u8>>,
    
    /// Receiver's current balance before redeem (CL5 only)
    pub receiver_current_balance: Option<u64>,
    
    /// Receiver's wallet_seq (CL5 only)
    pub receiver_wallet_seq: Option<u64>,

    /// YPX-020 — receiver's CURRENT `hibernation_until` (CL5 only), supplied by
    /// the validator from its stored receiver state (same trusted path as
    /// `receiver_current_balance`; k-witnessing keeps it honest). CL5 CARRIES it
    /// into the produced state rather than zeroing it, so a self-redeem cannot
    /// clear a wallet's hibernation lock. `None`/0 = not hibernating.
    #[serde(default)]
    pub receiver_current_hibernation: Option<u64>,
    /// §5.2.2c — the receiver's CURRENT stake lock, so CL5 can carry it forward
    /// into the produced state. A redeem must never clear it: the lock is
    /// released by time, never by a transaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver_current_wall_clock_lock: Option<u64>,

    /// Expected new balance after redeem (CL5 only)
    pub receiver_new_balance: Option<u64>,
    
    /// Expected new state_id after redeem (CL5 only)
    pub receiver_new_state_id: Option<[u8; 32]>,

    // fee_breakdown on PublicInputs deleted 2026-06-05 PM. Pre-fix the
    // SDK proposed the per-validator allocation and Lambda forwarded it
    // here for Core CL5's NET balance binding. Replaced by reading
    // `cheque.rate_bps` (Dilithium-signed at issuance) from each cheque
    // in `cheque_bundle.cheques`. Core CL5 sums
    // `expected_fee_slot_amount(c.amount, c.rate_bps)` directly. No
    // client view of validator rates flows into the hash any more.
    // Closes `E_RECEIPT_COMMITMENT_MISMATCH` class. CLAUDE.md §13:
    // pre-mainnet, no shim — just delete.

    // === CL3 S-ABR Overlap fields ===
    
    /// This validator's public key (CL3 only)
    /// Used to determine if this validator is overlapped or fresh
    pub my_validator_pk: Option<Vec<u8>>,

    /// Overlapped signatures: witness sigs from previous-TX validators
    /// who have ALREADY signed THIS transaction (CL3 only)
    /// Fresh validators must provide ≥ k-1 overlapped sigs to proceed
    pub overlapped_signatures: Vec<WitnessSig>,

    // === Group wallet fields ===

    /// Member index for group wallet withdrawal (group wallet TX only)
    /// Identifies which member is withdrawing their share.
    /// Core verifies: members[index] exists and amount <= available.
    /// The receiver's personal wallet verifies wallet_id matches on redemption.
    pub group_member_index: Option<u32>,

    // === FACT chain fields (YPX-001) ===

    /// Sender's FACT chain for CL2 send validation.
    /// Lambda passes the sender's stored chain; Core verifies integrity.
    /// At CL5 redeem, FACT chain comes from cheque_bundle.fact_chain instead.
    pub sender_fact_chain: Option<FactChain>,

    /// YPX-010 §11.2.1 / P3.7 — the receiver's co-signature for the `ArkSendFinalize`
    /// mode (offline k=0 ⟠ trade). The sender's own Core assembles the k=0 send link
    /// and attaches this witness (the SDK cannot, CLAUDE §12). `None` on every online
    /// mode. Only `ArkSendFinalize` reads it.
    #[serde(default)]
    pub receiver_witness: Option<ReceiverWitness>,

    /// YPX-010 §11.2.1 — the redeeming wallet's OWN Ed25519 signing key, supplied
    /// ONLY on the offline k=0 CL5 profile so Core can sign the redeem link's
    /// `receiver_witness` in-guest (a k=0 link is unverifiable without one, P3.2).
    /// The exact `my_dilithium_sk` precedent: keys pass INTO Core, Core signs —
    /// the SDK never assembles witness material (CLAUDE §12). Never transmitted on
    /// any wire: the offline redeem executes on the receiver's own device (like
    /// `wallet_secret`). `None` on every online mode and every k≥3 redeem; the k=0
    /// CL5 profile REJECTS (`ArkReceiverWitnessMissing`) without it.
    #[serde(default)]
    pub receiver_signing_key: Option<[u8; 32]>,

    /// Operator-configurable maximum FACT chain depth (from `lambda.toml`'s
    /// `max_fact_links`). Lambda passes this in CL2 calls so Core — not Lambda —
    /// enforces depth-gating. `None` = no operator limit (effectively unlimited;
    /// Core's hard protocol cap `MAX_TOTAL_LINKS` still applies in `fact.rs`).
    ///
    /// `is_heal && sender_wallet_id == receiver_wallet_id` is exempt: scar-burn
    /// recovery TXs need to bypass the depth gate to clear scars that prevent
    /// FACT compression. See `validation.rs` for the check and
    /// `feedback_layer_roles.md` for why this lives in Core, not Lambda.
    pub max_fact_links: Option<u32>,

    /// YP §26.17.6.5 B2/B4 (2026-09-11) — the certificate bundles the FACT
    /// witnesses of `sender_fact_chain` resolve to (live-tail witnesses,
    /// checkpoint cosigners, burn-proof signers), deduplicated by reference.
    /// Core verifies each ONCE (`verify_vbc_bundle_historical`, no clock) and
    /// binds witnesses by hash. An absent certificate is a refusal, never a
    /// lookup: who supplies the bytes (the client from its receipts, Lambda
    /// from its store) is transport, and the verdict is the same everywhere.
    #[serde(default)]
    pub fact_certificates: Vec<VBCProofBundle>,

    /// Receiver's existing FACT chain at CL5 redeem time.
    /// Core appends the new redeem link to this via `build_fact_link`
    /// when the finalizer's CL5 has all `required_k` witness sigs in
    /// `fact_witness_sigs`. None for first-time receivers (chain starts
    /// empty). The SDK passes this from `wallet.fact_chain()` so Core —
    /// not the SDK — assembles FACT links (CLAUDE.md §12).
    #[serde(default)]
    pub receiver_fact_chain: Option<FactChain>,

    // === Validator crypto keys (CL3 only) ===

    /// This validator's Dilithium private key (CL3 only).
    /// Core uses this to sign FACT commitments internally.
    /// Lambda MUST NOT sign FACT directly — it passes the key to Core.
    pub my_dilithium_sk: Option<Vec<u8>>,

    /// This validator's Dilithium public key (CL3 only).
    /// Included in FACT witness entries.
    pub my_dilithium_pk: Option<Vec<u8>>,

    /// This validator's ID (CL3 only).
    /// Included in FACT witness entries.
    pub my_validator_id: Option<[u8; 32]>,

    /// Accumulated FACT witness signatures from other validators (CL3/k=3 path only).
    /// At k=3, Core builds the FACT link using these sigs plus its own.
    pub fact_witness_sigs: Vec<WitnessSig>,

    // === CL8 NBC Issuance fields ===

    /// Issuer's SPHINCS+ private key for NBC signing (CL8 only).
    /// Core signs the NBC internally — Nabla MUST NOT call sign_sphincs directly.
    pub issuer_sphincs_sk: Option<Vec<u8>>,

    // === CL1 ZKP fields ===

    /// Client's CL1 execution proof (optional).
    /// When present, Lambda's ZkvmVerifier checks this before calling CL2.
    /// CL1 ZKP proves the client ran Core and got Accept — validator can fast-path.
    #[serde(default)]
    pub cl1_execution_proof: Option<Vec<u8>>,

    /// Fresh 256-bit random nonce for ZKP anti-replay binding.
    /// Core hashes this into PublicOutputs; verifier checks the binding.
    #[serde(default)]
    pub zkp_nonce: Option<[u8; 32]>,

    // === §23.14 Peer Audit ===

    /// Audit confirmation from Lambda in response to a previous AuditDemand.
    /// If Core previously demanded an audit and the AVM countdown is active,
    /// Lambda MUST provide this within AUDIT_COUNTDOWN_TXS invocations.
    #[serde(default)]
    pub audit_confirmation: Option<AuditConfirmation>,

    // === YPX-009 Silicon Pulse ===

    /// Nonce response from Lambda (YPX-009 §3.6).
    /// Lambda answers the previous NonceChallenge with current wallet state.
    #[serde(default)]
    pub nonce_response: Option<NonceResponse>,

    /// Audit response from Lambda (YPX-009 §4.4).
    /// Lambda re-executed selected TXs and provides chain hash.
    #[serde(default)]
    pub audit_response: Option<PulseAuditResponse>,

    /// Wallet secret for CL5 ownership verification (never transmitted on wire).
    /// Client provides this for local DMAP proof; validator sees only the proof.
    #[serde(default)]
    pub wallet_secret: Option<[u8; 32]>,

    /// Fan-out message for CL10 verification (§18.8).
    #[serde(default)]
    pub fanout_message: Option<FanOutMessage>,

    /// `NablaStakeProof` — the ORACLE claim's stake evidence only (YPX-012,
    /// `validation.rs` oracle path; the oracle is disabled). Its certificate
    /// use was RULED out (ValidatorJoin §6b.8, executed 2026-09-15 — KI#168):
    /// CL8 does not read it; the registration stamp is the stake authority.
    #[serde(default)]
    pub nabla_stake_proof: Option<NablaStakeProof>,

    /// JFP §7: Frozen wallet PKs from active freeze orders in management_db.
    /// Lambda queries freeze_orders table and passes wallet PKs here.
    /// Core CL1 rejects transactions from any sender whose client_pk is in this set.
    /// Dual enforcement: Nabla SCAR marks for public knowledge, Core freeze blocks TXs.
    #[serde(default)]
    pub frozen_wallets: Option<Vec<[u8; 32]>>,

    // ── CL11: Console (YPX-013) ──────────────────────────────────────────────

    /// Current Console Certificate (for chain verification during election finalization).
    #[serde(default)]
    pub console_current_cert: Option<ConsoleCertificate>,

    /// New Console Certificate to validate (CL11 FinalizeElection).
    #[serde(default)]
    pub console_new_cert: Option<ConsoleCertificate>,

    /// Selector picks for election verification (CL11 FinalizeElection).
    #[serde(default)]
    pub console_selector_picks: Option<Vec<SelectorPick>>,

    /// Nomination list (validator_ids that self-nominated during election).
    #[serde(default)]
    pub console_nominations: Option<Vec<[u8; 32]>>,

    // === CL5 Txid Attestation (YPX-014) ===

    /// Client-provided Nabla txid attestation for global double-redeem prevention.
    /// Core CL5 verifies: Ed25519 signature, status == "NOT_REDEEMED", PK trust anchor.
    /// Lambda handles freshness (wall clock). Core handles cryptographic verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txid_attestation: Option<NablaTxidAttestation>,

    /// Client-provided Nabla cheque-claim proof — the synchronous-write
    /// chokepoint that closes the gossip-race window of `txid_attestation`.
    /// `Option<>` for back-compat with non-redeem CL paths only; **CL5
    /// requires this** and rejects with `E_CHEQUE_CLAIM_PROOF_MISSING`
    /// if absent (per CLAUDE.md §13 — no soft fallback).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cheque_claim_proof: Option<ChequeClaimProof>,

    // === YPX-021 OODS health flag (§8.2) ===

    /// Client-carried Nabla OODS reading for the health flag. When present,
    /// Core verifies it (`validation::verify_oods_attestation` — hard
    /// reject on an invalid one, never a silent downgrade) and stamps the
    /// derived `OodsFlag` into the receipt + `receipt_commitment`. `None`
    /// on paths with no Nabla reading (heal, genesis claim — Phase 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oods_attestation: Option<NablaOodsAttestation>,

    /// YPX-022 RECALL — Nabla recall attestation (proof the txid's consume-once
    /// landed). Core CL2 requires it on a RECALL self-send before it relaxes overlap
    /// + restores the pre-send balance. `None` on every non-RECALL path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recall_attestation: Option<RecallAttestation>,

    /// §10.0 FOB fee-claim — Nabla attestation of the FULL pool + linkage.
    /// Core CL2 REQUIRES it on a `ValidatorWithdrawalMint` self-send and pins
    /// amount/sender/class against it. `None` on every other path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fob_claim_attestation: Option<FobClaimAttestation>,
    /// ╔═ BOOTSTRAP SUBSIDY — REMOVE WHEN POOLS DRAIN ═══════════════╗
    /// Design: AXIOM_DESIGN_ValidatorJoin.md §5.2.2b
    /// ╚═════════════════════════════════════════════════════════════╝
    /// The CLAIMANT's provisional VBC — the §5.2.2 binding that must exist
    /// BEFORE the funding. `None` on every path that is not a subsidy claim.
    ///
    /// ⚠ DISTINCT FROM `vbc_bundle`, which is the WITNESSING validator's
    /// credential — each witness carries its own, and nothing carried the
    /// CLAIMANT's. That absence is why the claim had no admission gate at all
    /// and three ordinary wallets drew 498.5 AXC each on 2026-09-02.
    ///
    /// Rides `PublicInputs`/`WitnessRequest`, NOT the canonical `Transaction`,
    /// so txids, receipt commitments and the signed tx bytes are untouched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimant_vbc: Option<VBCProofBundle>,

    // === §13 Progressive Redeem Registration ===

    // === YPX-018 — CLARA wallet recovery attestation ===

    /// Client-provided Nabla CLARA attestation for partial-witness recovery.
    /// When present, Core CL2 verifies the wallet binding, the Nabla signature,
    /// the NBC anchor and the eligibility rule (validator's stored state ==
    /// `healed_to_state_id`, KI#260). Nothing is rewritten.
    /// See YPX-018 §2.3 and Yellow Paper §17.10.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clara_attestation: Option<ClaraAttestation>,

    // === YPX-018 — Console BLOOM_PHASE_OUT (CL11) ===

    /// Payload for a `BLOOM_PHASE_OUT` Console action. When present, CL11
    /// dispatches on this instead of the election finalization path.
    /// Validated against the constitutional limits in §6.2.3 (50-year minimum
    /// age, 5-year minimum grace, era exists, era not already phased out,
    /// effective_tick in the future). The Console cannot override these
    /// limits — only a new Core ELF can.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase_out_payload: Option<ConsoleProposalBloomPhaseOut>,

    /// Map of `era_id → era end_tick`, supplied by Lambda from the Bloom Age
    /// Index gossip state. Used by CL11 to verify the constitutional minimum
    /// age check (era.end_tick + MIN_PHASE_OUT_AGE_TICKS <= effective_tick).
    /// CBOR-encoded as `Vec<(u64, u64)>`. Empty when not in a BLOOM_PHASE_OUT
    /// CL11 invocation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub phase_out_era_end_ticks: Vec<(u64, u64)>,

    /// Set of era_ids that are already in `PhasedOut` or `ScheduledPhaseOut`
    /// status (per Lambda's view of the gossiped Bloom Age Index). CL11
    /// rejects re-phase-out of any era in this set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub phase_out_blocked_era_ids: Vec<u64>,

    /// Current TARDIS tick (passed in by Lambda for grace-period validation).
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub current_tick: u64,

    /// BLAKE3 of the Core ELF this host is running. Validators pass it in
    /// from compile-time `CANONICAL_CORE_ID` (release) or runtime hash of
    /// the loaded ELF (dev). CL2 Step −1.5 rejects with
    /// `ValidationError::CoreIdMismatch` if the incoming TX's `core_id`
    /// is non-zero and doesn't match — cheaper than running DMAP /
    /// signature verification just to discover the same thing deep in
    /// the proof.
    ///
    /// Defaults to all-zero, which disables the check (backward compat
    /// for callers built before this field existed and for dev paths
    /// that haven't wired the hash through yet).
    #[serde(default)]
    pub local_core_id: [u8; 32],

    /// §4.2a — the receiver's CURRENT `emission_claimed_epoch`, replayed into the
    /// CL5 post-redeem state hash exactly like the two lock fields above.
    #[serde(default)]
    pub receiver_current_emission_claimed_epoch: Option<u64>,

    /// §6b.13 — the receiver's CURRENT `stake_floor_until`, CARRIED into the CL5
    /// post-redeem state hash (receiving never sets, lowers or gates it). `None`
    /// outside CL5. Mandatory on the wire (no `serde(default)`).
    pub receiver_current_stake_floor_until: Option<u64>,
    /// §6b.13 — the receiver's CURRENT wallet-format block. CL5 refuses a
    /// receiver state whose block is not `WalletFormat::CURRENT`
    /// (`E_WALLET_FORMAT_INVALID`) and carries it into the produced state.
    pub receiver_current_wallet_format: Option<WalletFormat>,
    /// YPX-007 §9.2 (KI#125) — mode `ZkpQualify` only (T1 + the journal binding).
    /// `None` on every other mode; skipped from the wire when `None` so every
    /// other mode's input encoding is byte-unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zkq_request: Option<ZkpQualifyRequest>,
}

impl PublicInputs {
    /// Build minimal inputs for `CL12` (offline Send Proof verification): the
    /// proof's signed `transaction` plus its finalized `receipt` (carried as
    /// `prev_receipts[0]`); every other field empty/None. Lets an offline
    /// verifier (e.g. `tools/verify-send-proof`) pipe a retained proof straight
    /// into the Core ELF without hand-constructing 60 unrelated fields.
    pub fn for_send_proof_verify(transaction: Transaction, receipt: Receipt) -> Self {
        PublicInputs {
            zkq_request: None,
            fact_certificates: alloc::vec::Vec::new(),
            mode: CoreLogicMode::CL12,
            transaction,
            prev_receipts: alloc::vec![receipt],
            current_state: None,
            vbc_bundle: None,
            cheque_bundle: None,
            receiver_pk: None,
            receiver_current_balance: None,
            receiver_wallet_seq: None,
            receiver_current_hibernation: None,
            receiver_current_wall_clock_lock: None,
            receiver_current_emission_claimed_epoch: None,
            receiver_current_stake_floor_until: None,
            receiver_current_wallet_format: None,
            receiver_new_balance: None,
            receiver_new_state_id: None,
            my_validator_pk: None,
            overlapped_signatures: alloc::vec![],
            group_member_index: None,
            sender_fact_chain: None,
            receiver_witness: None,
            receiver_signing_key: None,
            max_fact_links: None,
            receiver_fact_chain: None,
            my_dilithium_sk: None,
            my_dilithium_pk: None,
            my_validator_id: None,
            fact_witness_sigs: alloc::vec![],
            issuer_sphincs_sk: None,
            cl1_execution_proof: None,
            zkp_nonce: None,
            audit_confirmation: None,
            nonce_response: None,
            audit_response: None,
            wallet_secret: None,
            fanout_message: None,
            nabla_stake_proof: None,
            frozen_wallets: None,
            console_current_cert: None,
            console_new_cert: None,
            console_selector_picks: None,
            console_nominations: None,
            txid_attestation: None,
            cheque_claim_proof: None,
            oods_attestation: None,
            recall_attestation: None,
            fob_claim_attestation: None,
            claimant_vbc: None,
            clara_attestation: None,
            phase_out_payload: None,
            phase_out_era_end_ticks: alloc::vec![],
            phase_out_blocked_era_ids: alloc::vec![],
            current_tick: 0,
            local_core_id: [0u8; 32],
        }
    }
}

#[inline]
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

/// Public outputs from Core.bin (what comes out of the zkVM)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicOutputs {
    /// Accept or Reject
    pub result: ValidationResult,
    
    /// New state hash (if accepted)
    pub new_state_hash: Option<[u8; 32]>,
    
    /// Produced state ID (if accepted)
    pub produced_state_id: Option<[u8; 32]>,
    
    /// New wallet sequence number (if accepted)
    pub new_wallet_seq: Option<u64>,
    
    /// Rejection reason (if rejected)
    pub rejection_reason: Option<ValidationError>,
    
    /// S-ABR: Is the calling validator overlapped with prev_receipts?
    /// None = no VBC provided (can't determine)
    /// Some(true) = validator's PK found in prev_receipts witness sigs
    /// Some(false) = validator is new (not in prev_receipts)
    pub is_overlapped: Option<bool>,
    
    /// Commitment hash computed by Core for this transaction.
    /// BLAKE3("AXIOM_WITNESS_V2" || consumed_state_id || client_pk || ...)
    /// Validators MUST sign this hash. Lambda MUST NOT compute it.
    pub commitment_hash: Option<[u8; 32]>,
    
    /// Transaction ID computed by Core.
    /// BLAKE3("AXIOM_TXID" || consumed_state_id || len32(client_pk) || client_pk || ...)
    /// Lambda MUST NOT compute this. Core returns it in outputs.
    pub txid: Option<[u8; 32]>,
    
    /// FACT commitment signature (Dilithium ML-DSA-65) for this validator.
    /// Core signs the FACT commitment internally using the validator's Dilithium SK.
    /// Lambda MUST NOT sign FACT directly — Core returns this in outputs.
    pub fact_signature: Option<Vec<u8>>,
    
    /// New balance after this transaction (for Lambda storage).
    /// Core computes balance math. Lambda MUST NOT do balance arithmetic.
    pub new_balance: Option<u64>,

    /// NBC signature bytes (SPHINCS+, CL8 only).
    /// Core signs the NBC and returns the 7,856-byte signature.
    pub nbc_signature: Option<Vec<u8>>,

    /// BLAKE3("AXIOM_ZKP_NONCE" || zkp_nonce) — binds this proof to one specific TX.
    /// Verifier MUST check this matches the expected nonce from the original TX.
    #[serde(default)]
    pub zkp_nonce_hash: Option<[u8; 32]>,

    /// Compressed FACT chain returned by Core after verify_and_compress.
    /// Core is the sole authority for FACT compression (Dilithium checkpoint signing).
    /// Lambda MUST use this instead of the input chain for the witness response.
    #[serde(default)]
    pub compressed_fact_chain: Option<FactChain>,

    /// YPX-010 §11.2.1 / P3.7 — the sender's FACT chain WITH the freshly-assembled k=0
    /// send link (receiver-as-witness attached), produced by the `ArkSendFinalize` mode
    /// on the offline sender's device. `Some` only for that mode; the ark session puts
    /// it into the leg-3 cheque's `sender_fact_chain` so the receiver's local CL5 can
    /// verify + redeem. Core is the sole assembler (CLAUDE §12).
    #[serde(default)]
    pub ark_send_fact_chain: Option<FactChain>,

    /// Receiver's FACT chain after CL5 appended the redeem link.
    ///
    /// Populated only by `execute_cl5` on the finalizer validator (the one
    /// whose `inputs.fact_witness_sigs` plus its own sig reach `required_k`).
    /// All earlier validators in the redeem witness round leave this `None`;
    /// only the finalizer's Core call builds the link via `build_fact_link`.
    ///
    /// Lambda forwards this directly into the redeem response; the SDK stores
    /// it on the receiver's wallet via `wallet.set_fact_chain`. Replaces the
    /// pre-A2 SDK-side `build_and_append_fact_bridge` assembly path which
    /// violated CLAUDE.md §12 (Core is the sole cryptographic authority).
    #[serde(default)]
    pub receiver_fact_chain: Option<FactChain>,

    /// YPX-007: Required k extracted from receiver's wallet_id.
    /// Core fills this during validation. Lambda reads it for receipt threshold.
    #[serde(default)]
    pub required_k: u8,

    /// YPX-007: Proof type extracted from receiver's wallet_id.
    /// Core fills this during validation. Lambda reads it for DMAP/ZKP routing.
    #[serde(default)]
    pub extracted_proof_type: u8,

    // === §23.14 Peer Audit ===

    /// Audit demand generated by Core (§23.14 Ping Defense).
    /// When present, Lambda MUST initiate an audit of the target validator
    /// and provide `AuditConfirmation` within AUDIT_COUNTDOWN_TXS invocations.
    /// If Lambda fails to comply, the AVM interpreter self-terminates.
    #[serde(default)]
    pub audit_demand: Option<AuditDemand>,

    // === YPX-009 Silicon Pulse ===

    /// Audit request from AVM (YPX-009 §4.3).
    /// When present, Lambda must re-execute selected TXs and provide
    /// PulseAuditResponse in next PublicInputs.
    #[serde(default)]
    pub audit_request: Option<PulseAuditRequest>,

    /// Nonce challenge from AVM (YPX-009 §3.6).
    /// Lambda must look up the target wallet and respond with NonceResponse.
    #[serde(default)]
    pub nonce_challenge: Option<NonceChallenge>,

    /// Pulse proof data from AVM after successful audit (YPX-009 §5.1).
    /// Lambda forwards to Nabla for gossip broadcast.
    #[serde(default)]
    pub pulse_proof: Option<PulseProofData>,

    /// AVM detected audit failure (YPX-009 §4.5).
    /// Lambda should log and initiate restart.
    #[serde(default)]
    pub audit_failed: bool,

    /// Decremented TTL for fan-out forwarding (CL10 only).
    /// Lambda MUST use this value — cannot inflate.
    #[serde(default)]
    pub fanout_new_ttl: Option<u8>,

    /// CL11: Console chain hash of the verified new certificate.
    /// Lambda uses this to confirm Core accepted the election result.
    pub console_chain_hash: Option<[u8; 32]>,

    /// Receipt commitment — BLAKE3("AXIOM_RECEIPT_v1" || txid || state_hash
    /// || produced_state_id || new_wallet_seq || commitment_hash || epoch).
    /// Core computes this from its own outputs. Lambda signs it with
    /// Ed25519 and includes in WitnessSig.receipt_commitment_sig.
    /// CL2 on the next TX recomputes from receipt fields and verifies
    /// k signatures match — prevents receipt fabrication.
    #[serde(default)]
    pub receipt_commitment: Option<[u8; 32]>,


    /// Dev-class flag carried back from Core to Lambda so the Receipt
    /// Lambda builds (`receipt.rs::build_*_receipt`) stamps the SAME
    /// value Core just bound into `receipt_commitment`. Source of
    /// truth lives in Core (`modes.rs` CL3 reads
    /// `is_dev_wallet(tx.sender_wallet_id)`, CL5 cross-checks every
    /// cheque in the bundle); Lambda mirrors by copying this field
    /// onto the Receipt verbatim. `None` from non-TX modes is treated
    /// as `false` at the caller. See
    /// `AXIOM_DESIGN_FactClassIsolation.md`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_dev_class: Option<bool>,

    /// YPX-021 §8.2: the OODS health flag Core just derived from the
    /// verified `PublicInputs::oods_attestation` and bound into
    /// `receipt_commitment`. Carried back so Lambda/SDK stamp the SAME
    /// value onto `Receipt.oods_flag` (mirror of the `is_dev_class`
    /// pattern — source of truth lives in Core). `None` when no
    /// attestation was supplied (heal / genesis claim, Phase 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oods_flag: Option<OodsFlag>,

    /// P3.6 — the Core-computed CI factors carried back from a k=3 send so
    /// Lambda/SDK stamp the SAME value onto `Receipt.confidence_index` (source of truth
    /// in Core, mirror of `oods_flag`/`is_dev_class`). `None` on non-k=3 paths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_index: Option<ConfidenceIndex>,

    /// YP §32.3: the sender's `state_id` this redeem's funds derive from,
    /// which Core CL5 derived from the cheque bundle's FACT `sender_anchor`
    /// and bound into `receipt_commitment`. Carried back so Lambda/SDK stamp
    /// the SAME value onto `Receipt.sender_state` (mirror of `oods_flag` —
    /// source of truth in Core). `None` on every non-redeem path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_state: Option<[u8; 32]>,

    /// YPX-020: the hibernation deadline the produced state carries after a HAL
    /// re-anchor (`Transaction::produced_hibernation_until()` — `epoch +
    /// HIBERNATION_WINDOW` ticks projected onto the unix-second stamp); `0` for
    /// every other tx. This is the SAME value `compute_new_state_hash` folds into
    /// the state hash, so Lambda persisting it keeps the stored state in lock-step
    /// with what k=3 witnessed (the §15 anchor recomputes with it). The Core CL2
    /// gate reads the PRIOR state's value and rejects `WalletHibernating` while
    /// `tx.epoch < hibernation_until`. Skipped from the wire when 0 so normal-tx
    /// output encodings are byte-unchanged.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub hibernation_until: u64,

    /// §5.2.2c — the wall-clock lock on the PRODUCED state. Mirrors
    /// `hibernation_until` above and exists for the same reason: it is bound into
    /// `new_state_hash`, so Lambda and the wallet MUST persist THIS value or their
    /// next §15 anchor recompute misses and the wallet cannot commit. Core binding
    /// a value it does not return is exactly how the claim redeem got stuck.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub wall_clock_lock: u64,
    /// §4.2a — the produced state's `emission_claimed_epoch`, carried back to
    /// Lambda exactly like the two lock fields so it persists the value
    /// `compute_new_state_hash` bound into the witnessed state.
    #[serde(default)]
    pub emission_claimed_epoch: u64,
    /// §6b.13 — the produced state's `stake_floor_until`, returned so Lambda and
    /// the wallet persist the value bound into `new_state_hash` (the lesson of
    /// `wall_clock_lock` above: Core binding a value it does not return strands
    /// the wallet). Mandatory.
    pub stake_floor_until: u64,
    /// §6b.13 — the produced state's wallet-format block (always
    /// `WalletFormat::CURRENT` on an Accept). Mandatory.
    pub wallet_format: WalletFormat,
    /// YPX-007 §9.4 (KI#125) — the record mode `ZkpQualify` signed on Accept.
    /// `None` on every other mode (and skipped from the wire).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zkp_qualification: Option<ZkpQualificationRecord>,
}


// === §23.14: Peer Audit Demand (The Ping Defense) ===

/// Audit demand constants
pub const AUDIT_TRIGGER_RATE: u64 = crate::validation::protocol_gen::AUDIT_TRIGGER_RATE;    // ~1 in 100 TXs triggers audit
pub const AUDIT_COUNTDOWN_TXS: u8 = crate::validation::protocol_gen::AUDIT_COUNTDOWN_TXS as u8;     // Self-audit: Lambda has this many TXs to confirm (protocol_core.toml)
pub const PEER_AUDIT_COUNTDOWN_TXS: u8 = crate::validation::protocol_gen::PEER_AUDIT_COUNTDOWN_TXS as u8;  // Peer-audit: TXs to comply, email round-trip budget (protocol_core.toml)
/// Peer-audit response timeout, 10 min. ⚠ UNIT (tick-discipline fix 2026-09-21): a difference of
/// ATTESTED tick VALUEs (unix-second stamps — Core time, from `oods_attestation.tick`), compared
/// DIRECTLY. The `_TICKS` suffix flags Core-tick-sourced (NOT SystemTime), NOT a tick-COUNT — do
/// NOT project by TICK_INTERVAL_SECS. Same "tick is tick" convention as VBC expiry + the time-bond.
/// 600 tick-VALUE units = 600 s = 10 min. Replaced the wall-clock `_SECS` gate (`Instant::elapsed`).
pub const PEER_AUDIT_TIMEOUT_TICKS: u64 = crate::validation::protocol_gen::PEER_AUDIT_TIMEOUT_TICKS;
/// Ban duration: 24 hours as a TICK COUNT (a tick is <=5s wall clock, so
/// 24h = 86400s / TICK_INTERVAL_SECS = 17280 ticks). ⚠ DIFFERENT unit from the timeout above:
/// this is a COUNT, projected onto the `epoch` unix-second watermark by multiplying by
/// TICK_INTERVAL_SECS (`ban_window_stamp`) — the ban holds for AT LEAST this many ticks.
/// NEVER compared against SystemTime::now().
pub const PEER_AUDIT_BAN_TICKS: u64 = crate::validation::protocol_gen::PEER_AUDIT_BAN_TICKS;
// PEER_AUDIT_CRASH_DELAY_SECS removed 2026-09-21 — its only consumer was the process::exit
// self-crash deleted with the KI#207 raw-fields build (fac3bb33); a const nobody reads is a ghost
// (RULE 3). See `git show fac3bb33` (the removed `if !matches { … process::exit(1) }` block).
/// §23.14.1 peer-audit TIME-BOND (ticks). The volume trigger (AUDIT_TRIGGER_RATE)
/// never fires for a low-traffic validator; this bonds the peer audit to the
/// ATTESTED tick so one fires at least this often regardless of volume. Compile-time
/// dev pair (500 in a dev-mode build). Judged against the Nabla-attested oods tick,
/// NEVER tx.epoch or wall clock. See `AvmInterpreter::enforce_audit_post`.
pub const AUDIT_MAX_TICK_GAP: u64 = crate::validation::protocol_gen::AUDIT_MAX_TICK_GAP;

/// An audit demand generated by Core during CL2/CL3 execution.
///
/// Core deterministically selects a target validator from the current
/// transaction's witness set and demands that Lambda (the operator)
/// initiate an audit of that validator.
///
/// If Lambda does not provide an `AuditConfirmation` within
/// `AUDIT_COUNTDOWN_TXS` subsequent Core invocations, the AVM
/// interpreter refuses to execute — effectively terminating Core.
/// Restart incurs VBC re-verification, ZK benchmark, and operational
/// downtime: a real cost that makes non-compliance irrational.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditDemand {
    /// The challenge nonce (derived deterministically from txid).
    /// Lambda must echo this in the confirmation to prove it responded
    /// to this specific demand.
    pub challenge_nonce: [u8; 32],

    /// Public key of the validator to audit (selected from prev_receipts
    /// witness set of the current transaction).
    pub target_validator_pk: Vec<u8>,

    /// The txid that triggered this audit (for traceability).
    pub trigger_txid: [u8; 32],
}

/// Confirmation that Lambda performed the demanded audit.
///
/// §23.14 Audit confirmation — Lambda's response to an AuditDemand.
///
/// **Self-audit** (target == our PK): Lambda looks up trigger_txid in its DB
/// and sends back the raw stored fields. Core hashes them and compares against
/// the TxDigest in the audit buffer. Lambda does zero crypto.
///
/// **Peer-audit** (target != our PK): Lambda sends PeerAuditRequest via ANTIE
/// email. Remote Lambda looks up txid in DB, remote Core verifies. Response
/// hash is compared locally by Core. See PeerAuditRequest/PeerAuditResponse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfirmation {
    /// Must match the `challenge_nonce` from the `AuditDemand`.
    pub challenge_nonce: [u8; 32],

    /// Target validator's public key (must match demand).
    pub target_validator_pk: Vec<u8>,

    /// Raw DB data — Lambda sends these as-is, Core hashes and verifies.
    /// Lambda does ZERO crypto. Core is the sole cryptographic authority.
    /// tx_number is NOT included — Lambda doesn't know it (AVM-internal).
    /// AVM uses PendingAudit.trigger_tx_number to find the right entry.
    pub sender_balance: u64,
    pub receiver_balance: u64,
    pub state_id: [u8; 32],
    pub amount: u64,
}

// === §23.14.6: Peer Audit Protocol ===
// (The `AXIOM_PEER_AUDIT_V1` content-hash tag lives in `audit.rs`, its one
// builder; a second, unread `pub const` copy here was deleted 2026-10-02 —
// KI#55 B2#7.)

/// Peer audit request — sent to remote validator (B) via ANTIE email.
///
/// KI#207 (raw-fields, ruled 2026-09-21): the request carries NO expected hash.
/// Handing B the answer let a malicious B echo it back and always pass — the
/// audit was a ghost against an adversary (RULE 3 shape 6). B is now asked only
/// "report what you stored for `txid`"; the requester (A) is the sole judge.
///
/// KI#175 (auth, ruled 2026-09-21): the request is SIGNED by A's operational
/// wallet (`requester_sig` over `peer_audit_request_signing_payload`, verified
/// against `requester_pk`). B drops an unsigned/forged request instead of
/// answering it (anti-grief). Core holds no keys — Lambda signs, Core verifies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAuditRequest {
    /// The txid to audit — remote Lambda looks this up in its DB.
    pub txid: [u8; 32],

    /// Challenge nonce from the original AuditDemand (binding).
    pub challenge_nonce: [u8; 32],

    /// Requesting validator's public key (== A's operational signing pk, the
    /// same key its witness sigs carry). B verifies `requester_sig` against it.
    pub requester_pk: Vec<u8>,

    /// Ed25519 signature by A's operational wallet over
    /// `peer_audit_request_signing_payload(txid, challenge_nonce, requester_pk)`.
    /// KI#175: B refuses to answer a request whose signature does not verify.
    pub requester_sig: Vec<u8>,
}

/// Peer audit response — sent back from remote validator (B) via ANTIE email.
///
/// KI#207 (raw-fields): B reports the RAW DB fields it stored for `txid`; it
/// does NOT compute or send a hash. A's Core hashes them
/// (`compute_peer_audit_hash`) and compares against A's own expected value
/// (`PendingAudit.peer_expected_hash`, computed from A's audit buffer). B cannot
/// echo an answer it was never given; honest fields match, tampered fields
/// mismatch → ban. Mirrors the self-audit shape (Lambda sends raw data, Core
/// judges — RULE 1). Core is the sole cryptographic authority; Lambda does zero
/// crypto beyond the operational-wallet signature below.
///
/// KI#175 (auth): SIGNED by B's operational wallet (`responder_sig`). A verifies
/// the signature AND that `responder_pk == demand.target_validator_pk` (the peer
/// A actually demanded) BEFORE any ban — so a forged wrong-fields response
/// injected as B cannot get B banned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAuditResponse {
    /// The txid that was audited.
    pub txid: [u8; 32],

    /// Challenge nonce echo (binding to original demand).
    pub challenge_nonce: [u8; 32],

    /// Raw DB fields B stored for `txid` — B sends these as-is, A's Core hashes
    /// and judges. Lambda does ZERO crypto on these (Core is sole authority).
    pub sender_balance: u64,
    pub receiver_balance: u64,
    pub state_id: [u8; 32],
    pub amount: u64,

    /// Responding validator's public key (== B's operational signing pk).
    pub responder_pk: Vec<u8>,

    /// Ed25519 signature by B's operational wallet over
    /// `peer_audit_response_signing_payload(...)`. KI#175: A verifies this and
    /// `responder_pk == target_validator_pk` before banning.
    pub responder_sig: Vec<u8>,
}

/// Reason a validator was banned in peer-audit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PeerAuditBanReason {
    /// Peer responded with wrong hash — DB tampering detected.
    HashMismatch,
    /// Peer did not respond within 100 TXs / 10 minutes.
    NonResponds,
    /// §23.14.6 (KI#213): peer answered `NotHeld` for a tx it PROVABLY
    /// co-witnessed — its own signature sits on A's stored receipt for that
    /// txid. A co-witness executed the tx and persists its digest at CL2
    /// (`witness_digests`), so "not held" from it is lost or hidden data:
    /// attributable, like a wrong hash. A `NotHeld` from a validator A cannot
    /// prove co-witnessed is NOT a ban (it clears the audit).
    NotHeldByCoWitness,
}

/// §23.14.6 (KI#213, ruled 2026-09-24): B's SIGNED "I hold no record for this
/// txid". Until this existed B's only answer was a generic failure A's audit
/// handler never saw, so a delivered-and-answered request read as SILENCE and
/// B was banned NonResponds. Signed by B's operational wallet over
/// `audit::peer_audit_not_held_signing_payload` (its own domain).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAuditNotHeld {
    pub txid: [u8; 32],
    pub challenge_nonce: [u8; 32],
    pub responder_pk: Vec<u8>,
    pub responder_sig: Vec<u8>,
}

/// A banned validator entry — tracked in AVM (survives across TXs, clears on restart).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAuditBanEntry {
    /// Banned validator's public key.
    pub validator_pk: Vec<u8>,

    /// When the ban was imposed — the validated TARDIS tick stamp (the TX
    /// `epoch`, a unix-second-valued stamp per TICK_INTERVAL_SECS docs),
    /// NEVER SystemTime::now().
    pub banned_at_tick: u64,

    /// Why the ban was imposed.
    pub reason: PeerAuditBanReason,
}

// === §6.9 / §11.5: Ark Mode ⟠ — Offline Operation ===

/// Ark artifact — a locally generated, signed intent record for offline trading.
///
/// Created when sender transfers ⟠ value offline. Both sender and receiver
/// run Core/AVM locally with DMAP. No validators, no k=3.
///
/// The artifact is NOT a transaction — it becomes one at reconciliation.
/// Contains the transaction, sender's DMAP attestation hash, and Confidence Index.
///
/// Per White Paper §6.9: "Ark-Mode does not create valid transactions.
/// It preserves transaction intent under disconnection."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArkArtifact {
    /// The intended transaction (same Transaction struct as online TXs)
    pub transaction: Transaction,

    /// Reference to sender's last known valid wallet state_id
    pub last_state_id: [u8; 32],

    /// Locally monotonic nonce — prevents replay within offline chain.
    /// Each artifact from the same wallet increments this.
    pub ark_nonce: u64,

    /// BLAKE3 hash of sender's DMAP attestation for this execution.
    /// Proves Core/AVM ran locally and accepted the transaction.
    /// Receiver can verify by re-executing through their own AVM.
    pub dmap_attestation_hash: [u8; 32],

    /// Hash of previous artifact in this wallet's offline chain.
    /// None for the first offline TX after loading.
    /// Chains offline TXs within a single wallet (ordering guarantee).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_artifact_hash: Option<[u8; 32]>,

    /// Sender's Confidence Index — issued by validators during last online session.
    /// Cryptographically signed, sender cannot forge.
    /// Receiver inspects CI to decide whether to accept (GREEN/YELLOW/RED).
    pub confidence_index: ConfidenceIndex,

    /// Timestamp of artifact creation (sender's local clock — untrusted).
    pub created_at_secs: u64,
}

/// Confidence Index (CI) — offline risk assessment for Ark ⟠ trades (YPX-010).
///
/// Computed by the RECEIVER from the sender's FACT chain. Not pre-issued.
/// The receiver reads the FACT chain, extracts the five trust factors, and
/// Core evaluates them against the CI matrix to produce GREEN/YELLOW/RED.
///
/// All five factors are computable offline from the FACT chain alone.
/// No network queries. No external oracles.
///
/// Status mapping (YPX-010 §4):
///   GREEN  — Low risk, normal offline acceptance
///   YELLOW — Moderate risk, reduced limits or extra caution
///   RED    — High risk, offline payment discouraged or refused
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ConfidenceIndex {
    /// Wallet public key this CI belongs to
    pub wallet_pk: Vec<u8>,

    // === Factor 1: K=3 Staleness (YPX-010 §2 Factor 1) ===

    /// Unix timestamp of last successful k=3 validation (from FACT chain)
    pub last_k3_at: u64,

    // === Factor 2: Ark TX Count Since Last K=3 (YPX-010 §2 Factor 2) ===

    /// Number of Ark (k=0) transactions since last k=3 (from FACT chain)
    pub ark_tx_count_since_k3: u64,

    // === Factor 3: Stakes Ratio (YPX-010 §2 Factor 3) ===

    /// Wallet balance at last k=3 transaction (from FACT chain)
    pub k3_balance: u64,

    // === Factor 4: TX vs History Pattern (YPX-010 §2 Factor 4) ===

    /// Mean transaction amount from prior Ark links (from FACT chain)
    pub ark_tx_mean_amount: u64,

    // === Factor 5: Validator Ecosystem Depth (YPX-010 §2 Factor 5) ===

    /// Number of distinct validators that have processed prior Ark settlements
    pub ark_validator_count: u8,

    // === Override checks ===

    /// Whether a FACT scar is present in the chain
    pub has_fact_scar: bool,

    /// Whether the wallet has ever had a k=3 transaction
    pub has_any_k3: bool,

    /// Number of detected double-spend conflicts (lifetime)
    pub conflict_count: u64,

    // === Validator attestation (optional, for online-issued CI) ===

    /// Validator-signed attestation over CI fields (optional).
    /// Present when CI was issued online by a validator.
    /// Absent when CI is computed locally by receiver from FACT chain.
    #[serde(default)]
    pub validator_signature: Vec<u8>,

    /// Public key of the validator who signed this CI (if any)
    #[serde(default)]
    pub issuer_validator_pk: Vec<u8>,
}

/// Domain tag for Confidence Index signing
pub const CI_DOMAIN: &[u8] = b"AXIOM_CI_V1";

/// Domain tag for Ark artifact hashing
pub const ARK_ARTIFACT_DOMAIN: &[u8] = b"AXIOM_ARK_ARTIFACT_V1";

// === YPX-009: Silicon Pulse — Core-Initiated Lambda Audit ===

/// Silicon Pulse constants (YPX-009 §4/§8)
///
/// Dual-trigger audit design:
///   TIME:  every 5 minutes, audit fires regardless of TX count.
///          Catches low-traffic validators (even 1 TX/hour gets audited).
///   COUNT: buffer reaches 80% of PULSE_BUFFER_MAX (prevents overflow).
///          High-traffic validators don't accumulate unbounded entries.
///
/// Sample sizing: 10% of buffer contents, randomly selected (Fiat-Shamir).
///   Lambda can't predict which 10% — must keep ALL entries honest.
///   Detection probability per audit (if Lambda tampers with 5% of TXs):
///     5 entries sampled: 23%    | 50 entries: 92%    | 160 entries: 99.98%
///   Multiple audits compound: after 3 audits with 50 samples, detection > 99.9%.
///
/// Argon2id uses 32MB (32768 KiB) per call — exceeds L3 cache on commodity
/// hardware (8-36MB) where attacks are likely. Primary purpose: tamper-evident
/// chain ensuring Lambda records data honestly. Secondary: detect multi-validator
/// co-location. High-end server CPUs (64-384MB L3) are not the threat model —
/// operators with such hardware are traceable and have skin in the game.
/// Time trigger: audit fires every 5 minutes regardless of TX count.
pub const PULSE_AUDIT_INTERVAL_SECS: u64 = crate::validation::protocol_gen::PULSE_AUDIT_INTERVAL_SECS;

/// Hard cap on buffer entries. Prevents unbounded memory growth.
/// At 32MB Argon2id (~30ms/call release), 2000 entries = ~60 seconds
/// of accumulated work. Buffer memory: 2000 × ~105 bytes ≈ 210 KB.
pub const PULSE_BUFFER_MAX: u32 = 2000;

/// Count trigger ratio: audit fires when buffer reaches this fraction of max.
/// 80% = 1600 entries, leaving 20% headroom before hard cap.
pub const PULSE_BUFFER_TRIGGER_RATIO: f64 = 0.80;

/// Sample ratio: fraction of buffer entries to audit per cycle.
/// 10% keeps replay under 9 seconds at max buffer (160 entries × 55ms).
/// Random Fiat-Shamir selection ensures Lambda can't predict which entries.
pub const PULSE_SAMPLE_RATIO: f64 = 0.10;

pub const PULSE_AUDIT_BASELINE_MS: f64 = 50.0;           // reference DMAP time (Pi-class)
pub const PULSE_AUDIT_DEADLINE_TICKS: u64 = crate::validation::protocol_gen::PULSE_AUDIT_DEADLINE_TICKS;          // ~300s to respond to audit (protocol_core.toml)
pub const PULSE_EPOCH_LENGTH_TICKS: u64 = 720;           // 1 hour — pulse evaluation window
pub const PULSE_MISS_TOLERANCE: u32 = 3;                 // miss 3 → degraded
pub const PULSE_MISS_EVICTION: u32 = 10;                 // miss 10 → evicted
pub const PULSE_GRACE_CYCLES: u32 = 6;                   // new nodes get 6 epochs grace
pub const NONCE_MISMATCH_TOLERANCE: u32 = 3;             // 3 consecutive mismatches → audit_failed

/// Calibration benchmark duration in milliseconds.
/// Longer = more accurate, but delays startup. 200ms is a good balance.
pub const PULSE_CALIBRATION_MS: u64 = 200;

/// Transaction digest stored in AVM audit buffer (YPX-009 §3.4).
/// Captures financial/state integrity fields only — the data Lambda stores
/// in its DB and could tamper with. DMAP has its own independent verification
/// path (re-execution, Merkle proofs). Mixing would couple two security layers
/// and break ZKP-mode validators that don't use DMAP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxDigest {
    /// Transaction sequence number (monotonic per AVM instance)
    pub tx_number: u64,
    /// Sender balance at time of TX
    pub sender_balance: u64,
    /// Receiver balance at time of TX (0 if unknown)
    pub receiver_balance: u64,
    /// Produced state_id from Core (SHA3-256)
    pub state_id: [u8; 32],
    /// Transaction amount
    pub amount: u64,
}

impl TxDigest {
    /// Serialize to canonical bytes for hashing (Argon2id input, audit verification).
    /// Domain-tagged: "AXIOM_TX_DIGEST" prefix ensures no collision with other hashes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(b"AXIOM_TX_DIGEST");
        buf.extend_from_slice(&self.tx_number.to_le_bytes());
        buf.extend_from_slice(&self.sender_balance.to_le_bytes());
        buf.extend_from_slice(&self.receiver_balance.to_le_bytes());
        buf.extend_from_slice(&self.state_id);
        buf.extend_from_slice(&self.amount.to_le_bytes());
        buf
    }

    /// Build TxDigest from AuditConfirmation raw fields + stored tx_number.
    /// Used by Core to reconstruct the digest for verification.
    /// tx_number comes from PendingAudit (AVM-internal), not from Lambda.
    pub fn from_confirmation(conf: &AuditConfirmation, tx_number: u64) -> Self {
        TxDigest {
            tx_number,
            sender_balance: conf.sender_balance,
            receiver_balance: conf.receiver_balance,
            state_id: conf.state_id,
            amount: conf.amount,
        }
    }
}

/// Audit request emitted by AVM when buffer is full (YPX-009 §4.3).
/// Attached to PublicOutputs. Lambda must re-execute selected TXs
/// and return an AuditResponse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PulseAuditRequest {
    /// Selected entry indices into the buffer (ordered)
    pub selected_indices: Vec<u32>,
    /// The tx_number for each selected entry (AVM-internal sequence)
    pub tx_numbers: Vec<u64>,
    /// produced_state_id for each selected entry (Lambda DB lookup key)
    pub state_ids: Vec<[u8; 32]>,
    /// Core's chain hash over the selected subset (the expected answer)
    pub expected_hash: [u8; 32],
    /// Epoch number (for freshness)
    pub epoch: u64,
}

/// Audit response from Lambda (YPX-009 §4.4).
/// Lambda sends back raw DB fields — zero crypto. Core replays
/// Argon2id→BLAKE3 chain and compares against expected_hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PulseAuditResponse {
    /// Raw TX data from Lambda's DB (one per requested TX, in order).
    /// Core replays Argon2id→BLAKE3 chain over these to verify.
    pub entries: Vec<TxDigest>,
    /// Epoch (must match request)
    pub epoch: u64,
}

/// Nonce challenge emitted by AVM every TX (YPX-009 §3.6).
/// AVM picks a random wallet from its cache and asks Lambda to prove
/// it still holds the correct state for that wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceChallenge {
    /// Which wallet to look up
    pub target_wallet_pk: [u8; 32],
    /// Expected state_id (from AVM's wallet cache)
    pub expected_state_id: [u8; 32],
}

/// Nonce response from Lambda (YPX-009 §3.6).
/// Lambda looks up the wallet in its DB and returns current state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceResponse {
    /// The wallet that was looked up
    pub target_wallet_pk: [u8; 32],
    /// Current state_id in Lambda's DB
    pub current_state_id: [u8; 32],
    /// Current balance in Lambda's DB
    pub current_balance: u64,
}

/// Pulse proof data emitted by AVM after successful audit (YPX-009 §5.1).
/// Lambda forwards this to Nabla for gossip broadcast.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PulseProofData {
    /// Global epoch number at time of audit
    pub epoch: u64,
    /// Core's accumulator over the audited buffer
    pub full_accumulator: [u8; 32],
    /// Total entries in audit buffer at trigger time.
    pub entry_count: u32,
    /// Number of entries selected for re-execution (PULSE_SAMPLE_RATIO × entry_count)
    pub sample_size: u32,
    /// Hash of the audit response (proves Lambda responded correctly)
    pub audit_hash: [u8; 32],
    /// Measured Argon2id(64MB,t=1) throughput (iterations/sec).
    /// Reported for peer validation — peers can compare expected vs actual.
    #[serde(default)]
    pub argon2id_per_sec: u64,
}

// === YPX-007: ZKP Qualification ===
// `QualificationState`, `ZKP_QUAL_THRESHOLD_SECS`, `ZKP_QUAL_TTL_SECS` DELETED
// 2026-10-03 (KI#125 ruling — never wired; a TTL is a time-gate). The ruled
// design is `ZkpQualificationRecord` + mode `ZkpQualify` (YPX-007 §9).

/// Validation errors
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationError {
    // State errors
    StateIdAlreadyConsumed,
    InvalidStateId,

    /// §15: client-supplied `current_state.balance` / `wallet_seq` does NOT
    /// re-derive to `prev_receipts.last().state_hash`. Either the SDK shipped
    /// state from a different chain timeline (stale wallet against fresh env,
    /// pre-rebuild Mac client, etc) or Lambda fell back to a default-zero
    /// state. Recovery: `RecoveryHint::ClaraHealNextSend` — the wallet must
    /// heal-forward to re-anchor cryptographically. See CLAUDE.md §15 +
    /// `docs/AXIOM_HANDOFF_MacClientStaleState.md`.
    StateNotAnchored,


    // Wallet sequence errors
    InvalidWalletSeq,
    WalletSeqOverflow,
    
    // Wallet ID errors
    InvalidWalletId,
    MalformedAddress,
    
    // Signature errors
    InvalidClientSignature,
    InvalidWitnessSignature,
    UnsupportedSignatureAlgorithm,
    
    // Balance errors
    InsufficientBalance,
    ConservationViolation,
    ZeroAmount,  // C2 fix: Explicit rejection of amount=0
    DustAmount,  // G2 fix: Rejection of amount below MINIMUM_TX_ATOMS (anti-spam)
    
    // VBC errors
    InvalidVBC,
    /// VBC `expires_at` is in the past. Carries the expiry tick and
    /// the validator's current tick view so clients can populate
    /// `VbcLifecycleDetail` (§4 Errors YP). Phase 2b.14 upgrade from
    /// a unit variant — breaking ValidationError enum shape change,
    /// requires ELF rebuild.
    VBCExpired { expires_at: u64, current_tick: u64 },
    /// VBC `issued_at` is in the future. Same shape as VBCExpired.
    VBCNotYetValid { issued_at: u64, current_tick: u64 },
    /// KI#130 — a witness VBC is within `VBC_UNUSABLE_REMAINING_TICKS` of its hard
    /// expiry, judged on the ATTESTED tick: it "loses usefulness" before it expires,
    /// forcing renewal before a lapse. `current_tick` is the attested now. Same
    /// shape as VBCExpired.
    VBCUnusableSoon { expires_at: u64, current_tick: u64 },
    /// KI#130 Gap B — the round's attested OODS tick (`attested_tick`) is staler than
    /// the wallet's last round's OODS tick (`prev_tick`) by more than the
    /// carrier-latency buffer: a replay of an old reading. Fetch a fresh reading.
    VBCStaleAttestation { attested_tick: u64, prev_tick: u64 },
    /// KI#130 — a CL8 VBC-issuance/renewal request asks for a lifetime
    /// (`expires_at - issued_at`) longer than the max non-genesis validity
    /// (`VBC_VALIDITY_TICKS`). Applies to ALL CL8 issuance including a genesis-lineage
    /// renewal — the initial 10-year genesis cert is ceremony-signed, never via CL8.
    VBCLifetimeTooLong { expires_at: u64, issued_at: u64 },
    /// Q2-b (the owner ruled 2026-09-21) — a VBC RENEWAL (a supporting cert shares
    /// the target's SPHINCS+ subject) carried NO `renewal_work_receipt`. Renewal
    /// requires >=1 k-signed receipt the renewing validator co-signed this term
    /// (proof of real witnessing work). A validator that witnessed nothing this
    /// term is correctly refused — witness something, then renew.
    VbcRenewalNoProofOfWork,
    /// Q2-b — the presented `renewal_work_receipt` is not co-signed by the
    /// renewing validator: no witness carries its `subject_pubkey_ed25519` with a
    /// VALID `receipt_commitment_sig`. Being merely LISTED proves nothing.
    VbcRenewalNotCoSigned,
    /// Q2-b — the presented `renewal_work_receipt` does not post-date the current
    /// cert: it has no OODS reading (`oods_flag = None`: heal / genesis / offline
    /// redeem — no tick to judge) or its `oods_flag.tick <= prev.baseline_tick`.
    /// The proof must be an ONLINE witnessed receipt from THIS term.
    VbcRenewalWorkReceiptStale,
    /// Q2-b — the presented `renewal_work_receipt` does not carry a real quorum:
    /// fewer than the absolute floor of 3 distinct validators produced a valid
    /// `receipt_commitment_sig` over it (a fabricated / sub-quorum receipt).
    VbcRenewalWorkReceiptSubQuorum,
    VBCChainTooDeep,
    VBCMissingIssuer,
    /// CRITICAL: VBC issuer claims to be root-level (chain_depth=0) but issuer PKs
    /// do not match any compiled ROOT_AUTHORITY_PKS. This means either:
    /// 1. Core was compiled with stale genesis.rs (re-run ceremony, paste constants, rebuild)
    /// 2. A mirror universe attack — VBC signed by keys outside this universe's trust root
    ///    Either way, this validator MUST NOT process any transactions until resolved.
    VBCRootKeyMismatch,
    /// A reserved genesis validator NAME (alpha..kappa) was carried by a VBC
    /// whose `validator_id` is NOT the pinned `GENESIS_VALIDATORS` entry for that
    /// name. Genesis names are hardcoded-reserved to their genesis keys
    /// (`genesis::genesis_index_for_name`), so a genesis name cannot be attached
    /// to any other key — even by a root-authority mis-issuance.
    GenesisNameReserved,
    DuplicateValidator,
    InvalidVBCCount,
    
    // Genesis errors
    MissingPrevReceipts,
    InvalidGenesisTransaction,
    
    // Proof errors
    InvalidExecutionProof,
    ProgramDigestMismatch,
    
    // JSON errors
    InvalidCanonicalJson,
    
    // Cheque errors
    InsufficientCheques,
    InconsistentChequeBundle,
    InvalidChequeSignature,
    ChequeAlreadyRedeemed,
    /// A2: redeem requires a non-empty sender_fact_chain on the cheque
    /// bundle (or its first ValidatorCheque). The chain's tip becomes
    /// the redeem link's sender_anchor. Without it, the receiver's
    /// chain cannot be anchored to the sender's verified provenance.
    /// KI#146 (2026-09-11): also raised when chains ARE presented but none
    /// is THIS send's (tip tx_id == cheque.txid, tip new_state_id ==
    /// cheque.produced_state_id) — `redeem_fact_chain_ref` chooses nothing.
    RedeemSenderAnchorMissing,

    /// YP §17.10.5.3 — Core CL5 rejects a redeem whose sender FACT
    /// chain tip carries a `NablaConfirmation` with
    /// `committed_at_tick >= inputs.current_tick`.  The redeem must
    /// happen at least 1 TARDIS tick after the sender's commit, so
    /// gossip has had time to propagate that commit through the
    /// Nabla mesh before any receiver redeems against it.
    /// Scarred links (no NablaConfirmation) are exempt — Ark-mode
    /// operation continues unchanged.
    RedeemBeforeCommitPropagated,

    // YPX-014 Txid attestation errors (CL5)
    TxidAttestationMissing,    // No attestation provided
    TxidAttestationInvalidSig, // Ed25519 signature verification failed
    TxidAttestationRedeemed,   // Status is REDEEMED (global double-redeem)
    TxidAttestationBadStatus,  // Status is not "NOT_REDEEMED" or "REDEEMED"
    TxidAttestationUntrusted,  // Attester PK not in trusted set (not a known Nabla node)

    // Cheque-claim-proof errors (CL5, synchronous double-redeem prevention)
    /// No `cheque_claim_proof` provided in PublicInputs.  This is the
    /// proof the Nabla writer signs on successful `register_cheque_claim`;
    /// missing it means the receiver bypassed the §4.6 verify path —
    /// reject hard, no soft fallback (CLAUDE.md §13).
    ChequeClaimProofMissing,
    /// Ed25519 signature on the claim proof failed verification.
    ChequeClaimProofInvalidSig,
    /// YPX-022 §2.1.2a (KI#205): the proof's `claim_sig` is not a valid
    /// Ed25519 signature by `client_pk` over
    /// `compute::cheque_claim_signing_payload(cheque_id, client_pk, k_tier,
    /// wallet_address)` — the claim was not made by the key the cheque is
    /// addressed to. The Core half of the authenticated claim (RULE 5).
    ChequeClaimProofUnauthenticated,
    /// Proof's `cheque_id` doesn't match the redeem's bundle txid — proof
    /// was for a different cheque (stolen / forwarded).
    ChequeClaimProofTxidMismatch,
    /// Proof's `client_pk` doesn't match the redeem's `receiver_pk` —
    /// proof was issued to a different wallet (replay across receivers).
    ChequeClaimProofReceiverMismatch,
    /// Proof's `nabla_node_pk` is not bound by a valid NBC chained back
    /// to a Nabla root authority.  Catches self-signed forgeries.
    ChequeClaimProofUntrusted,
    /// Defense-in-depth: the redeem's txid already appears in the
    /// receiver's FACT chain.  Closes the post-finalization replay
    /// window even when Nabla state is unavailable.
    TxidAlreadyInReceiverChain,
    /// Cheque-claim proof's tick is outside the CL5 freshness window
    /// (`cheque_claim_proof_max_age_ticks`, ~24h). The receiver re-claims.
    /// This bounds the PROOF only — since KI#205 (YPX-022 §2.1.2a item 2)
    /// Nabla holds the authenticated claim itself until
    /// `recall_init_window_high`; the proof's freshness is deliberately
    /// shorter than the recall opening and is never what blocks a recall.
    ChequeClaimProofExpired,

    // Redeem errors (CL5)
    RedeemBalanceMismatch,     // old_balance + amount != new_balance
    RedeemBalanceOverflow,     // Addition would overflow u64
    MissingExecutionProof,     // Witness has empty execution_proof (§37)
    MissingRedeemInputs,       // Required CL5 fields not provided
    MissingVBC,                // VBC bundle required (production mode)

    // Fee ledger errors (YP §19.6 amendment — receiver-pays-only fee model)
    /// A single validator's fee_breakdown slot exceeds MAX_VALIDATOR_FEE_BPS
    /// (30 bps = 0.30%) of the transaction amount.
    FeeExceedsValidatorCap,
    /// The sum of fee_breakdown slots exceeds MAX_TOTAL_TX_FEE_BPS
    /// (90 bps = 0.90%) of the transaction amount.
    FeeExceedsAggregateCap,
    /// The sum of fee_breakdown slots is greater than the transaction amount
    /// (no fees can exceed the value being moved). Defense-in-depth — the
    /// aggregate cap already enforces this for non-zero amounts; this guards
    /// the amount=0 / dust edge cases.
    FeeExceedsAmount,
    /// A WitnessSig's `slot_amount` doesn't equal
    /// `min(rate_bps, MAX_VALIDATOR_FEE_BPS) × amount / FEE_BPS_DIVISOR`.
    /// Either the validator signed an inconsistent (rate, slot) pair or a
    /// downstream actor tampered with one of the two fields. Every Core that
    /// touches the receipt re-derives the slot and rejects on mismatch.
    /// Closes the "SDK can lie about a validator's fee" gap.
    FeeSlotMathInvalid,
    // KI#156 item 3 (DELETED 2026-09-21): FeeSlotReceiptMismatch + FeeSlotCountMismatch
    // removed with `verify_receipt_fee_breakdown` (their only producer, 0 callers).

    // Carrier errors (Section 26.9.3)
    CarriersTooLarge,     // Total carriers exceed 512 bytes
    
    // Validator hint errors (Section 27.5)
    InvalidHintCount,     // Validators MUST include 0-3 hints (max 3)
    SelfHintNotAllowed,   // Validator MUST NOT include own contact in hints
    
    // S-ABR overlap errors (CL3)
    SABRInsufficientOverlap,   // Fresh validator: not enough overlapped sigs
    SABROverlapNotInPrev,      // Overlapped sig PK not found in prev_receipts
    SABRMissingValidatorPK,    // CL3 called without my_validator_pk
    SABRHashMismatch,          // CL3: Lambda's reported state doesn't match client's consumed_state_id
    
    // YPX-007: Security level errors (`ZkpNotQualified` DELETED 2026-10-03,
    // KI#125 — never raised; there is no qualification gate. IPC 930 retired.)
    ArkNotImplemented,      // k=0 Ark mode not yet implemented

    // YPX-012: Oracle claim errors
    OracleSenderMismatch,          // sender != receiver (oracle is self-payout only)
    OracleInsufficientK,           // k < 5 (oracle requires k=5)
    OracleVBCTooOld,               // Witness VBC older than ORACLE_VBC_RENEWAL_TICKS (24h). Renew via CL8.
    OracleInsufficientStake,       // Validator balance < ORACLE_MIN_STAKE (1M AXC)
    OracleStakeScarred,            // Stake wallet has unresolved FACT scars — disqualifies oracle witnessing.
    OraclePlatformInvalid,         // platform URL not in whitelist
    OracleLivingSignatureMissing,  // username missing AXM_<hex> signature
    OracleZeroDelta,               // credit_delta == 0 (no new work)
    OracleNonZeroAmount,           // oracle TX must have amount == 0
    OracleMaturityNotReached,      // cheque age < 48h at redeem

    // Reference field
    ReferenceTooLarge,             // reference > 256 bytes (DoS prevention)


    // Other
    InvalidMode,
    InternalError,
    
    // `AuthHashRequired` (950) / `InvalidAuthProof` (951) DELETED 2026-09-25
    // with `Transaction.owner_proof` (KI#108). The IPC codes stay retired.

    // Lineage binding errors (YP §23.11)
    ReceiptFromWrongWorldline,  // SDID mismatch — receipt from different fork
    ReceiptLineageMismatch,     // Lineage hash not from our upgrade path
    ReceiptCommitmentMismatch,  // Receipt fields don't match k-validator signed commitment
    
    // Group wallet errors
    GroupTooManyMembers,        // members.len() > MAX_GROUP_MEMBERS (32)
    GroupShareBpsInvalid,       // sum(share_bps) != 10000
    GroupNotMember,             // withdrawal destination is not a member's wallet_id
    GroupInsufficientAvailable, // withdrawal amount > member's available balance
    GroupChecksumFailed,        // sum(available) != balance
    GroupMembersImmutable,      // attempted to change members list
    GroupDistributionOverflow,  // distribution math would overflow
    GroupMemberMismatch,        // client_pk does not match members[index].member_pk
    
    // FACT chain errors (YPX-001)
    FactChainTooDeep,           // chain.links exceeds limit (Core's MAX_TOTAL_LINKS or operator's max_fact_links); self-send heal + BURN_ADDRESS+target burn exempt from the operator gate (KI#241 F-9.4)
    FactChainBreak,             // state_id discontinuity between links
    FactInsufficientWitnesses,  // link has <3 witnesses
    FactInvalidSignature,       // witness signature doesn't verify
    FactDuplicateWitness,       // same validator_id appears twice in a link
    FactInvalidCheckpoint,      // checkpoint integrity failure
    FactChainEmpty,             // SEC-11: checkpoint provenance anchor read from an empty link set
    FactAmountOverflow,         // SEC-11: checkpoint total_amount/compressed_count addition overflowed u64
    // YP §26.17.6.5 FACT Provenance Binding (2026-09-11, KI#145)
    FactWitnessUncertified,     // B2: a witness's vbc_hash names no presented+verified certificate, or its keys differ
    FactOriginInvalid,          // B1: the chain does not start at the wallet's derived opening state
    FactCertificateInvalid,     // B2: a presented certificate bundle fails verification to the roots
    FactBurnSigInvalid,         // B2′: a burn-proof signature is not one of the burn link's verified witnesses
    StakeClaimTierInvalid,      // KI#152 (b): a subsidised stake claim must land at the claimant's Standard-tier (k=3) address

    // Burn errors (YPX-001 §1.5.4)
    BurnNoFactChain,            // burn TX but sender has no FACT chain
    BurnMissingTarget,          // burn_target_tx_id set but receiver != BURN_ADDRESS (self-send heal-burn exempt)
    BurnTargetNotFound,         // target tx_id not found in sender's FACT chain
    BurnTargetNotScarred,       // target link already has nabla_confirmation (not scarred)
    BurnTargetAlreadyBurned,    // target link already has burn_proof
    BurnAmountMismatch,         // burn TX amount != scarred link amount

    // BurnProof structural errors (verify_fact_link / verify_fact_chain).
    // Closes pre-2026-05-07 forge: BurnProof { burn_tx_id: any, validator_sigs: vec![] }
    // made link.is_resolved() return true with zero verifier checks.
    BurnProofInsufficientWitnesses, // burn_proof.validator_sigs.len() < MIN_FACT_WITNESSES
    BurnProofDuplicateValidator,    // same validator_id twice in burn_proof.validator_sigs
    BurnTxIdNotInChain,             // burn_proof.burn_tx_id doesn't match any link's tx_id
    BurnTargetMismatch,             // named burn link's witnessed burn_target_tx_id != this scar (COPY forge, 2026-07-17)

    // Heal errors
    HealNotNeeded,              // is_heal=true but FACT chain last link has k witnesses (fully committed)

    // Scar cap
    TooManyUnresolvedScars,     // wallet has > MAX_UNRESOLVED_SCARS unhealed/unburned FACT links

    // Wallet state errors
    MissingWalletState,         // No wallet state — Lambda must provide it (no silent fallbacks)

    // Version errors
    VersionMismatch,            // Transaction core_version doesn't match this binary
    CoreIdMismatch,             // Transaction core_id (BLAKE3 of ELF) doesn't match validator's local Core ELF — non-poisoning, non-byzantine; wallet should not blacklist on this

    // MissingDilithiumKey (1050) / MissingDilithiumPk (1402) REMOVED 2026-09-15 with
    // CL9 (YPX-001 §1.5.3 push path). Codes reserved; do not reuse.
    MissingField,               // Required input field not provided

    // Wallet secret errors
    WalletSecretMismatch,       // wallet_secret + pk don't match wallet_id checksum

    // Fan-Out errors (CL10, §18.8)
    FanOutMissingMessage,
    FanOutTtlExceeded,
    FanOutInvalidFanout,
    FanOutContentEmpty,
    FanOutContentTooLarge,
    FanOutTtlExpired,
    FanOutTtlInflated,
    FanOutUnknownContentType,
    FanOutTimestampFuture,
    FanOutTimestampExpired,
    FanOutDiffusionIdMismatch,
    FanOutInvalidOriginator,
    FanOutOriginatorPkMismatch,
    FanOutInvalidSignature,
    /// Candidate's stake is below the required tier minimum (CL8)
    InsufficientStake,
    /// Wallet is frozen by an approved JFP order (§7). All transactions rejected.
    WalletFrozen,
    /// sender_wallet_id does not match the wallet's stored identity (identity binding).
    /// Prevents lockup bypass and Ark policy spoofing.
    SenderWalletIdMismatch,
    /// Ark wallet (k=0) cannot send to non-Ark wallet (§11.9.2). Ark-to-Ark only.
    ArkToNonArkRejected,
    /// Only the wallet owner can charge their own Ark wallet (§11.9.1).
    ArkChargeNotOwner,
    /// Ark→Normal unload requires FACT chain fully clean — zero scars (§11.9.3).
    ArkUnloadScarred,
    /// Ark→Ark in the ONLINE witnessed pipeline is a category error: Ark-to-Ark
    /// is the OFFLINE trade (§11). (BUILD §2.2 "W7".)
    ArkOnlineTradeRejected,
    /// YPX-010 §11 — a k=0 Ark ⟠-trade link is missing its receiver-as-witness
    /// attestation (`receiver_witness` = None), or (exclusivity §11.7) carries
    /// validator witness sigs it must not. A k=0 link is witnessed by EXACTLY the
    /// receiver's wallet key and nothing else.
    ArkReceiverWitnessMissing,
    /// YPX-010 §11 — a k=0 Ark ⟠-trade link's receiver-as-witness Ed25519 signature
    /// does not verify against `receiver_witness.receiver_pk` over the fact commitment.
    ArkReceiverWitnessInvalid,
    /// YPX-010 §11 "S1" — a k=0 Ark link carries a `NablaConfirmation`. Offline trades
    /// have no Nabla, and settlement resolves via consume-once (not a link
    /// confirmation), so presence of one on a k=0 link is malformed.
    ArkK0NablaConfirmationForbidden,
    /// YPX-010 §11.2 (ruling 2026-07-20): a k=0 offline ⟠-trade witness leg
    /// (receiver-side CL2) requires the SENDER's CL1 DMAP attestation in
    /// `cl1_execution_proof` — the worldline proof. Absent/empty → reject.
    ArkSenderProofMissing,
    /// YPX-010 §11.2: the sender's CL1 DMAP attestation failed in-guest
    /// verification (decode / strict same-CoreID / sender-pk binding /
    /// input-hash reconstruction / checkpoint-challenge / signature).
    ArkSenderProofInvalid,
    /// Self-send rejected — cannot send to own address except Ark (§11.9.4).
    SelfSendRejected,
    /// Receiver wallet_id has -XX email change suffix but no receiver_address provided.
    ReceiverAddressRequired,
    /// Receiver address has invalid checksum (typo protection).
    InvalidReceiverAddress,
    // `NablaWriterDetected` and the six `Stake*` CL8 stake-proof refusals
    // (`StakeWalletMismatch`, `StakeNablaSignatureInvalid`, `StakeStateMismatch`,
    // `StakeInsufficientReceipts`, `StakeProofExpired`, `StakeWalletScarred`)
    // were DELETED 2026-10-02 (KI#249): no code emitted any of them since CL8's
    // stake-proof verification was removed (ValidatorJoin §6b.8a, KI#168, which
    // ruled their deletion on 2026-09-15). IPC codes 1310–1316 are retired
    // (`core/ipc/src/codec.rs`) — never reassign.
    /// §6b — a VBC-shaped certificate carries no Nabla registration stamp: a
    /// candidate, not a usable credential.
    VbcNotRegistered,
    /// §6b — the certificate's Nabla registration stamp does not verify
    /// (signature, NBC anchor, hash/wallet binding, or floor).
    VbcStampInvalid,
    /// §5.2.2e — a PROVISIONAL certificate request carries no candidacy
    /// Pulse proof (only a running validator can produce one).
    VbcCandidacyPulseMissing,
    /// §5.2.2e — the candidacy Pulse proof does not verify (another key, bad
    /// signature, empty audit, stale epoch, or below the throughput floor).
    VbcCandidacyPulseInvalid,
    /// §5.2.2e part iii (KI#142) — the candidacy Pulse proof carries no
    /// Nabla-attested tick: the self-audit was not seeded by a tick the
    /// candidate obtained from Nabla, so it is neither fresh work nor a
    /// witness that the candidate reaches Nabla.
    VbcCandidacyPulseUntimed,
    /// A DEV account (`@axiom` / `@axiom.internal`) requested a validator
    /// certificate. Validators and Nabla nodes MUST be real accounts — there
    /// is NO dev VBC/NBC (the owner, 2026-09-20; `AXIOM_DESIGN_FactClassIsolation.md`
    /// preamble point 0). A dev account touches only the dev pool and never
    /// takes part in real-money consensus. Hard reject at the VBC request.
    DevAccountForbiddenFromValidator,

    // MVIB errors (YP §10)
    /// MVIB admission set is empty (must have k=3 issuers)
    MvibEmptyAdmissionSet,
    /// MVIB admission set has wrong size (must be exactly 3)
    MvibInvalidAdmissionSetSize,
    /// MVIB admission set contains duplicate validator IDs
    MvibDuplicateIssuer,
    /// MVIB signature verification failed
    MvibInvalidSignature,
    /// MVIB binding tick is zero (invalid)
    MvibInvalidTick,

    // Console errors (YPX-013)
    /// Console certificate generation doesn't increment by exactly 1
    ConsoleInvalidGeneration,
    /// Console certificate previous_link_hash doesn't match current certificate
    ConsoleChainMismatch,
    /// Console certificate doesn't have exactly CONSOLE_SIZE (15) seats
    ConsoleInvalidSeatCount,
    /// Console certificate has duplicate validator_ids in seats
    ConsoleDuplicateSeat,
    /// Console certificate term_start doesn't match previous term_end
    ConsoleTermMismatch,
    /// Console certificate term_end != term_start + TICKS_PER_YEAR
    ConsoleInvalidTermLength,
    /// Selector is not a member of the current Console
    ConsoleInvalidSelector,
    /// Selector picks contain validator not in nomination list
    ConsoleInvalidPick,
    /// Not all 3 selectors submitted picks
    ConsoleIncompleteSelection,
    /// Console action TX sender is not in Console seats
    ConsoleNotMember,

    // Genesis lockup errors (White Paper §2.10.1)
    /// Sender is a genesis validator wallet in the 3-year lockup period.
    GenesisStakeLocked,

    // YPX-018 — CLARA & Tiered Bloom Memory (v2.11.15)
    /// CLARA attestation Ed25519 signature verification failed.
    ClaraInvalidSignature,
    /// CLARA attestation `wallet_pk` does not match the witness request's wallet.
    ClaraWalletPkMismatch,
    /// The CL2 view's state_id for this wallet is not the attestation's
    /// `healed_to_state_id` (KI#260: eligibility is `healed_to` ONLY — the
    /// name predates that ruling; the wire code is unchanged).
    ClaraStateNotGarbage,
    /// CLARA attestation NBC trust anchor failed (issuer not root authority,
    /// or SPHINCS+ signature invalid, or commitment mismatch).
    ClaraNbcTrustFailed,
    /// CLARA attestation `garbage_state_ids` is empty. Must declare at least
    /// one abandoned state.
    ClaraEmptyGarbage,
    /// Console BLOOM_PHASE_OUT proposal violates a constitutional limit
    /// (era too young, grace period too short, era already phased out, or
    /// effective tick in the past). Core CL11 refuses to sign.
    ConsolePhaseOutInvalid,
    /// Txid attestation status is `PhasedOut` — the bloom era containing
    /// this txid was retired by Console action. Cheque is irrevocably dead.
    TxidPhasedOut,

    // §13 Progressive Redeem Registration
    /// Redeem registration incomplete (progress < required_k) and no scar_passcode.
    RedeemRegistrationIncomplete,

    // §17.11 Genesis Claim
    /// Genesis claim rejected: wallet_seq must be 1 and prev_seq must be 0.
    GenesisClaimInvalidSeq,
    /// §5.2.2c — the wallet holds a validator stake lock (`wall_clock_lock`) whose
    /// deadline has NOT passed.
    ///
    /// ⚠ CORRECTED 2026-09-05. This doc read "at least one of the two deadlines
    /// (attested tick / wall clock) has NOT passed. Both must. Fails closed: with
    /// no attested tick, release cannot be proven." That described a gate that no
    /// longer exists in this shape: the separate `stake_locked_until_tick` field was
    /// DELETED, and the two halves are now enforced by two DIFFERENT gates —
    /// - the TICK half is `hibernation_until`, stamped through the shared
    ///   HAL/RECALL path (`hibernation_until_for`) and refused as
    ///   `WalletHibernating`;
    /// - the WALL-CLOCK half is this variant, `tx.epoch < st.wall_clock_lock`.
    ///
    /// Both are enforced, so the AND still holds — but `StakeLocked` is emitted for
    /// the wall-clock half ALONE. See `validation.rs` (the §5.2.2c gate) for the
    /// banner recording where each half lives.
    StakeLocked,
    /// §5.2.2c INTERLOCK (KI#137) — the wallet's `(hibernation_until,
    /// wall_clock_lock)` pair is a distance apart that NO tier could have
    /// minted, so it was FORGED rather than merely still running.
    ///
    /// Distinct from [`StakeLocked`] on purpose: that one means "the lock is
    /// real and has not expired" and its only cure is waiting; this one means
    /// "this lock is not real" and waiting will never cure it. Collapsing them
    /// would tell a holder to wait out a deadline that does not exist.
    StakeLockPairUnmintable,
    /// ValidatorJoin §6b.13 (KI#225) — the STAKE FLOOR: this transaction lowers
    /// the balance below `VALIDATOR_STAKE_FLOOR_ATOMS` while the wallet's
    /// `stake_floor_until` is live (or cannot be PROVEN lapsed — no verified
    /// attested tick). Distinct from [`StakeLocked`] on purpose: the surplus
    /// above the floor is spendable, so this is a floor, not a lock. The cure
    /// is to send less (keep 500) or wait for the certificate's maximum life to
    /// pass.
    StakeFloor,
    /// ValidatorJoin §6b.13 — a wallet state whose format block is not
    /// `WalletFormat::CURRENT` (`wallet_version != WALLET_VERSION` or a
    /// non-zero reserved ext field). Core neither consumes nor produces one.
    WalletFormatInvalid,
    /// §5.2.2c — a subsidy claim's redeem carried no attested tick, so the
    /// stake lock has no verifiable base to count from. FAILS CLOSED: a lock
    /// stamped from 0 would read as already-expired, i.e. a subsidy with no
    /// lock at all. Retry with an OODS reading.
    ///
    /// ⚠ **DECLARED AND NOT EMITTED — RULE 3 §1, marked rather than deleted
    /// (2026-09-05).** No production site constructs this variant, and a reader
    /// must not infer that Core checks for an attested tick at the stamp: it does
    /// not. The stamp's base is the ISSUERS' signed `created_at`, validated by the
    /// two-account cross-check (`types::stamp_stake_lock`), which refuses with
    /// `StakeLockTimeDisagreement` — that is what took over this variant's job.
    ///
    /// KEPT, not deleted, for one specific reason: the stake RELEASE path is an
    /// OPEN RULING (a stake wallet currently cannot send again — the hibernation
    /// half is binary and never reopens), and judging release on an attested tick
    /// is one of the live options. If the ruling lands without needing an attested
    /// tick, DELETE this variant in that commit rather than leaving it parked.
    StakeLockNoAttestedTick,
    /// §5.2.2c — the claimant's declared epoch and the issuers' clocks disagree
    /// about the claim's own witness round by more than the tolerated range.
    /// One of them is lying; neither is trusted alone, so the claim is refused.
    StakeLockTimeDisagreement,
    /// §23.15 TRANSACTION VELOCITY LIMIT (TVL, KI#221). This transaction's
    /// Nabla-attested tick is fewer than `TX_VELOCITY_MIN_TICKS` after the
    /// wallet's previous witnessed transaction (`prev_receipt.oods_flag.tick`).
    ///
    /// A wallet moving faster than the tick floor is the burst a double-spend
    /// fork needs: redeem a stale attestation onto two validator sets, then fork
    /// two sends from the shared state before the conflict-ban gossip converges.
    /// An honest wallet never transacts this fast, so the floor is refused rather
    /// than raced. The judged tick is Nabla-signed (`verify_oods_attestation`), so
    /// this holds unless every Nabla and validator on the round colludes.
    ///
    /// NON-POISONING: the validator is not byzantine and the wallet is not forged
    /// — it simply moved too fast. The client retries after the floor elapses.
    TxVelocityTooFast,
    /// Genesis claim rejected: tx.amount must be 0 (pool amount is protocol-determined).
    GenesisClaimInvalidAmount,

    // ╔═ BOOTSTRAP SUBSIDY — REMOVE WHEN POOLS DRAIN ═══════════════╗
    // §5.2.2b admission gate. Removal: delete these four variants with the
    // two claim kinds. Design: AXIOM_DESIGN_ValidatorJoin.md §5.2.2b
    // ╚═════════════════════════════════════════════════════════════╝
    /// Subsidy claim rejected: no claimant provisional VBC was supplied.
    /// §5.2.2 requires the BINDING before the FUNDING — a claim with no
    /// binding is not a claim. Fails closed.
    ValidatorJoinNoProvisionalVbc,
    /// Subsidy claim rejected: the claimant's VBC is NOT provisional.
    /// A full VBC carries a §7.1 stake proof, so its holder already holds its
    /// floor and is a SELF-FUNDED joiner — §5.2.1 says such a candidate never
    /// touches a claim kind. Accepting one would fund the party that does not
    /// need it and let a single identity claim twice.
    ValidatorJoinVbcNotProvisional,
    /// Subsidy claim rejected: the claimant's VBC does not bind `tx.client_pk`.
    /// Without this, any candidate's cert would fund any wallet.
    ValidatorJoinVbcNotBound,
    /// Subsidy claim rejected: the claimant's VBC failed verification
    /// (issuer set / signatures / chain). Structure alone is not a credential.
    ValidatorJoinVbcInvalid,
    /// CL5 redeem rejected: a self-send cheque carrying GENESIS_CLAIM_AMOUNT
    /// (i.e., an airdrop cheque) was presented for redemption against a wallet
    /// whose stored state is already advanced (balance != 0 OR wallet_seq != 0).
    /// Genesis-claim cheques are one-shot by §17.11 invariant — a replay
    /// against a funded wallet is the infinite-mint attack class. Closes the
    /// hole where per-validator try_mark_cheque_redeemed and the
    /// receiver_fact_chain check (Step 3.5c) both failed to fire on a
    /// rescan-resurrected airdrop bundle.
    GenesisClaimWalletAlreadyFunded,

    /// SEC-02 (cap-at-mint via FACT scar). A genesis claim (self-send of
    /// GENESIS_CLAIM_AMOUNT) was presented for redemption but its FACT link
    /// is SCARRED — it carries no `nabla_confirmation`. The only thing that
    /// gates a genesis draw against the 100M/1M pool ceiling is the admitting
    /// Nabla's `try_claim`, and a Nabla emits its blessing (NablaConfirmation)
    /// ONLY after `try_claim` succeeds. An un-blessed genesis link therefore
    /// means the pool was never debited: the mint would be unaccounted supply.
    /// Hard reject. See docs/security_review_20260612/SEC-02_*.
    GenesisNablaBlessingMissing,

    /// FACT class isolation Rule R1 violation
    /// (`AXIOM_DESIGN_FactClassIsolation.md` §2.1, §3).
    /// Sender and receiver wallet_ids belong to different classes —
    /// one is dev (`@axiom.internal`), the other public. Cross-class
    /// TXs are forbidden in either direction.
    DomainMismatch,

    /// YPX-020 — the wallet is HIBERNATING: its witnessed prev-state
    /// `hibernation_until` is still in the future relative to `tx.epoch`, so
    /// the wallet is "out of work" and CL2 rejects every returning tx until the
    /// period elapses. CL1 (no prev state) is exempt.
    WalletHibernating,

    /// YPX-021 §8.2 — a supplied `NablaOodsAttestation` failed verification
    /// (bad Ed25519 signature, missing/invalid NBC trust anchor, or the
    /// claimed baseline is not bound into the issuer-signed cert). A hard
    /// reject: an invalid attestation never silently downgrades to
    /// "no flag" — that would let an attacker strip an unhealthy reading.
    OodsAttestationInvalid,
    /// YPX-021 §8.5 (2026-07-05) — a RECOVERY re-anchor (HAL / RECALL / HEAL)
    /// was attempted while the network's OODS is NOT verified-healthy (unhealthy
    /// reading, or no reading at all). Recovery ops are overlap-relaxed, so their
    /// double-spend backstop (Nabla consume-once) is weakest exactly during a
    /// partition/eclipse — which is what unhealthy OODS signals. So a recovery is
    /// BLOCKED until OODS is healthy. This is RETRYABLE (RecoveryHint::WaitAndRetry):
    /// the wallet re-attempts when the network recovers — it is NOT stranded, and
    /// NOT poisoned. Distinct from `OodsAttestationInvalid` (a forged reading, hard
    /// reject) — this is an honestly-unhealthy or absent reading.
    OodsUnhealthyRetry,
    /// YPX-022 — a RECALL attestation failed verification (bad Nabla sig / NBC anchor).
    RecallAttestationInvalid,
    /// KI#59 — an out-of-order confirmation failed verification (bad Nabla sig / NBC anchor).
    OooConfirmationInvalid,
    /// §10.0 FOB fee-claim — attestation missing/failed verification, or a pin
    /// (amount ==, sender ==, class ==) did not hold. Wrong amount = this.
    FobClaimInvalid,
    /// `AXIOM_DESIGN_ValidatorJoin.md` §5.2.2 — a PROVISIONAL certificate was
    /// presented as a witness's or a cheque signer's credential. A provisional
    /// is a candidate binding issued before funding; it confers no service
    /// rights, so a signature made under one is not a validator signature.
    ///
    /// Detected by LIFETIME (`validation::vbc_is_provisional`), never by
    /// remaining life — see that function for why a remaining-life test here
    /// would retroactively strand honest wallets.
    ///
    /// ⚠ Filed at the END of this enum, away from the VBC family it belongs
    /// with, deliberately: `ValidationError` derives `Serialize`, so an
    /// insertion mid-enum would shift every later variant's index in any
    /// positional encoding. Same rule as new gossip variants. The numeric
    /// wire code is explicit (`ve_to_u64` = 508) and is unaffected by
    /// position, so the code stays with the VBC family where a reader
    /// expects it.
    VBCProvisionalCannotServe { issued_at: u64, expires_at: u64 },

    // ╔═ §5.3 GENESIS LINEAGE + CL8 ISSUANCE — DISTINCT REFUSAL REASONS ═╗
    //
    // Every one of these arms returned a bare `InvalidVBC` until 2026-09-04.
    // That is RULE 3 shape 2: the rejections were real and firing, and from
    // outside the guest they were INDISTINGUISHABLE from each other and from
    // "the check never ran". A certificate request that CL8 refused could not
    // be diagnosed at all — `execute_cl8` runs inside the RISC-V guest, where
    // the `#[cfg(feature = "std")]` VBC_DIAG prints are compiled out, so the
    // error variant is the ONLY channel that survives to the mesh.
    //
    // The §5.3 family (VBC*) is shared by BOTH sites that implement the rule —
    // `vbc::verify_chain_recursive` (the enforcement) and `execute_cl8` (the
    // fail-fast twin) — so one vocabulary describes one rule (RULE 1).
    //
    // ⚠ Appended at the END for the same reason `VBCProvisionalCannotServe`
    // was: `ValidationError` derives `Serialize`, so a mid-enum insertion
    // shifts every later variant's index in a positional encoding. The numeric
    // wire codes (`ve_to_u64`, 510-515 / 520-525) sit with the VBC family
    // where a reader looks for them.
    // ╚══════════════════════════════════════════════════════════════════╝
    /// §5.3 — the issuing bar could not be judged: no attested tick was
    /// supplied. FAILS CLOSED. `tx.epoch` is sender-chosen and unbounded
    /// (KI#130), so an admission control must never fall back to it —
    /// backdating would rescue an unfit issuer.
    VBCNoAttestedTick,
    /// §5.3 — an issuer's OWN certificate is absent from `supporting_vbcs`,
    /// so its genesis family and remaining life cannot be resolved. The
    /// issuers' certs are what the rule is checked against; they must ride in
    /// the request.
    VBCIssuerCertMissing,
    /// §5.3 — an issuer holds less remaining life than the ISSUING bar
    /// (`validation::vbc_can_issue`). A validator about to expire may still
    /// serve; it may not admit a newcomer whose standing would outlive it.
    VBCIssuerCannotIssue,
    /// §5.3 — an issuer belongs to no genesis family, so it has no lineage to
    /// contribute. Lineage is one of the ten genesis validators, identified by
    /// SPHINCS+ PUBLIC KEY (`GENESIS_VALIDATORS`), never by `validator_id`.
    VBCIssuerNoLineage,
    /// §5.3 — two issuers share one genesis family. THE RULE: three issuers,
    /// three DIFFERENT families. This is what stops one family admitting
    /// itself over and over.
    VBCIssuersShareLineage,
    /// §5.3 — the certificate's own `genesis_lineage` is not one of its
    /// issuers'. A newcomer is ADOPTED into a sponsoring family; it does not
    /// found an eleventh, and it may not name standing nobody granted it.
    VBCLineageNotAdopted,

    /// CL8 — called with no `vbc_bundle`. Plumbing: the caller sent no
    /// certificate to sign.
    Cl8MissingBundle,
    /// CL8 — called with no `issuer_sphincs_sk`. Plumbing: the caller sent no
    /// key to sign with.
    Cl8MissingIssuerKey,
    /// CL8 — the signing key derives to a public key that is NOT among the
    /// certificate's declared issuers. Such a signature is cryptographically
    /// fine and belongs to nobody the cert names, so `verify_chain_recursive`
    /// (which pairs `signatures[i]` with `issuer_set[i]`) could never match
    /// it. Refused at issue rather than shipped as a cert that verifies
    /// nowhere.
    Cl8SignerNotInIssuerSet,
    /// CL8 — a provisional (unstaked) certificate was presented with a zero or
    /// inverted lifetime (`expires_at <= issued_at`). Never sign a cert that
    /// is already dead or whose window runs backwards.
    Cl8ProvisionalLifetimeInvalid,
    /// CL8 — `sphincs_pk_from_sk` failed: the issuer key is malformed or the
    /// wrong length. Core fault or a corrupt operator key, not a protocol
    /// refusal.
    Cl8IssuerKeyUnusable,
    /// CL8 — SPHINCS+ signing itself failed. Core fault, not a protocol
    /// refusal.
    Cl8SigningFailed,
    /// CL8 — verify-after-sign failed (fail-stop, same as the ceremony). Core
    /// or transport fault: the signature Core just produced does not verify
    /// under the key that produced it.
    Cl8VerifyAfterSignFailed,
    /// CL8 — the certificate's OODS stamp (`network_size_baseline` /
    /// `baseline_tick`) disagrees with the attestation the request carried.
    ///
    /// RULED (the owner, 2026-09-04). The stamp is what §5.3's issuing bar is
    /// judged on at EVERY later verification (`vbc::issuing_tick_for`), and it
    /// is what YPX-021 §7 says justifies whether a certificate is trustworthy
    /// at all. So an issuer must not sign one it has been shown no evidence
    /// for: the candidate DECLARES the reading, and Core binds it to the
    /// attestation the round carried. Without this bind the candidate would be
    /// writing its own admission clock.
    Cl8OodsStampMismatch,
    /// §11.9.1b — the SENDER of an Ark CHARGE carries an unresolved FACT link.
    /// the owner's ruling 2026-09-17: the sender must be healthy on BOTH legs of a
    /// normal<->Ark self-send; the receiver never needs to be. Appended LAST —
    /// a new variant goes at the end so existing discriminants do not shift.
    ArkChargeScarred,
    /// Fable review 2026-10-01 F-1(b) — CL5's receiver anchor: the redeem's
    /// DECLARED receiver state and its carried `prev_receipts` do not have the
    /// anchorable shape. A returning (non-opening, `!WalletState::is_opening_state`) receiver
    /// must carry EXACTLY ONE receipt — its last; a first-time (opening) state must
    /// carry NONE. (A carried receipt that does not re-derive the declared state
    /// is `StateNotAnchored`.) Appended LAST, same rule as above.
    ReceiverStateNotAnchored,
    // YPX-007 §9.4 (KI#125) — mode `ZkpQualify` refusals, each its own code.
    // None of them is a service refusal: the validator keeps serving every
    // proof_type; it only gets no qualification record.
    /// `zkq_request` or the T0 reading (`oods_attestation`) is absent.
    ZkqMissingRequest,
    /// `my_validator_id` / `my_dilithium_pk` / `my_dilithium_sk` is absent.
    ZkqMissingSigner,
    /// T1 was signed by a different Nabla node than T0.
    ZkqNodeMismatch,
    /// `T1.tick < T0.tick` or `T1.tick − T0.tick > ZKQ_MAX_GAP_TICKS`.
    ZkqTooSlow,
    /// The journal's `zkp_nonce_hash` is not the hash of the T0-derived challenge.
    ZkqChallengeMismatch,
}

impl core::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StateIdAlreadyConsumed => write!(f, "E_STATE_ID_CONSUMED"),
            Self::InvalidStateId => write!(f, "E_INVALID_STATE_ID"),
            Self::InvalidWalletSeq => write!(f, "E_INVALID_WALLET_SEQ"),
            Self::WalletSeqOverflow => write!(f, "E_WALLET_SEQ_OVERFLOW"),
            Self::InvalidWalletId => write!(f, "E_INVALID_WALLET_ID"),
            Self::MalformedAddress => write!(f, "E_MALFORMED_ADDRESS"),
            Self::InvalidClientSignature => write!(f, "E_INVALID_CLIENT_SIG"),
            Self::InvalidWitnessSignature => write!(f, "E_INVALID_WITNESS_SIG"),
            Self::UnsupportedSignatureAlgorithm => write!(f, "E_UNSUPPORTED_SIG_ALG"),
            Self::InsufficientBalance => write!(f, "E_INSUFFICIENT_BALANCE"),
            Self::ConservationViolation => write!(f, "E_CONSERVATION_VIOLATION"),
            Self::ZeroAmount => write!(f, "E_ZERO_AMOUNT"),
            Self::DustAmount => write!(f, "E_DUST_AMOUNT"),
            Self::InvalidVBC => write!(f, "E_INVALID_VBC"),
            Self::VBCExpired { .. } => write!(f, "E_VBC_EXPIRED"),
            Self::VBCNotYetValid { .. } => write!(f, "E_VBC_NOT_YET_VALID"),
            Self::VBCUnusableSoon { .. } => write!(f, "E_VBC_UNUSABLE_SOON"),
            Self::VBCStaleAttestation { .. } => write!(f, "E_VBC_STALE_ATTESTATION"),
            Self::VBCLifetimeTooLong { .. } => write!(f, "E_VBC_LIFETIME_TOO_LONG"),
            Self::VbcRenewalNoProofOfWork => write!(f, "E_VBC_RENEWAL_NO_PROOF_OF_WORK"),
            Self::VbcRenewalNotCoSigned => write!(f, "E_VBC_RENEWAL_NOT_CO_SIGNED"),
            Self::VbcRenewalWorkReceiptStale => write!(f, "E_VBC_RENEWAL_WORK_RECEIPT_STALE"),
            Self::VbcRenewalWorkReceiptSubQuorum => write!(f, "E_VBC_RENEWAL_WORK_RECEIPT_SUB_QUORUM"),
            Self::VBCProvisionalCannotServe { .. } => write!(f, "E_VBC_PROVISIONAL_CANNOT_SERVE"),
            // §5.3 genesis lineage — one vocabulary, both enforcement sites.
            Self::VBCNoAttestedTick => write!(f, "E_VBC_NO_ATTESTED_TICK"),
            Self::VBCIssuerCertMissing => write!(f, "E_VBC_ISSUER_CERT_MISSING"),
            Self::VBCIssuerCannotIssue => write!(f, "E_VBC_ISSUER_CANNOT_ISSUE"),
            Self::VBCIssuerNoLineage => write!(f, "E_VBC_ISSUER_NO_LINEAGE"),
            Self::VBCIssuersShareLineage => write!(f, "E_VBC_ISSUERS_SHARE_LINEAGE"),
            Self::VBCLineageNotAdopted => write!(f, "E_VBC_LINEAGE_NOT_ADOPTED"),
            // CL8 issuance.
            Self::Cl8MissingBundle => write!(f, "E_CL8_MISSING_BUNDLE"),
            Self::Cl8MissingIssuerKey => write!(f, "E_CL8_MISSING_ISSUER_KEY"),
            Self::Cl8SignerNotInIssuerSet => write!(f, "E_CL8_SIGNER_NOT_IN_ISSUER_SET"),
            Self::Cl8ProvisionalLifetimeInvalid => write!(f, "E_CL8_PROVISIONAL_LIFETIME_INVALID"),
            Self::Cl8IssuerKeyUnusable => write!(f, "E_CL8_ISSUER_KEY_UNUSABLE"),
            Self::Cl8SigningFailed => write!(f, "E_CL8_SIGNING_FAILED"),
            Self::Cl8VerifyAfterSignFailed => write!(f, "E_CL8_VERIFY_AFTER_SIGN_FAILED"),
            Self::Cl8OodsStampMismatch => write!(f, "E_CL8_OODS_STAMP_MISMATCH"),
            Self::VBCChainTooDeep => write!(f, "E_VBC_CHAIN_TOO_DEEP"),
            Self::VBCMissingIssuer => write!(f, "E_VBC_MISSING_ISSUER"),
            Self::VBCRootKeyMismatch => write!(f, "E_VBC_ROOT_KEY_MISMATCH"),
            Self::GenesisNameReserved => write!(f, "E_GENESIS_NAME_RESERVED"),
            Self::DuplicateValidator => write!(f, "E_DUPLICATE_VALIDATOR"),
            Self::InvalidVBCCount => write!(f, "E_INVALID_VBC_COUNT"),
            Self::MissingPrevReceipts => write!(f, "E_MISSING_PREV_RECEIPTS"),
            Self::InvalidGenesisTransaction => write!(f, "E_INVALID_GENESIS_TX"),
            Self::InvalidExecutionProof => write!(f, "E_INVALID_EXECUTION_PROOF"),
            Self::ProgramDigestMismatch => write!(f, "E_PROGRAM_DIGEST_MISMATCH"),
            Self::InvalidCanonicalJson => write!(f, "E_INVALID_JSON"),
            Self::TxidAttestationMissing => write!(f, "E_TXID_ATTESTATION_MISSING"),
            Self::TxidAttestationInvalidSig => write!(f, "E_TXID_ATTESTATION_INVALID_SIG"),
            Self::TxidAttestationRedeemed => write!(f, "E_TXID_ATTESTATION_REDEEMED"),
            Self::TxidAttestationBadStatus => write!(f, "E_TXID_ATTESTATION_BAD_STATUS"),
            Self::TxidAttestationUntrusted => write!(f, "E_TXID_ATTESTATION_UNTRUSTED"),
            Self::InsufficientCheques => write!(f, "E_INSUFFICIENT_CHEQUES"),
            Self::InconsistentChequeBundle => write!(f, "E_INCONSISTENT_CHEQUE_BUNDLE"),
            Self::InvalidChequeSignature => write!(f, "E_INVALID_CHEQUE_SIG"),
            Self::ChequeAlreadyRedeemed => write!(f, "E_CHEQUE_ALREADY_REDEEMED"),
            Self::RedeemSenderAnchorMissing => write!(f, "E_REDEEM_SENDER_ANCHOR_MISSING"),
            Self::RedeemBeforeCommitPropagated => write!(f, "E_REDEEM_BEFORE_COMMIT_PROPAGATED"),
            Self::RedeemBalanceMismatch => write!(f, "E_REDEEM_BALANCE_MISMATCH"),
            Self::RedeemBalanceOverflow => write!(f, "E_REDEEM_BALANCE_OVERFLOW"),
            Self::MissingExecutionProof => write!(f, "E_MISSING_EXECUTION_PROOF"),
            Self::MissingRedeemInputs => write!(f, "E_MISSING_REDEEM_INPUTS"),
            Self::MissingVBC => write!(f, "E_MISSING_VBC"),
            Self::FeeExceedsValidatorCap => write!(f, "E_FEE_EXCEEDS_VALIDATOR_CAP"),
            Self::FeeExceedsAggregateCap => write!(f, "E_FEE_EXCEEDS_AGGREGATE_CAP"),
            Self::FeeExceedsAmount => write!(f, "E_FEE_EXCEEDS_AMOUNT"),
            Self::FeeSlotMathInvalid => write!(f, "E_FEE_SLOT_MATH_INVALID"),
            Self::CarriersTooLarge => write!(f, "E_CARRIERS_TOO_LARGE"),
            Self::InvalidHintCount => write!(f, "E_INVALID_HINT_COUNT"),
            Self::SelfHintNotAllowed => write!(f, "E_SELF_HINT_NOT_ALLOWED"),
            Self::ArkNotImplemented => write!(f, "E_ARK_NOT_IMPLEMENTED"),
            Self::OracleSenderMismatch => write!(f, "E_ORACLE_SENDER_MISMATCH"),
            Self::OracleInsufficientK => write!(f, "E_ORACLE_INSUFFICIENT_K"),
            Self::OracleVBCTooOld => write!(f, "E_ORACLE_VBC_TOO_OLD"),
            Self::OracleInsufficientStake => write!(f, "E_ORACLE_INSUFFICIENT_STAKE"),
            Self::OracleStakeScarred => write!(f, "E_ORACLE_STAKE_SCARRED"),
            Self::OraclePlatformInvalid => write!(f, "E_ORACLE_PLATFORM_INVALID"),
            Self::OracleLivingSignatureMissing => write!(f, "E_ORACLE_LIVING_SIG_MISSING"),
            Self::OracleZeroDelta => write!(f, "E_ORACLE_ZERO_DELTA"),
            Self::OracleNonZeroAmount => write!(f, "E_ORACLE_NONZERO_AMOUNT"),
            Self::OracleMaturityNotReached => write!(f, "E_ORACLE_MATURITY_NOT_REACHED"),
            Self::ReferenceTooLarge => write!(f, "E_REFERENCE_TOO_LARGE"),
            Self::InvalidMode => write!(f, "E_INVALID_MODE"),
            Self::InternalError => write!(f, "E_INTERNAL"),
            Self::SABRInsufficientOverlap => write!(f, "E_SABR_INSUFFICIENT_OVERLAP"),
            Self::SABROverlapNotInPrev => write!(f, "E_SABR_OVERLAP_NOT_IN_PREV"),
            Self::SABRMissingValidatorPK => write!(f, "E_SABR_MISSING_VALIDATOR_PK"),
            Self::SABRHashMismatch => write!(f, "E_SABR_HASH_MISMATCH"),
            Self::ReceiptFromWrongWorldline => write!(f, "E_RECEIPT_WRONG_WORLDLINE"),
            Self::ReceiptLineageMismatch => write!(f, "E_RECEIPT_LINEAGE_MISMATCH"),
            Self::ReceiptCommitmentMismatch => write!(f, "E_RECEIPT_COMMITMENT_MISMATCH"),
            Self::GroupTooManyMembers => write!(f, "E_GROUP_TOO_MANY_MEMBERS"),
            Self::GroupShareBpsInvalid => write!(f, "E_GROUP_SHARE_BPS_INVALID"),
            Self::GroupNotMember => write!(f, "E_GROUP_NOT_MEMBER"),
            Self::GroupInsufficientAvailable => write!(f, "E_GROUP_INSUFFICIENT_AVAILABLE"),
            Self::GroupChecksumFailed => write!(f, "E_GROUP_CHECKSUM_FAILED"),
            Self::GroupMembersImmutable => write!(f, "E_GROUP_MEMBERS_IMMUTABLE"),
            Self::GroupDistributionOverflow => write!(f, "E_GROUP_DISTRIBUTION_OVERFLOW"),
            Self::GroupMemberMismatch => write!(f, "E_GROUP_MEMBER_MISMATCH"),
            // FACT chain errors
            Self::FactChainTooDeep => write!(f, "E_FACT_CHAIN_TOO_DEEP"),
            Self::FactChainBreak => write!(f, "E_FACT_CHAIN_BREAK"),
            Self::FactInsufficientWitnesses => write!(f, "E_FACT_INSUFFICIENT_WITNESSES"),
            Self::FactInvalidSignature => write!(f, "E_FACT_INVALID_SIGNATURE"),
            Self::FactDuplicateWitness => write!(f, "E_FACT_DUPLICATE_WITNESS"),
            Self::FactInvalidCheckpoint => write!(f, "E_FACT_INVALID_CHECKPOINT"),
            Self::FactChainEmpty => write!(f, "E_FACT_CHAIN_EMPTY"),
            Self::FactAmountOverflow => write!(f, "E_FACT_AMOUNT_OVERFLOW"),
            Self::FactWitnessUncertified => write!(f, "E_FACT_WITNESS_UNCERTIFIED"),
            Self::FactOriginInvalid => write!(f, "E_FACT_ORIGIN_INVALID"),
            Self::FactCertificateInvalid => write!(f, "E_FACT_CERTIFICATE_INVALID"),
            Self::FactBurnSigInvalid => write!(f, "E_FACT_BURN_SIG_INVALID"),
            Self::StakeClaimTierInvalid => write!(f, "E_STAKE_CLAIM_TIER_INVALID"),
            // Burn errors
            Self::BurnNoFactChain => write!(f, "E_BURN_NO_FACT_CHAIN"),
            Self::BurnMissingTarget => write!(f, "E_BURN_MISSING_TARGET"),
            Self::BurnTargetNotFound => write!(f, "E_BURN_TARGET_NOT_FOUND"),
            Self::BurnTargetNotScarred => write!(f, "E_BURN_TARGET_NOT_SCARRED"),
            Self::BurnTargetAlreadyBurned => write!(f, "E_BURN_TARGET_ALREADY_BURNED"),
            Self::BurnAmountMismatch => write!(f, "E_BURN_AMOUNT_MISMATCH"),
            Self::BurnProofInsufficientWitnesses => write!(f, "E_BURN_PROOF_INSUFFICIENT_WITNESSES"),
            Self::BurnProofDuplicateValidator => write!(f, "E_BURN_PROOF_DUPLICATE_VALIDATOR"),
            Self::BurnTxIdNotInChain => write!(f, "E_BURN_TX_ID_NOT_IN_CHAIN"),
            Self::BurnTargetMismatch => write!(f, "E_BURN_TARGET_MISMATCH"),
            Self::TooManyUnresolvedScars => write!(f, "E_TOO_MANY_UNRESOLVED_SCARS"),
            Self::MissingWalletState => write!(f, "E_MISSING_WALLET_STATE"),
            Self::VersionMismatch => write!(f, "E_VERSION_MISMATCH"),
            Self::CoreIdMismatch => write!(f, "E_CORE_ID_MISMATCH"),
            Self::MissingField => write!(f, "E_MISSING_FIELD"),
            Self::WalletSecretMismatch => write!(f, "E_WALLET_SECRET_MISMATCH"),
            // Fan-Out errors (CL10)
            Self::FanOutMissingMessage => write!(f, "E_FANOUT_MISSING_MESSAGE"),
            Self::FanOutTtlExceeded => write!(f, "E_FANOUT_TTL_EXCEEDED"),
            Self::FanOutInvalidFanout => write!(f, "E_FANOUT_INVALID_FANOUT"),
            Self::FanOutContentEmpty => write!(f, "E_FANOUT_CONTENT_EMPTY"),
            Self::FanOutContentTooLarge => write!(f, "E_FANOUT_CONTENT_TOO_LARGE"),
            Self::FanOutTtlExpired => write!(f, "E_FANOUT_TTL_EXPIRED"),
            Self::FanOutTtlInflated => write!(f, "E_FANOUT_TTL_INFLATED"),
            Self::FanOutUnknownContentType => write!(f, "E_FANOUT_UNKNOWN_CONTENT_TYPE"),
            Self::FanOutTimestampFuture => write!(f, "E_FANOUT_TIMESTAMP_FUTURE"),
            Self::FanOutTimestampExpired => write!(f, "E_FANOUT_TIMESTAMP_EXPIRED"),
            Self::FanOutDiffusionIdMismatch => write!(f, "E_FANOUT_DIFFUSION_ID_MISMATCH"),
            Self::FanOutInvalidOriginator => write!(f, "E_FANOUT_INVALID_ORIGINATOR"),
            Self::FanOutOriginatorPkMismatch => write!(f, "E_FANOUT_ORIGINATOR_PK_MISMATCH"),
            Self::FanOutInvalidSignature => write!(f, "E_FANOUT_INVALID_SIGNATURE"),
            Self::InsufficientStake => write!(f, "Insufficient stake for validator onboarding"),
            Self::WalletFrozen => write!(f, "Wallet frozen by Judicial Freeze Protocol"),
            Self::ArkToNonArkRejected => write!(f, "Ark wallet can only send to other Ark wallets"),
            Self::ArkChargeNotOwner => write!(f, "Only the wallet owner can charge their Ark wallet"),
            Self::ArkUnloadScarred => write!(f, "Ark unload requires fully clean FACT chain (zero scars)"),
            Self::ArkChargeScarred => write!(f, "Ark charge requires the SENDING wallet's FACT chain to be clean (zero unresolved links)"),
            Self::ReceiverStateNotAnchored => write!(f, "E_RECEIVER_STATE_NOT_ANCHORED"),
            Self::ZkqMissingRequest => write!(f, "E_ZKQ_MISSING_REQUEST"),
            Self::ZkqMissingSigner => write!(f, "E_ZKQ_MISSING_SIGNER"),
            Self::ZkqNodeMismatch => write!(f, "E_ZKQ_NODE_MISMATCH"),
            Self::ZkqTooSlow => write!(f, "E_ZKQ_TOO_SLOW"),
            Self::ZkqChallengeMismatch => write!(f, "E_ZKQ_CHALLENGE_MISMATCH"),
            Self::ArkOnlineTradeRejected => write!(f, "Ark-to-Ark trades are offline-only; rejected in the online witnessed pipeline"),
            Self::ArkReceiverWitnessMissing => write!(f, "E_ARK_RECEIVER_WITNESS_MISSING"),
            Self::ArkReceiverWitnessInvalid => write!(f, "E_ARK_RECEIVER_WITNESS_INVALID"),
            Self::ArkK0NablaConfirmationForbidden => write!(f, "E_ARK_K0_NABLA_CONFIRMATION_FORBIDDEN"),
            Self::ArkSenderProofMissing => write!(f, "E_ARK_SENDER_PROOF_MISSING"),
            Self::ArkSenderProofInvalid => write!(f, "E_ARK_SENDER_PROOF_INVALID"),
            Self::SelfSendRejected => write!(f, "Cannot send to own address (except Ark)"),
            Self::ReceiverAddressRequired => write!(f, "Receiver has changed email (-XX suffix). Provide receiver_address."),
            Self::InvalidReceiverAddress => write!(f, "Receiver address has invalid checksum"),
            Self::VbcCandidacyPulseMissing => write!(f, "E_VBC_CANDIDACY_PULSE_MISSING: a provisional certificate request must carry the candidate Pulse proof (only a running validator can produce one)"),
            Self::VbcCandidacyPulseInvalid => write!(f, "E_VBC_CANDIDACY_PULSE_INVALID: the candidacy Pulse proof does not verify (key, signature, content, freshness or throughput floor)"),
            Self::VbcCandidacyPulseUntimed => write!(f, "E_VBC_CANDIDACY_PULSE_UNTIMED: the candidacy Pulse proof carries no Nabla-attested tick (the self-audit must be seeded by a tick obtained from Nabla)"),
            Self::DevAccountForbiddenFromValidator => write!(f, "E_DEV_ACCOUNT_FORBIDDEN_FROM_VALIDATOR: a dev account (@axiom / @axiom.internal) cannot request or hold a validator certificate — validators and Nabla nodes must be real accounts"),
            Self::VbcNotRegistered => write!(f, "E_VBC_NOT_REGISTERED: certificate carries no Nabla registration stamp"),
            Self::VbcStampInvalid => write!(f, "E_VBC_STAMP_INVALID: certificate's Nabla registration stamp does not verify"),
            // MVIB errors
            Self::MvibEmptyAdmissionSet => write!(f, "E_MVIB_EMPTY_ADMISSION_SET"),
            Self::MvibInvalidAdmissionSetSize => write!(f, "E_MVIB_INVALID_ADMISSION_SET_SIZE"),
            Self::MvibDuplicateIssuer => write!(f, "E_MVIB_DUPLICATE_ISSUER"),
            Self::MvibInvalidSignature => write!(f, "E_MVIB_INVALID_SIGNATURE"),
            Self::MvibInvalidTick => write!(f, "E_MVIB_INVALID_TICK"),
            // Console errors (YPX-013)
            Self::ConsoleInvalidGeneration => write!(f, "E_CONSOLE_INVALID_GENERATION"),
            Self::ConsoleChainMismatch => write!(f, "E_CONSOLE_CHAIN_MISMATCH"),
            Self::ConsoleInvalidSeatCount => write!(f, "E_CONSOLE_INVALID_SEAT_COUNT"),
            Self::ConsoleDuplicateSeat => write!(f, "E_CONSOLE_DUPLICATE_SEAT"),
            Self::ConsoleTermMismatch => write!(f, "E_CONSOLE_TERM_MISMATCH"),
            Self::ConsoleInvalidTermLength => write!(f, "E_CONSOLE_INVALID_TERM_LENGTH"),
            Self::ConsoleInvalidSelector => write!(f, "E_CONSOLE_INVALID_SELECTOR"),
            Self::ConsoleInvalidPick => write!(f, "E_CONSOLE_INVALID_PICK"),
            Self::ConsoleIncompleteSelection => write!(f, "E_CONSOLE_INCOMPLETE_SELECTION"),
            Self::ConsoleNotMember => write!(f, "E_CONSOLE_NOT_MEMBER"),
            Self::GenesisStakeLocked => write!(f, "E_GENESIS_STAKE_LOCKED"),
            Self::SenderWalletIdMismatch => write!(f, "E_SENDER_WALLET_ID_MISMATCH"),
            // YPX-018 CLARA & Tiered Bloom
            Self::ClaraInvalidSignature => write!(f, "E_CLARA_INVALID_SIGNATURE"),
            Self::ClaraWalletPkMismatch => write!(f, "E_CLARA_WALLET_PK_MISMATCH"),
            Self::ClaraStateNotGarbage => write!(f, "E_CLARA_STATE_NOT_GARBAGE"),
            Self::ClaraNbcTrustFailed => write!(f, "E_CLARA_NBC_TRUST_FAILED"),
            Self::ClaraEmptyGarbage => write!(f, "E_CLARA_EMPTY_GARBAGE"),
            Self::ConsolePhaseOutInvalid => write!(f, "E_CONSOLE_PHASE_OUT_INVALID"),
            Self::TxidPhasedOut => write!(f, "E_TXID_PHASED_OUT"),
            Self::RedeemRegistrationIncomplete => write!(f, "E_REDEEM_REGISTRATION_INCOMPLETE"),
            Self::GenesisClaimInvalidSeq => write!(f, "E_GENESIS_CLAIM_INVALID_SEQ"),
            Self::GenesisClaimInvalidAmount => write!(f, "E_GENESIS_CLAIM_NON_ZERO_AMOUNT"),
            Self::StakeLocked => write!(f, "E_STAKE_LOCKED"),
            Self::StakeLockPairUnmintable => write!(f, "E_STAKE_LOCK_PAIR_UNMINTABLE"),
            Self::StakeFloor => write!(f, "E_STAKE_FLOOR"),
            Self::WalletFormatInvalid => write!(f, "E_WALLET_FORMAT_INVALID"),
            Self::StakeLockNoAttestedTick => write!(f, "E_STAKE_LOCK_NO_ATTESTED_TICK"),
            Self::TxVelocityTooFast => write!(f, "E_TX_VELOCITY_TOO_FAST"),
            Self::StakeLockTimeDisagreement => write!(f, "E_STAKE_LOCK_TIME_DISAGREEMENT"),
            Self::ValidatorJoinNoProvisionalVbc => write!(f, "E_VALIDATOR_JOIN_NO_PROVISIONAL_VBC"),
            Self::ValidatorJoinVbcNotProvisional => write!(f, "E_VALIDATOR_JOIN_VBC_NOT_PROVISIONAL"),
            Self::ValidatorJoinVbcNotBound => write!(f, "E_VALIDATOR_JOIN_VBC_NOT_BOUND"),
            Self::ValidatorJoinVbcInvalid => write!(f, "E_VALIDATOR_JOIN_VBC_INVALID"),
            Self::GenesisClaimWalletAlreadyFunded => write!(f, "E_GENESIS_CLAIM_WALLET_ALREADY_FUNDED"),
            Self::GenesisNablaBlessingMissing => write!(f, "E_GENESIS_NABLA_BLESSING_MISSING"),
            Self::DomainMismatch => write!(f, "E_DOMAIN_MISMATCH"),
            Self::WalletHibernating => write!(f, "E_WALLET_HIBERNATING"),
            Self::OodsAttestationInvalid => write!(f, "E_OODS_ATTESTATION_INVALID"),
            Self::OodsUnhealthyRetry => write!(f, "E_OODS_UNHEALTHY_RETRY"),
            Self::RecallAttestationInvalid => write!(f, "E_RECALL_ATTESTATION_INVALID"),
            Self::OooConfirmationInvalid => write!(f, "E_OOO_CONFIRMATION_INVALID"),
            Self::FobClaimInvalid => write!(f, "E_FOB_CLAIM_INVALID"),
            Self::HealNotNeeded => write!(f, "E_HEAL_NOT_NEEDED"),
            // Cheque-claim proof (CL5 synchronous double-redeem prevention)
            Self::ChequeClaimProofMissing => write!(f, "E_CHEQUE_CLAIM_PROOF_MISSING"),
            Self::ChequeClaimProofInvalidSig => write!(f, "E_CHEQUE_CLAIM_PROOF_INVALID_SIG"),
            Self::ChequeClaimProofUnauthenticated => write!(f, "E_CHEQUE_CLAIM_PROOF_UNAUTHENTICATED"),
            Self::ChequeClaimProofTxidMismatch => write!(f, "E_CHEQUE_CLAIM_PROOF_TXID_MISMATCH"),
            Self::ChequeClaimProofReceiverMismatch => write!(f, "E_CHEQUE_CLAIM_PROOF_RECEIVER_MISMATCH"),
            Self::ChequeClaimProofUntrusted => write!(f, "E_CHEQUE_CLAIM_PROOF_UNTRUSTED"),
            Self::TxidAlreadyInReceiverChain => write!(f, "E_TXID_ALREADY_IN_RECEIVER_CHAIN"),
            Self::ChequeClaimProofExpired => write!(f, "E_CHEQUE_CLAIM_PROOF_EXPIRED"),
            Self::StateNotAnchored => write!(f, "E_STATE_NOT_ANCHORED"),
        }
    }
}
// ============================================================================
// Wire types — moved from lambda/src/types.rs (UMP consolidation, 2026-05-10).
// Live here so ANTIE/Nabla/SDK can deserialize/serialize without maintaining
// mirror structs (the drift pattern that produced E_RECEIPT_COMMITMENT_MISMATCH
// 5+ times). See CLAUDE.md §13.
// ============================================================================

/// Witness request from Gateway
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessRequest {
    /// Request ID for correlation. SDK ships this on the email envelope
    /// header (`axiom_sdk::redeem::build_email`), NOT inside the CBOR
    /// body. `#[serde(default)]` keeps the typed deserialize from
    /// rejecting a body without the field; ANTIE substitutes
    /// `email.request_id` post-deserialize.
    #[serde(default)]
    pub request_id: String,

    /// The transaction to witness
    pub transaction: Transaction,

    /// Signatures from overlapped validators (for S-ABR)
    pub overlapped_signatures: Vec<WitnessSig>,

    /// Previous receipts proving prior state was legitimately consumed.
    /// REQUIRED — for genesis send the producer sends `Vec::new()`
    /// explicitly. No `#[serde(default)]`: if the field is absent from
    /// the wire payload, that's a producer bug we want surfaced (§13).
    pub prev_receipts: Vec<Receipt>,
    
    /// Client's claimed balance for S-ABR new-validator path.
    /// 
    /// SECURITY: This is NOT trusted blindly. Core cryptographically verifies it:
    /// Core computes produced_state_id using this balance, and compares against
    /// the hash that overlapped validators (who have the real balance from storage)
    /// already verified. If the client lies, the hashes won't match → TX rejected.
    /// 
    /// Only used when a NEW validator (not overlapped) processes a transaction.
    /// Overlapped validators IGNORE this and use their stored TransactionRecord.
    /// 
    /// Optimization: could be replaced with balance embedded in overlapped validator
    /// responses. Current approach is secure — Core verifies via SHA3-256 hash match.
    /// If client lies, state_id hash won't match and TX is rejected.
    #[serde(alias = "declared_balance")]
    pub claimed_balance_for_sabr: u64,

    /// YPX-020 — client's declared `hibernation_until` for the §15 anchor
    /// check, mirroring `claimed_balance_for_sabr`. NOT trusted blindly:
    /// Core's `verify_state_anchored` recomputes
    /// `compute_state_hash(pk, balance, seq, hibernation_until, wall_clock_lock)`
    /// and rejects unless it matches the k-signed `prev_receipt.state_hash`, so a
    /// wrong value (e.g. 0 to dodge the hibernation gate) fails the hash. REQUIRED
    /// because the overlap-relaxed HAL completion reaches FRESH validators
    /// that never stored the re-anchor's produced state — they cannot source
    /// the real `H` from local storage, so the client must declare it and
    /// Core verifies. 0 for every non-hibernating tx (omitted from the wire).
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub claimed_hibernation_until: u64,

    /// §5.2.2c — client's declared `wall_clock_lock` (the validator stake
    /// lock), the SECOND input `compute_state_hash` binds. Exists for exactly
    /// the same reason as `claimed_hibernation_until` above, and is safe for
    /// exactly the same reason: the anchor re-derive rejects any value that
    /// does not reproduce the k-signed `prev_receipt.state_hash`, so a holder
    /// cannot declare `0` to shed the lock.
    ///
    /// ⚠ THIS IS NOT THE LOCK'S ENFORCEMENT and must never become it. The lock
    /// is enforced by Lambda against ITS OWN stored row (`consensus.rs`
    /// STAKE-LOCKED gate) and by Core against the ATTESTED TICK — never by a
    /// number the client sent (RULE 5). This field only lets a validator
    /// RE-DERIVE a hash, which is why declaring it is harmless.
    ///
    /// Measured 2026-09-06: without it, both Lambda state views hardcoded `0`
    /// while the claim redeem's receipt bound the real `L`, so EVERY send from
    /// a stake-locked wallet died `E_STATE_NOT_ANCHORED` once its lock
    /// released — the release leg could never complete. Storage is not an
    /// alternative source: a FRESH validator in the round has no row for this
    /// wallet and would pass `0`, exactly as the HAL note above records for
    /// hibernation. 0 for every unstaked wallet (omitted from the wire).
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub claimed_wall_clock_lock: u64,
    pub claimed_emission_claimed_epoch: u64, // §4.2a — the sixth §15 field, same rule as the lock
    /// §6b.13 — the wallet's `stake_floor_until` and wallet-format block,
    /// DECLARED so a validator (even a fresh one with no row) can re-derive the
    /// §15 anchor, exactly like the lock above. Not the floor's enforcement: a
    /// lie changes the hash and `verify_state_anchored` refuses it; the floor
    /// itself is gated by Core against the anchored value. Mandatory.
    pub claimed_stake_floor_until: u64,
    pub claimed_wallet_format: WalletFormat,

    /// YPX-021 §8.2 — client-fetched Nabla OODS reading. ANTIE forwards
    /// verbatim (never strips — CLAUDE.md §12 mirror-struct rule); Lambda
    /// passes it into the CL2/CL3 `PublicInputs`; Core verifies and stamps
    /// the derived `OodsFlag` into the receipt. `None` on paths with no
    /// Nabla reading (heal, genesis claim, WASM webclient — Phase 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oods_attestation: Option<NablaOodsAttestation>,

    /// YPX-022 RECALL — Nabla recall attestation carried on the RECALL self-send wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recall_attestation: Option<RecallAttestation>,

    /// §10.0 FOB fee-claim — the pool/linkage attestation carried on the
    /// fee-claim self-send wire (Lambda copies it into `PublicInputs`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fob_claim_attestation: Option<FobClaimAttestation>,
    /// ╔═ BOOTSTRAP SUBSIDY — REMOVE WHEN POOLS DRAIN ═══════════════╗
    /// Design: AXIOM_DESIGN_ValidatorJoin.md §5.2.2b
    /// ╚═════════════════════════════════════════════════════════════╝
    /// The CLAIMANT's provisional VBC — the §5.2.2 binding that must exist
    /// BEFORE the funding. `None` on every path that is not a subsidy claim.
    ///
    /// ⚠ DISTINCT FROM `vbc_bundle`, which is the WITNESSING validator's
    /// credential — each witness carries its own, and nothing carried the
    /// CLAIMANT's. That absence is why the claim had no admission gate at all
    /// and three ordinary wallets drew 498.5 AXC each on 2026-09-02.
    ///
    /// Rides `PublicInputs`/`WitnessRequest`, NOT the canonical `Transaction`,
    /// so txids, receipt commitments and the signed tx bytes are untouched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimant_vbc: Option<VBCProofBundle>,

    /// ╔═════════════════════════════════════════════════════════════╗
    /// ║  THE CERTIFICATE THIS ROUND IS ASKING TO HAVE SIGNED         ║
    /// ║  Design: AXIOM_DESIGN_ValidatorJoin.md §5.2.2d               ║
    /// ╚═════════════════════════════════════════════════════════════╝
    /// The candidate's own UNSIGNED VBC (`target_vbc.signatures` empty),
    /// present ONLY on a `TxKind::VbcRequest` round. Each witness signs it
    /// via Core CL8 and returns a `VbcIssuerSignature`; the client combines
    /// three into a usable certificate.
    ///
    /// ⚠ DISTINCT FROM BOTH SIBLINGS, and the distinction is the whole point:
    ///   - `vbc_bundle`   — the WITNESSING validator's own credential.
    ///   - `claimant_vbc` — a credential being PRESENTED as admission (the
    ///                      §5.2.2b subsidy gate).
    ///   - `vbc_request`  — a certificate being REQUESTED, not yet valid.
    /// Carrying a requested cert in either sibling would let an unsigned
    /// self-authored VBC be read as a credential. Never merge these fields.
    ///
    /// Rides the envelope, NOT the canonical `Transaction`, so txids and
    /// receipt commitments are untouched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vbc_request: Option<VBCProofBundle>,

    /// YPX-001 §1.5.1 — scar-consent voucher carried on a re-initiated
    /// scarred send AFTER the generating validator verified the receiver's
    /// passcode (hop 1 of the retry round). Later overlapped hops verify
    /// the issuer signature against this request's prev-receipt witness
    /// set and skip the gate. `None` on every non-consent send.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scar_consent_voucher: Option<ScarConsentVoucher>,

    /// Requester's address. SDK doesn't ship this in the body — ANTIE
    /// substitutes `email.from` post-deserialize. `#[serde(default)]`
    /// for the same reason as `request_id`.
    #[serde(default)]
    pub requester_address: String,

    /// Offered fee in atoms
    #[serde(default)]
    pub offered_fee: u64,

    /// Validator hints from requester (YP §27). SDK conditionally
    /// ships when the wallet has hints worth relaying (empty hint
    /// list is omitted by `relay_validator_hints_cbor`).
    /// `#[serde(default)]` so an honest empty-hints body decodes.
    #[serde(default)]
    pub validator_hints: Vec<ValidatorHint>,
    
    /// The produced_state_id computed by Core (CL2) at Gateway
    /// Lambda MUST use this value, NOT compute its own!
    /// This ensures only Core computes state_ids
    #[serde(default)]
    pub produced_state_id: Option<Vec<u8>>,
    
    /// The commitment_hash computed by Core (CL2) at Gateway
    /// Lambda MUST use this for signing — Core computes, Lambda signs.
    #[serde(default)]
    pub commitment_hash: Option<Vec<u8>>,
    
    /// Member index for group wallet withdrawal (group wallet TX only)
    /// Passed through to Core's PublicInputs.group_member_index
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_member_index: Option<usize>,
    
    /// Client's FACT chain — money provenance history (YPX-001 §1.6).
    /// The FACT chain is CARRIED BY THE CLIENT, not stored by validators.
    /// Client includes this in every witness request. Validators:
    ///   1. Verify it (Core CL3)
    ///   2. Sign FACT commitment (witness role)
    ///   3. Build updated chain at k=3 → return in WitnessResponse.sender_fact_chain
    ///   4. Attach to cheque for receiver
    ///      Validators do NOT store FACT chains. S-ABR stores tx records for balance verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_fact_chain: Option<FactChain>,

    /// YP §26.17.6.5 B4 (2026-09-11) — the certificate bundles the client holds
    /// for `sender_fact_chain`'s witnesses (from its receipts and the cheques it
    /// received), so the validator can present them to Core. The validator
    /// completes the set from its own store; Core verifies what it is handed and
    /// refuses what it is not.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fact_certificates: Vec<VBCProofBundle>,

    /// Client's CL1 execution proof (ZKP proving client ran Core locally).
    /// CL1 is mandatory everywhere (post-v2.13). ANTIE passes this through
    /// without inspection — Core/Lambda verifies.
    ///
    /// `#[serde(default)]` because the SDK conditionally omits the field
    /// when the proof is empty (`build_witness_payload_cbor_v3` only
    /// pushes when `proof.is_empty() == false`). The typed deserialize
    /// would otherwise reject every witness round with no proof yet —
    /// the genesis-claim path produces the proof only after the
    /// witness round completes. Lambda's own CL1 mandate is the
    /// authoritative check, not this wire constraint.
    #[serde(default)]
    pub cl1_execution_proof: Vec<u8>,

    /// §17.11: auth_hash carried on a genesis claim, stored by Lambda into
    /// `WalletState.auth_hash`. Since 2026-09-25 (KI#108, `owner_proof`
    /// deleted) Core verifies nothing against it — see `WalletState::auth_hash`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_hash: Option<Vec<u8>>,

    /// §23.14: Audit confirmation from client (carrying target validator's response).
    /// Client received AuditDemand in a prior WitnessResponse, carried it to the
    /// target validator, and now returns AuditConfirmation for Lambda to pass to Core.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_confirmation: Option<AuditConfirmation>,

    /// YPX-009: Nonce response from Lambda (answer to prior NonceChallenge).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_response: Option<NonceResponse>,

    /// YPX-009: Audit response from Lambda (re-executed TXs chain hash).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_response: Option<PulseAuditResponse>,

    /// YPX-002 §3.2 — sender's designated (sticky) Nabla node.
    /// The sender pre-declares which Nabla node it will register with;
    /// each witnessing validator stamps this into the `nabla_hint` field
    /// of the `ValidatorCheque` it issues. The receiver reads it from the
    /// cheque and queries that node first (per §4.2 step 2). Sender and
    /// receiver never communicate directly — the validator is the courier.
    /// Lambda treats this as opaque pass-through; Core never validates it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nabla_hint: Option<NablaHint>,

    /// YPX-018 — CLARA attestation. When present, Lambda forwards this to
    /// Core CL2 which verifies the Nabla signature, the wallet binding, and
    /// the eligibility (validator's stored state == `healed_to_state_id`,
    /// KI#260). Lambda writes no CLARA state.
    /// See YPX-018 §2.3 and Yellow Paper §17.10.14.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clara_attestation: Option<ClaraAttestation>,
}

/// Witness response to Gateway
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessResponse {
    /// Request ID for correlation
    pub request_id: String,
    
    /// Whether witnessing succeeded
    pub success: bool,
    
    /// Our witness signature (if success)
    pub witness_signature: Option<WitnessSig>,
    
    /// All collected signatures (for sender's record)
    pub overlapped_signatures: Vec<WitnessSig>,
    
    /// Rejection reason (if !success)
    pub rejection: Option<RejectionInfo>,
    
    /// The ValidatorCheque to send to receiver (if success)
    /// Gateway should deliver this to receiver via ANTIE
    pub cheque_for_receiver: Option<ValidatorCheque>,

    /// This issuer's CL8 signature over the requested certificate — the
    /// `TxKind::VbcRequest` round's product, returned WHERE A CHEQUE WOULD
    /// GO on a normal send and never alongside one.
    ///
    /// the owner's ruling (§5.2.2d): a VBC request is an ORDINARY transaction, so
    /// the flow is the flow — same witness round, same k, same anchoring. Only
    /// the artifact differs, and it carries no value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vbc_signature: Option<VbcIssuerSignature>,
    
    /// The complete receipt for sender's records (if success and k reached)
    pub receipt: Option<Receipt>,
    
    /// The produced state_id after this transaction (for client state tracking)
    /// Client MUST use this as consumed_state_id for their next transaction
    #[serde(default)]
    pub produced_state_id: Option<Vec<u8>>,
    
    /// The commitment_hash computed by Core (CL2) that this validator signed.
    /// Returned on EVERY successful witness response (not just k=3 receipt).
    /// Client uses this to build receipts with non-zero commitment_hash.
    #[serde(default)]
    pub commitment_hash: Option<Vec<u8>>,

    /// State hash computed by Core (CL2/CL3) for this transaction.
    /// Top-level (mirrors commitment_hash) so the SDK can reconstruct
    /// receipt_commitment locally for partial-commit shapes where
    /// `receipt: Option<Receipt>` is None (k<3 path produces no
    /// finalised Receipt). Returned on every successful witness
    /// response, not just at k=3.
    #[serde(default)]
    pub state_hash: Option<Vec<u8>>,

    /// YP §32.3 — the sender-lineage Core CL5 bound into `receipt_commitment`
    /// (`received_from:state_id`). Top-level (mirrors `state_hash`) so the SDK
    /// adopts Core's AUTHORITATIVE value when it rebuilds the redeem receipt,
    /// rather than recomputing it — a diverging value would make the SDK's
    /// stored receipt_commitment mismatch the k-signed one and fail the NEXT
    /// send's CL2 prev_receipt verify. `None` on every non-redeem.
    #[serde(default)]
    pub sender_state: Option<Vec<u8>>,

    /// Receipt commitment computed by Core (CL3) — BLAKE3 over the
    /// six receipt input fields (txid || state_hash || produced_state_id
    /// || new_wallet_seq || commitment_hash || epoch). Top-level so
    /// the SDK embeds it in receipts built for prev_receipts use,
    /// including partial-commit receipts where Core CL3 always
    /// produces this value but Lambda's full Receipt isn't yet
    /// finalised. See `core/logic/src/crypto.rs::compute_receipt_commitment`.
    #[serde(default)]
    pub receipt_commitment: Option<Vec<u8>>,

    /// Transaction ID (BLAKE3 of canonical transaction bytes), exposed
    /// top-level so the SDK can build partial-commit receipts on the
    /// V1/V2 path where `receipt: Option<Receipt>` is None. Both V1/V2
    /// and V3 finalize paths populate this; receivers MUST compare it
    /// against `cheque.txid` for sanity. No `#[serde(default)]` —
    /// missing = producer bug.
    pub txid: Vec<u8>,

    /// Validator hints from this validator (1-3 required).
    /// Per Yellow Paper Section 27: Every witness response MUST include hints.
    /// No `#[serde(default)]`: missing on the wire = producer bug (§13).
    pub validator_hints: Vec<ValidatorHint>,
    
    /// Sender's updated FACT chain after this transaction (YPX-001).
    /// Only present when k=3 reached (overlapped validator builds the chain).
    /// Client includes this in ChequeBundle.fact_chain for the receiver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_fact_chain: Option<FactChain>,

    /// §23.14: Audit demand from Core — client must carry this to the target
    /// validator and return AuditConfirmation in a subsequent WitnessRequest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_demand: Option<AuditDemand>,

    /// YPX-009: Audit request from AVM — Lambda must re-execute selected TXs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_request: Option<PulseAuditRequest>,

    /// YPX-009: Nonce challenge from AVM — Lambda must respond with NonceResponse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_challenge: Option<NonceChallenge>,

    /// YPX-009: Pulse proof data from AVM after successful audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pulse_proof: Option<PulseProofData>,

    /// YPX-009: AVM detected audit failure — Lambda should log and restart.
    #[serde(default)]
    pub audit_failed: bool,

    /// §23.14.6: Outbound peer-audit request to send via ANTIE email.
    /// When Core demands a peer-audit and Lambda has the target's email,
    /// this is populated so Gateway can build and send the email.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_peer_audit: Option<OutboundPeerAudit>,

    /// §11.5: Confidence Index for the sender's wallet.
    /// Issued by this validator on every successful TX. Client stores this
    /// and presents it during offline ⟠ Ark trades for risk assessment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_index: Option<ConfidenceIndex>,

    /// YPX-001 §1.5.1: Scar-consent notification (receiver informed consent).
    /// Populated ONLY on the gate-fire rejection shape (`success = false`,
    /// rejection code `E_LAMBDA_SCAR_CONSENT_REQUIRED`) by the overlapped
    /// validator. Gateway (ANTIE) MUST deliver this to the RECEIVER's mailbox
    /// (like `cheque_for_receiver`) and MUST NOT forward it to the sender —
    /// the passcode travels receiver → sender out-of-band, that is the
    /// consent. Host-wire plumbing only: never read inside guest Core.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scar_consent_for_receiver: Option<ScarConsentNotification>,

    /// YPX-001 §1.5.1: consent voucher issued to the SENDER by the
    /// passcode-verifying validator on the successful verify hop. The
    /// sender's SDK attaches it to the round's remaining witness requests
    /// (`WitnessRequest.scar_consent_voucher`) so the other overlapped
    /// validators can verify consent instead of re-gating. Forwarded to
    /// the sender by ANTIE (unlike `scar_consent_for_receiver`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scar_consent_voucher: Option<ScarConsentVoucher>,
}

/// ANTIE's mail-reply envelope — the ONE reply shape for every message type
/// (witness, redeem, query, VSP, genesis, ACK, VBC sign, scar heal, …), read
/// by key by the SDK machines and Python. Lives in Core since KI#173
/// (2026-09-15): until then ANTIE kept its own copy and rebuilt it from
/// `WitnessResponse` field by field, which dropped `sender_state`.
///
/// Wire-format note: payload fields that contain `Vec<u8>` byte sequences
/// (validator_pk, signature, state_id, etc.) used to be typed as
/// `serde_json::Value` and converted via `serde_json::to_value(...)` from
/// the typed Lambda response. That intermediate flattened CBOR `Bytes` to
/// JSON integer arrays and then back to CBOR Array<u8> on the wire — a
/// lossy bandaid that masked byte-string corruption (rule #13 / two-day
/// debug, May 2026). All payload fields now carry their typed
/// `axiom_core_logic` structs so byte fields stay as CBOR `Bytes` end to
/// end. The SDK's CBOR reader handles both shapes via `cbor_to_bytes`,
/// so old `Array<u8>`-encoded responses still parse during the rollover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePayload {
    /// Success flag
    pub success: bool,

    /// Request ID echoed back
    pub request_id: String,

    /// Witness signature (if successful)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_signature: Option<WitnessSig>,

    /// Cheque for receiver (ValidatorCheque - needed for redemption)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cheque_for_receiver: Option<ValidatorCheque>,

    /// YPX-001 §1.5.1 — scar-consent voucher for the SENDER, issued by the
    /// passcode-verifying validator. The sender's SDK attaches it to the
    /// round's remaining witness requests so the other overlapped validators
    /// verify consent instead of re-gating. Forwarded verbatim (unlike the
    /// receiver-bound notification, which never rides the sender leg).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scar_consent_voucher: Option<ScarConsentVoucher>,

    /// ╔═══════════════════════════════════════════════════════════════╗
    /// ║  §5.2.2d — THE CERTIFICATE GOES TO THE REQUESTER              ║
    /// ╚═══════════════════════════════════════════════════════════════╝
    /// This issuer's CL8 signature over a `TxKind::VbcRequest` round's
    /// certificate.
    ///
    /// ⚠ IT MUST BE FORWARDED EXPLICITLY, and that is the whole point of this
    /// field existing here. ANTIE does NOT pass Lambda's `WitnessResponse`
    /// through — it REBUILDS a client-facing `ResponsePayload` field by field,
    /// so anything not named here is silently dropped at the carrier.
    ///
    /// That is exactly what happened on 2026-09-03: three issuers signed the
    /// certificate (Lambda logged all three), and the client collected ZERO.
    /// Nothing was broken in the issuing or the collecting — the artifact
    /// simply never left the validator. Same class as
    /// [[feedback_antie_cbor_preservation]].
    ///
    /// Unlike `cheque_for_receiver` (§17.9: delivered to the RECEIVER, never
    /// echoed to the sender), a certificate has no receiver — the requester IS
    /// the subject, so it comes back on this reply, like the scar-consent
    /// voucher above.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vbc_signature: Option<VbcIssuerSignature>,

    /// Produced state_id (sender's new state after witness, receiver's new state after redeem)
    /// Client MUST use this as consumed_state_id for their next transaction
    #[serde(skip_serializing_if = "Option::is_none")]
    pub produced_state_id: Option<Vec<u8>>,

    /// Receipt (if k=3 reached)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Receipt>,

    /// The commitment_hash computed by Core — returned on every successful witness
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment_hash: Option<Vec<u8>>,

    /// State hash computed by Core (CL2/CL3) — top-level so the SDK can
    /// rebuild receipt_commitment locally for partial-commit receipts.
    /// Pre-fix this field was missing from ResponsePayload, so ANTIE
    /// silently dropped Lambda's value during the deserialize→re-serialize
    /// hop. SDK then wrote receipts with state_hash=[0u8;32], and Core's
    /// strict-mode CL2 (post-4a81a34) rejected with
    /// E_RECEIPT_COMMITMENT_MISMATCH on the next send. CLAUDE.md §13.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_hash: Option<Vec<u8>>,

    /// Receipt commitment computed by Core (CL3) — top-level so the SDK
    /// embeds it in receipts (especially partial-commit receipts where
    /// Lambda's full Receipt isn't yet finalised). Same drop-by-mirror-drift
    /// fix as state_hash above.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_commitment: Option<Vec<u8>>,

    /// Transaction ID — top-level on every successful witness response so
    /// the SDK can build partial-commit receipts on the V1/V2 path where
    /// `receipt: Option<Receipt>` is None. Required field on success
    /// responses (no serde default — missing = producer bug, surface it).
    /// Optional only because rejection / non-success responses don't have
    /// a txid to forward.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txid: Option<Vec<u8>>,

    /// State ID (for genesis responses)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_id: Option<Vec<u8>>,

    /// Error message (if failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Rejection code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_code: Option<String>,

    /// Lambda's structured ErrorResponse forwarded verbatim on rejection
    /// (Phase 2 canonical). Carries the protocol-defined `code`,
    /// `message`, `category`, and `recovery` hint. Clients dispatch
    /// on `recovery` for state-drift handling. Pre-fix ANTIE flattened
    /// the structured response into the `error` string and the SDK lost
    /// the recovery hint entirely — w024 retry-loop bug observed in the
    /// v3.0.0-beta5 soak (task #63).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_response: Option<axiom_errors::ErrorResponse>,

    /// Validator hints — included in ALL responses (YP §27 peer discovery)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub validator_hints: Vec<ValidatorHint>,

    /// Updated sender FACT chain (YPX-001 §1.6) — only present when k=3 reached
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_fact_chain: Option<FactChain>,

    /// Updated receiver FACT chain after redeem (YPX-001 §1.6)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver_fact_chain: Option<FactChain>,

    /// This validator's Dilithium FACT signature on the redeem link's
    /// commitment. The SDK collects k of these to build the receiver's
    /// redeem FactLink. Only present on redeem responses (None on
    /// witness/heal/etc).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fact_signature: Option<Vec<u8>>,

    /// Free-form metadata for non-protocol responses — query (wallet
    /// state lookup), VSP (validator status). The map's keys are per
    /// response type. A CBOR value (KI#173: Core has no `serde_json`, and
    /// the protocol path is CBOR end to end); the maps ANTIE builds hold
    /// ints, strings and integer arrays, so the bytes equal the former
    /// `serde_json::Value` encoding. Witness / redeem responses leave this
    /// `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_data: Option<ciborium::Value>,

    /// YP §32.3 — the sender lineage Core bound into `receipt_commitment`,
    /// forwarded from `WitnessResponse::sender_state` by
    /// [`ResponsePayload::sender_leg`]. Before KI#173 ANTIE's copy of this
    /// envelope had no such field, so the carrier dropped it. `None` on
    /// every reply that has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_state: Option<Vec<u8>>,
}

impl ResponsePayload {
    /// The ONE conversion from Lambda's `WitnessResponse` to the reply that
    /// goes back to the SENDER (KI#173). Every field the sender's SDK reads is
    /// carried by name here, beside both types, so a field added to one is in
    /// view of the other.
    ///
    /// Deliberately NOT carried — each goes elsewhere or nowhere:
    /// - `cheque_for_receiver` — §17.9: delivered to the RECEIVER's mailbox,
    ///   never echoed to the sender.
    /// - `scar_consent_for_receiver` — YPX-001 §1.5.1: the passcode travels
    ///   receiver → sender out of band; that is the consent.
    /// - `vbc_signature` — §5.2.2f (RULED 2026-09-09): the certificate is a
    ///   DELIVERY by the cheque route to the stake wallet's mailbox, not a
    ///   reply.
    /// - `overlapped_signatures`, `audit_*`, `nonce_challenge`, `pulse_proof`,
    ///   `outbound_peer_audit`, `confidence_index` — Lambda/ANTIE-side
    ///   plumbing the sender leg never carried.
    ///
    /// A rejection travels as `error` (message) + `rejection_code` (code);
    /// `WitnessResponse` has no structured `ErrorResponse` (KI#157).
    pub fn sender_leg(w: WitnessResponse) -> Self {
        let (error, rejection_code) = match w.rejection {
            Some(r) => (Some(r.message), Some(r.code)),
            None => (None, None),
        };
        ResponsePayload {
            success: w.success,
            request_id: w.request_id,
            witness_signature: w.witness_signature,
            cheque_for_receiver: None,
            scar_consent_voucher: w.scar_consent_voucher,
            vbc_signature: None,
            produced_state_id: w.produced_state_id,
            receipt: w.receipt,
            commitment_hash: w.commitment_hash,
            state_hash: w.state_hash,
            receipt_commitment: w.receipt_commitment,
            txid: Some(w.txid),
            state_id: None,
            error,
            rejection_code,
            error_response: None,
            validator_hints: w.validator_hints,
            sender_fact_chain: w.sender_fact_chain,
            receiver_fact_chain: None,
            fact_signature: None,
            query_data: None,
            sender_state: w.sender_state,
        }
    }
}

/// YPX-001 §1.5.1: consent voucher issued by the passcode-verifying validator.
///
/// Under S-ABR every prior witness is "overlapped", so up to k validators
/// independently run the scar-consent gate — but the 6-digit passcode is
/// stored only at the validator that generated it. After that validator
/// verifies the receiver's passcode (single-use, consumed on match), it
/// signs this voucher over the txid; the SENDER carries it to the round's
/// remaining hops, each of which verifies the Ed25519 signature against the
/// prev-receipt witness set it already validates (client-carried, no
/// cross-validator state, no new trust edge — "one of MY OWN prior
/// witnesses attests the receiver consented"). A bare `scar_passcode`
/// without a voucher NEVER skips the gate, so a fabricated passcode cannot
/// bypass consent at any validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScarConsentVoucher {
    /// Txid of the consented transaction (passcode-independent).
    pub txid: [u8; 32],
    /// Issuing validator's id (must appear in the tx's prev-receipt
    /// witness set — that is what makes it verifiable by peers).
    pub validator_id: [u8; 32],
    /// Ed25519 signature by the issuer's witness key over
    /// `compute_scar_consent_voucher_payload(txid)`.
    pub signature: Vec<u8>,
}

/// YPX-001 §1.5.1: Scar-consent notification (validator → receiver via ANTIE).
///
/// "Incoming payment of {amount} from {sender}. This money has {scar_count}
/// unverified link(s) in its provenance. If you accept, your wallet inherits
/// these scars. Passcode: {passcode}." The receiver ACCEPTS by giving the
/// sender the passcode out-of-band; the sender re-initiates the same tx
/// (same txid — `compute_txid` excludes `scar_passcode`) with the passcode
/// set. REJECT = do nothing; the paused TX was never witnessed and dies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScarConsentNotification {
    /// Txid of the paused transaction (BLAKE3, passcode-independent).
    pub txid: [u8; 32],
    /// Sender's wallet_id (as carried on the paused tx).
    pub sender_wallet_id: String,
    /// Receiver's wallet_id (delivery target).
    pub receiver_wallet_id: String,
    /// Amount of the paused transaction (atoms).
    pub amount: u64,
    /// Number of unresolved (non-Ark) links in the sender's provenance.
    pub scar_count: u32,
    /// 6-digit consent passcode generated + stored by the overlapped
    /// validator. Single-use: deleted on first successful verification.
    pub passcode: u32,
}

/// §23.14.6: Outbound peer audit request data (piggybacked on WitnessResponse).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundPeerAudit {
    /// The PeerAuditRequest to send (txid + expected_hash + challenge_nonce + our PK)
    pub request: PeerAuditRequest,
    /// Target validator's email address (resolved from hints)
    pub target_email: String,
}

/// Rejection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectionInfo {
    pub code: String,
    pub message: String,
}


/// Redeem response to Gateway
/// 
/// Contains this validator's witness signature for receiver's new state.
/// Receiver must collect k such responses to finalize their balance update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedeemResponse {
    /// Request ID for correlation
    pub request_id: String,
    
    /// Whether this validator accepted the redemption
    pub success: bool,
    
    /// New balance after redemption (if success)
    pub new_balance: Option<u64>,
    
    /// New state_id (if success)
    pub new_state_id: Option<[u8; 32]>,
    
    /// This validator's witness signature (if success)
    /// Receiver needs k of these to prove their balance update
    pub witness_signature: Option<WitnessSig>,
    
    /// The commitment_hash that was signed (for receiver's receipt)
    #[serde(default)]
    pub commitment_hash: Option<Vec<u8>>,

    /// State hash computed by Core during redeem CL5 — top-level so
    /// the receiver SDK can rebuild receipt_commitment locally for
    /// the redeem receipt. Mirror of WitnessResponse.state_hash;
    /// without it the receiver writes a redeem receipt with
    /// state_hash=[0u8;32] and the next send fails CL2 with
    /// E_RECEIPT_COMMITMENT_MISMATCH (same drop-by-mirror-drift
    /// pattern as the witness path; CLAUDE.md §13).
    #[serde(default)]
    pub state_hash: Option<Vec<u8>>,

    /// Receipt commitment computed by Core during redeem CL5 — Core
    /// always produces this in strict mode (post-4a81a34). Receiver
    /// stores it in the redeem receipt for use as prev_receipts on
    /// the next send.
    #[serde(default)]
    pub receipt_commitment: Option<Vec<u8>>,

    /// Structured error response. Populated on every failure,
    /// `None` on success. See `docs/AXIOM_YellowPaper_Errors.md`.
    /// Clients MUST read this to get the failure reason — the legacy
    /// `error: Option<String>` field was removed in Phase 2b.15.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_response: Option<axiom_errors::ErrorResponse>,

    /// Validator hints from this validator (1-3 required)
    #[serde(default)]
    pub validator_hints: Vec<ValidatorHint>,

    /// This validator's FACT signature for the redeem transaction (YPX-001).
    /// Signs: BLAKE3("AXIOM_FACT" || tx_id || prev_state_id || new_state_id || amount)
    /// Receiver uses this when they later send funds (proves FACT continuity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fact_signature: Option<Vec<u8>>,
    
    /// Receiver's updated FACT chain after redeem (YPX-001 §1.6).
    /// Contains the sender's chain (from cheque) plus the new redeem link.
    /// Client stores this and includes it in future WitnessRequest.sender_fact_chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver_fact_chain: Option<FactChain>,
}

// ============================================================================
// Lambda IPC types — moved from lambda/src/types.rs (UMP consolidation,
// 2026-05-10). All wire types between Gateway/ANTIE/SDK ↔ Lambda live
// here so there is exactly ONE definition. Mirror-drift is structurally
// impossible. See CLAUDE.md §13.
// ============================================================================
/// State query request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateQueryRequest {
    pub request_id: String,
    pub wallet_pk: Vec<u8>,
}

// ============================================================================
// VSP — Validator Status Protocol (YPX-008)
// ============================================================================

/// VSP query request — client asks a validator for its status + known peers.
/// Free service, no authentication required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorStatusRequest {
    pub request_id: String,
}

/// VSP query response — validator returns its public profile + peer referrals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorStatusResponse {
    pub request_id: String,
    /// Validator's human-friendly name (from VBC node_name)
    pub validator_name: String,
    /// Validator unique ID (hex-encoded)
    pub validator_id: String,
    /// Proof capability: "dmap" or "zkvm"
    pub proof_cap: String,
    /// Carrier URIs for reaching this validator
    pub carriers: Vec<String>,
    /// Core version string (e.g., "Kyoto/1.1/GENESIS")
    pub core_version: String,
    /// Uptime in seconds since process start
    pub uptime_secs: u64,
    /// Total transactions witnessed (sender side)
    pub witness_count: u64,
    /// Total transactions redeemed (receiver side)
    pub redeem_count: u64,
    /// `zkp_qualification.is_some()` — DERIVED, never set independently (YPX-007 §9.5).
    pub zkp_qualified: bool,
    /// 3 known peer validators (for client routing/discovery)
    pub known_validators: Vec<ValidatorHint>,
    /// Fee rate in basis points (1 bps = 0.01%). 50 = 0.50%.
    #[serde(default)]
    pub fee_rate_bps: u32,
    /// Unix timestamp when fee schedule expires (0 = no expiry)
    #[serde(default)]
    pub fee_valid_until: u64,
    /// Minimum fee in atoms
    #[serde(default)]
    pub fee_min_amount: u64,
    /// Operator jurisdiction (ISO 3166-1 alpha-2, e.g., "SG", "US", or "NONE")
    #[serde(default)]
    pub jurisdiction: String,
    /// Operator name/organization (self-reported, not protocol-verified)
    #[serde(default)]
    pub operator_name: String,
    /// Operator contact (optional)
    #[serde(default)]
    pub operator_contact: String,
    /// Supported encryption for cheque delivery (e.g., "PGP", "GPG", "none")
    /// Clients with matching encryption suffix (-P, -G) in their wallet_id
    /// can expect encrypted cheque emails from this validator.
    #[serde(default)]
    pub supported_encryption: String,
    /// Encryption public key (e.g., PGP/GPG public key block, base64-encoded)
    /// Clients can use this to encrypt messages TO this validator.
    #[serde(default)]
    pub encryption_public_key: String,
    /// Validator's current stake in AXC atoms (from bound wallet).
    /// Public — clients can verify the validator meets tier requirements.
    #[serde(default)]
    pub stake: u64,
    /// Free-text notes from the validator operator (e.g., maintenance schedule,
    /// service announcements, terms of service URL)
    #[serde(default)]
    pub notes: String,
    /// L$ digit_version (White Paper §J.14-J.18). Presentation-only.
    /// 0 = 1 AXC = 1 L$. N = 1 AXC = 10^N L$. Console-managed.
    #[serde(default)]
    pub digit_version: u8,
    /// YPX-007 §9.5 (KI#125) — the Core-signed startup-benchmark record; `None` =
    /// not qualified (no prover, Nabla unreachable, too slow). A wallet re-checks it
    /// with `validation::verify_zkp_qualification_record`; a preference, never a gate.
    #[serde(default)]
    pub zkp_qualification: Option<ZkpQualificationRecord>,
}

/// State query response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateQueryResponse {
    pub request_id: String,
    pub found: bool,
    pub wallet_state: Option<StoredWalletState>,
}

/// Stored wallet state (Lambda's view)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredWalletState {
    /// Public key
    pub public_key: Vec<u8>,
    
    /// Current balance in atoms
    pub balance: u64,
    
    /// Current wallet sequence number
    pub wallet_seq: u64,
    
    /// Current state ID
    pub state_id: [u8; 32],
    
    /// Last transaction ID
    pub last_tx_id: Option<[u8; 32]>,
    
    /// State status: PENDING (awaiting ACK) or CONFIRMED (committed)
    /// Wallet state status: PENDING after witness, CONFIRMED after ACK (fee paid).
    /// Pending states are valid for subsequent transactions (balance/state_id usable)
    /// but the consumed_state_id is only marked permanent at ACK time.
    #[serde(default = "default_status")]
    pub status: WalletStateStatus,
    
    /// Group wallet members (None for personal wallets)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_members: Option<Vec<GroupMember>>,
    
    /// Mirror of `WalletState::auth_hash` — stored by Lambda, read by nothing in
    /// Core since `owner_proof` was deleted 2026-09-25 (KI#108). NOT stolen-key
    /// protection (the key derives from the wallet private key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_hash: Option<[u8; 32]>,

    /// Canonical wallet_id bound to this public key (identity binding).
    /// Set from tx.sender_wallet_id on the first transaction; immutable thereafter.
    /// Passed to Core in WalletState so Core can enforce sender_wallet_id consistency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_id: Option<String>,

    /// YPX-020 — persisted hibernation tick (see `WalletState::hibernation_until`).
    /// Persisted so a node restart cannot un-hibernate a wallet (restart-bypass).
    #[serde(default)]
    pub hibernation_until: u64,

    /// §5.2.2c — the persisted wall-clock lock (see `WalletState::wall_clock_lock`).
    ///
    /// ⚠ ADDED 2026-09-05, AND ITS ABSENCE WAS A REAL DEFECT, not an omission.
    /// Lambda is the ONLY layer that knows a wallet's stored state, and it did not
    /// carry this value — every Lambda site built `WalletState { wall_clock_lock:
    /// 0, .. }`. Two consequences, both live:
    ///
    ///   1. Core's §15 anchor check recomputes `compute_state_hash` from the
    ///      PRESENTED state. With 0 against a receipt k-signed over the REAL lock
    ///      the hashes differ, so a staked wallet's NEXT transaction dies with
    ///      `StateNotAnchored` — the wallet-side fix (Core returns it, the wallet
    ///      persists it) closed only HALF the carrier.
    ///   2. Core's release gate keys on `wall_clock_lock != 0` to tell a
    ///      time-released stake lock from an action-released hibernation. Read as
    ///      0, a staked wallet is judged by the wrong rule entirely.
    ///
    /// NO `serde(default)` (RULE 13): a missing value here is exactly the silent
    /// zero that caused the above. The rotation carrying this field wipes state,
    /// so there is no old row to be compatible with.
    pub wall_clock_lock: u64,
    /// §4.2a — the stored twin of `WalletState::emission_claimed_epoch`.
    #[serde(default)]
    pub emission_claimed_epoch: u64,
    /// §6b.13 — the stored twin of `WalletState::stake_floor_until`. Mandatory.
    pub stake_floor_until: u64,
    /// §6b.13 — the stored twin of `WalletState::wallet_format`. Mandatory.
    pub wallet_format: WalletFormat,
}

/// Wallet state status for pending/confirmed tracking
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum WalletStateStatus {
    /// State is committed and valid
    #[default]
    Confirmed,
    /// State is pending ACK from client
    Pending,
}

fn default_status() -> WalletStateStatus {
    WalletStateStatus::Confirmed
}

/// Transaction record for S-ABR overlap lookup
/// 
/// Each validator stores a record for every transaction they witness.
/// Lookup is by `produced_state_id` - when a new transaction arrives,
/// we check if we have a record where `produced_state_id` matches
/// the new transaction's `consumed_state_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    /// Transaction ID
    pub tx_id: [u8; 32],
    
    /// The state_id produced by this transaction
    /// This is the KEY for lookup - next tx's consumed_state_id
    pub produced_state_id: [u8; 32],
    
    /// Wallet public key (for TX_ID collision verification)
    pub wallet_pk: Vec<u8>,
    
    /// Balance after this transaction
    pub balance_after: u64,
    
    /// Wallet sequence after this transaction
    pub wallet_seq_after: u64,
    
    /// Group members after this transaction (post-deduction)
    /// Needed for S-ABR: next TX's overlapped validators must know
    /// the correct group_members to pass to Core for checksum validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_members_after: Option<Vec<GroupMember>>,
    
    /// Whether this was a genesis claim TX (§17.11).
    /// Genesis claims are self-sends that are allowed to self-redeem.
    #[serde(default)]
    pub is_genesis_claim: Option<bool>,

    /// Status: PENDING until ACK, then CONFIRMED
    pub status: WalletStateStatus,

    /// YPX-007: Required k for this transaction (Core-extracted from receiver address).
    /// Persisted so next TX's S-ABR overlap can use the previous TX's k.
    #[serde(default)]
    pub required_k: u8,

    /// YPX-007: Proof type for this transaction (0=ZKP, 1=DMAP, 2=Ark).
    #[serde(default)]
    pub proof_type: u8,

    /// Transaction amount (self-audit: Core verifies Lambda stored correct amount).
    #[serde(default)]
    pub amount: u64,

    /// Sender balance BEFORE this transaction (self-audit: Core needs pre-TX balance
    /// to rebuild TxDigest for Argon2id→BLAKE3 chain replay).
    #[serde(default)]
    pub sender_balance: u64,
}

impl From<StoredWalletState> for WalletState {
    fn from(s: StoredWalletState) -> Self {
        WalletState {
            // ⚠ Was `wall_clock_lock: 0` — a converted state shed the stored lock
            // (the silent-zero shape `StoredWalletState::wall_clock_lock`'s doc
            // records). Corrected 2026-10-01 while adding the §6b.13 fields beside
            // it: every §15 field carries across.
            wall_clock_lock: s.wall_clock_lock,
            emission_claimed_epoch: s.emission_claimed_epoch,
            stake_floor_until: s.stake_floor_until,
            wallet_format: s.wallet_format,
            public_key: s.public_key,
            balance: s.balance,
            wallet_seq: s.wallet_seq,
            state_id: s.state_id,
            auth_hash: s.auth_hash,
            wallet_id: s.wallet_id,
            group_members: s.group_members,
            hibernation_until: s.hibernation_until,
        }
    }
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub core_connected: bool,
    pub pending_transactions: usize,
}

/// Redeem request from Gateway (NEW MODEL)
/// 
/// Receiver brings k cheques (from sender's validators) to this validator
/// to have their balance updated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedeemRequestEnvelope {
    /// Request ID for correlation. The SDK ships this on the email
    /// envelope header (see `axiom_sdk::redeem::build_email`), NOT
    /// inside the CBOR body — `#[serde(default)]` keeps the typed
    /// deserialize from rejecting a body without the field. ANTIE's
    /// `gateway::handle_redeem_request` substitutes
    /// `email.request_id` after deserializing the typed envelope.
    #[serde(default)]
    pub request_id: String,
    
    /// The bundle of k cheques from sender's validators
    pub cheque_bundle: ChequeBundle,
    
    /// Receiver's public key
    pub receiver_pk: Vec<u8>,
    
    /// Receiver's current wallet state (if exists)
    pub current_state: Option<WalletState>,
    
    /// The receiver's LAST k-signed receipt — the anchor of its declared
    /// `current_state` (Fable review 2026-10-01 F-1(b), YP §17.3.1.4 / §15).
    /// SAME name, type and meaning as [`WitnessRequest::prev_receipts`]: Core
    /// CL5 (`modes::cl5_anchor_receiver_state`) verifies it with the ONE
    /// per-receipt verifier (`validation::verify_anchor_receipt`), re-derives the
    /// declared state from it (§15 `verify_state_anchored`), and runs S-ABR
    /// overlap against its witnesses. A returning receiver ships EXACTLY ONE (its
    /// last receipt); a first-time receiver (its OPENING state, `WalletState::is_opening_state`)
    /// ships NONE — Core refuses either shape mismatch
    /// (`E_RECEIVER_STATE_NOT_ANCHORED`). MANDATORY on the wire (no
    /// `serde(default)`, RULE 13); bound into the CL5 attestation input hash
    /// (`cl5_inputs::build_cl5_attestation_inputs`).
    ///
    /// ⚠ REPLACED `overlapped_signatures: Vec<WitnessSig>` (2026-10-01). That
    /// field was a GHOST (RULE 3 shape 4): the one canonical builder always sent
    /// it empty ("redeem has no S-ABR overlap") and Lambda only counted it, so YP
    /// §17.3.1.4's "redeem uses S-ABR, identical to the send path" was enforced
    /// nowhere. It was a fragment of THIS receipt — its witness sigs are over the
    /// previous receipt's commitments, which nothing could verify without the
    /// receipt itself. The redeem round's overlap carrier is `fact_witness_sigs`.
    pub prev_receipts: Vec<Receipt>,
    
    /// Receiver's signature proving ownership
    /// Signs: BLAKE3("AXIOM_REDEEM" || txid || receiver_pk)
    pub receiver_sig: Vec<u8>,
    
    /// Validator hints from requester (1-3 required)
    #[serde(default)]
    pub validator_hints: Vec<ValidatorHint>,
    
    /// Receiver's existing FACT chain (YPX-001 §1.6).
    /// Client carries their own FACT chain. If receiver already holds money from
    /// prior transactions, they include their chain here. For first-time receivers,
    /// this is None. The validator builds a new FACT link for the receive and
    /// returns the updated chain in RedeemResponse.receiver_fact_chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver_fact_chain: Option<FactChain>,

    /// CL5 DMAP execution proof — wallet ownership verification.
    /// Client runs CL5 locally with wallet_secret, produces DMAP attestation
    /// proving they own the receiver_wallet_id without revealing the secret.
    /// Validator verifies the DMAP proof structurally (CoreID + Merkle).
    ///
    /// §15: MANDATORY. No exceptions. No fallback. No "if present." No
    /// signature-only legacy path. Empty `Vec` is rejected by Lambda's
    /// `process_redeem_request` (mirroring the CL1 gate at consensus.rs:2421).
    /// Pre-§15 this was `Option<Vec<u8>>` with `#[serde(default,
    /// skip_serializing_if)]` and a "legacy mode (signature-only)" fallback —
    /// see CLAUDE.md §15 regression watch + AXIOM_HANDOFF_MacClientStaleState.md.
    pub cl5_execution_proof: Vec<u8>,

    /// Nabla txid attestation — proves this txid has NOT been redeemed globally.
    /// Client fetches from Nabla (GET /query-txid), includes in redeem request.
    /// Lambda verifies the Nabla node signature. Lambda NEVER queries Nabla directly.
    /// Required: redeem without attestation is rejected (no fallback).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txid_attestation: Option<NablaTxidAttestation>,

    /// Stream B (2026-05-13): Nabla-writer-signed cheque-claim proof.
    /// Receiver obtains by calling `register_cheque_claim` during the
    /// §4.6 verify step.  Core CL5 hard-rejects redeems without this
    /// (E_CHEQUE_CLAIM_PROOF_MISSING); Lambda forwards it into the CL5
    /// PublicInputs verbatim.  See `ChequeClaimProof` for the wire shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cheque_claim_proof: Option<ChequeClaimProof>,

    /// YPX-021 §8.2 — client-fetched Nabla OODS reading for the redeem
    /// receipt's health flag. Same forwarding contract as
    /// `WitnessRequest::oods_attestation`. `None` = no flag (Phase 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oods_attestation: Option<NablaOodsAttestation>,

    /// Accumulated FACT witness signatures from prior validators in the
    /// redeem witness round.
    ///
    /// Distinct from `WitnessRequest::overlapped_signatures` (the S-ABR
    /// overlap proof on the SEND path — Ed25519 over `commitment_hash`). On the
    /// redeem path the SDK collects k WitnessSigs from validators
    /// serially; each carries a `fact_signature` (Dilithium ML-DSA-65
    /// over the FACT commitment, NOT the S-ABR commitment_hash). The
    /// SDK populates this field with the prior k-1 entries; the
    /// finalizer's Lambda forwards them into Core CL5 as
    /// `inputs.fact_witness_sigs`, where Core's AVM assembles the
    /// receiver's redeem FactLink via `build_fact_link` (CLAUDE.md §12 —
    /// Core is the sole authority for FactLink assembly).
    ///
    /// Since 2026-10-01 (Fable review F-1(b)) these sigs are ALSO the redeem
    /// round's S-ABR overlap carrier: a CL5 validator that did NOT witness the
    /// receiver's last receipt (`prev_receipts`) requires `sabr_overlap(prev_k)`
    /// of them from that receipt's witnesses, each Dilithium-verified over THIS
    /// link's FACT commitment (`modes::cl5_receiver_overlap`) — the CL2 Checks
    /// 1–4 mirror.
    ///
    /// Why a separate field from the send path's `overlapped_signatures`: the two sig
    /// sets are over different commitments with different algorithms
    /// (Ed25519 vs Dilithium) and serve different protocol concepts
    /// (S-ABR overlap vs FACT chain provenance). Sharing one field
    /// forced every reader to disambiguate by mode and was the source
    /// of the post-A2 receiver-link assembly bug.
    #[serde(default)]
    pub fact_witness_sigs: Vec<WitnessSig>,

    // fee_breakdown deleted 2026-06-05 PM. Pre-fix the SDK proposed a
    // per-validator slot allocation that flowed into Core CL5's NET
    // balance binding — a stale client `validators.list` would propose
    // wrong slots and the resulting `state_hash` diverged from what each
    // validator actually charges, producing E_RECEIPT_COMMITMENT_MISMATCH.
    // Replaced by `ValidatorCheque.rate_bps` (Dilithium-signed at cheque
    // issuance time). Core CL5 sums
    // `expected_fee_slot_amount(c.amount, c.rate_bps)` across the bundle
    // to derive `total_fee` deterministically. No client influence.
    // CLAUDE.md §13: pre-mainnet, no back-compat shim. Wire breaks cleanly.
}

///
/// After client receives k=3 witness signatures, they send ACK to each
/// validator to transition state from PENDING to CONFIRMED. v3.x: no
/// per-TX fee payment at ACK — fees settle at CL5 via fee_breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckRequest {
    /// Request ID for correlation
    pub request_id: String,

    /// The ACK envelope
    pub ack: AckWithFee,

    /// Client's public key (sender or receiver)
    pub client_pk: Vec<u8>,
}

/// ACK response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckResponse {
    /// Request ID for correlation
    pub request_id: String,

    /// Whether ACK was accepted
    pub success: bool,

    /// New status after ACK (should be Confirmed)
    pub new_status: Option<String>,

    /// Structured error response. Populated on every failure,
    /// `None` on success. Legacy `error: Option<String>` was removed
    /// in Phase 2b.15.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_response: Option<axiom_errors::ErrorResponse>,
}


/// Gateway request envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[allow(clippy::large_enum_variant)] // Architectural: variants carry protocol payloads of varying size
pub enum GatewayRequest {
    #[serde(rename = "witness")]
    Witness(WitnessRequest),
    
    #[serde(rename = "query_state")]
    QueryState(StateQueryRequest),
    
    #[serde(rename = "redeem")]
    Redeem(RedeemRequestEnvelope),
    
    #[serde(rename = "ack")]
    Ack(AckRequest),


    #[serde(rename = "health")]
    Health(HealthRequest),

    #[serde(rename = "shutdown")]
    Shutdown(ShutdownRequest),

    /// Multi-carrier discovery (YP §27.5.2 — Phase 1).
    /// ANTIE pushes the canonical carrier URI list at startup.
    #[serde(rename = "set_carriers")]
    SetCarriers(SetCarriersRequest),

    /// VSP: Validator Status Protocol query (free, unauthenticated)
    #[serde(rename = "validator_status")]
    ValidatorStatus(ValidatorStatusRequest),

    /// Initialize genesis state for a wallet (DEV/TEST MODE ONLY)
    #[serde(rename = "init_genesis_dev")]
    InitGenesis(InitGenesisRequest),

    /// Load pre-computed test state directly (DEV/TEST MODE ONLY)
    #[serde(rename = "load_test_state")]
    LoadTestState(LoadTestStateRequest),

    /// Phase 1: New validator requests VBC signing (discovery)
    #[serde(rename = "vbc_sign_request")]
    VBCSignRequest(VBCSignRequestPayload),

    /// Phase 2: New validator requests actual signature (with complete issuer_set)
    #[serde(rename = "vbc_sign_commit")]
    VBCSignCommit(VBCSignCommitPayload),

    /// §23.14.6: Inbound peer audit request from remote validator (via ANTIE)
    #[serde(rename = "peer_audit_request")]
    PeerAuditRequest(PeerAuditRequestEnvelope),

    /// §23.14.6: Inbound peer audit response from remote validator (via ANTIE)
    #[serde(rename = "peer_audit_response")]
    PeerAuditResponse(PeerAuditResponseEnvelope),

    /// §23.14.6 (KI#213): Inbound signed NotHeld from the audited validator (via ANTIE)
    #[serde(rename = "peer_audit_not_held")]
    PeerAuditNotHeld(PeerAuditNotHeldEnvelope),

    /// §23.14.3: our own carrier failed to send the peer-audit request (from ANTIE)
    #[serde(rename = "peer_audit_dispatch_failed")]
    PeerAuditDispatchFailed(PeerAuditDispatchFailedEnvelope),

    /// §4.5 / §30.2: Set auth_hash on a wallet (NOT stolen-key protection).
    #[serde(rename = "set_auth_hash")]
    SetAuthHash(SetAuthHashRequest),

    /// Fan-Out dedup check — persistent replay prevention (READ-ONLY).
    #[serde(rename = "fanout_dedup")]
    FanOutDedup(FanOutDedupRequest),

    /// Fan-Out mark — record diffusion_id as processed (WRITE).
    #[serde(rename = "fanout_mark")]
    FanOutMark(FanOutMarkRequest),
}

/// Genesis funding result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisResult {
    pub state_id: Vec<u8>,
    pub wallet_seq: u64,
}

// ============================================================================
// IPC named-payload structs — used in tuple variants of GatewayRequest /
// GatewayResponse so ANTIE/clients can deserialize each variant's payload
// as a single named type. With `#[serde(tag = "type")]` on the enum, a
// tuple variant with a struct payload serializes IDENTICALLY to an inline
// struct variant — wire format unchanged. Existence in this module
// guarantees Lambda + ANTIE see the same definition; mirror impossible.
// (UMP consolidation, 2026-05-10.)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitGenesisRequest {
    pub request_id: String,
    pub public_key: Vec<u8>,
    pub balance: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_members: Option<Vec<GroupMember>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestStateRequest {
    pub request_id: String,
    pub public_key: Vec<u8>,
    pub state_id: Vec<u8>,
    pub balance: u64,
    pub wallet_seq: u64,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VBCSignRequestPayload {
    pub request_id: String,
    pub sphincs_pk_hex: String,
    pub dilithium_pk_hex: String,
    pub ed25519_pk_hex: String,
    #[serde(default)]
    pub pgp_fingerprint_hex: String,
    #[serde(default)]
    pub proof_cap: String,
    #[serde(default)]
    pub node_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VBCSignCommitPayload {
    pub request_id: String,
    pub sphincs_pk_hex: String,
    pub dilithium_pk_hex: String,
    pub ed25519_pk_hex: String,
    #[serde(default)]
    pub pgp_fingerprint_hex: String,
    #[serde(default)]
    pub proof_cap: String,
    #[serde(default)]
    pub node_name: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub chain_depth: u8,
    pub issuer_set_hex: Vec<String>,
    /// RENEWAL (`AXIOM_DESIGN_ValidatorJoin.md` §5.2): the certificate being
    /// renewed. `None` = initial issuance.
    ///
    /// Carried by the requester rather than looked up: verification is
    /// self-contained — the issuer verifies it by chaining to
    /// `ROOT_AUTHORITY_PKS` — so no approval propagation is needed (§5.3a).
    ///
    /// Appended LAST with `serde(default)` so field order is untouched and an
    /// older sender still deserializes (as `None`, i.e. initial issuance).
    #[serde(default)]
    pub previous_vbc: Option<VBCProofBundle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAuditRequestEnvelope {
    pub request_id: String,
    pub peer_audit_request: PeerAuditRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAuditResponseEnvelope {
    pub request_id: String,
    pub peer_audit_response: PeerAuditResponse,
}

/// §23.14.6 (KI#213): ANTIE → Lambda, B's signed NotHeld received for A's
/// pending peer audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAuditNotHeldEnvelope {
    pub request_id: String,
    pub peer_audit_not_held: PeerAuditNotHeld,
}

/// §23.14.3 (2026-09-24, KI#211 residual): ANTIE → Lambda, the carrier FAILED
/// to send A's peer-audit request after hand-off. Lambda un-marks the dispatch
/// so B's deadline does not run and the next witness build retries the send.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAuditDispatchFailedEnvelope {
    pub request_id: String,
    pub target_email: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetAuthHashRequest {
    pub request_id: String,
    pub public_key: Vec<u8>,
    pub auth_hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FanOutDedupRequest {
    pub request_id: String,
    pub diffusion_id: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FanOutMarkRequest {
    pub request_id: String,
    pub diffusion_id: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitGenesisResponse {
    pub request_id: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<GenesisResult>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestStateResponse {
    pub request_id: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VBCSignApprovalResponse {
    pub request_id: String,
    pub approval: VBCSignApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VBCSignCommitResponse {
    pub request_id: String,
    pub success: bool,
    pub signature_hex: String,
    pub signer_sphincs_pk_hex: String,
    pub commitment_hex: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAuditResultPayload {
    pub request_id: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<PeerAuditResponse>,
    /// §23.14.6 (KI#213): B holds no record for the txid — a signed statement
    /// ANTIE sends back in place of `response`. Exactly one of `response` /
    /// `not_held` is `Some` on success; both `None` = the request was dropped
    /// (bad signature).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_held: Option<PeerAuditNotHeld>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester_email: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAuditResponseAck {
    pub request_id: String,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetAuthHashResponse {
    pub request_id: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FanOutDedupResponse {
    pub request_id: String,
    pub already_seen: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FanOutMarkResponse {
    pub request_id: String,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownAck {
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthRequest {
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownRequest {
    pub request_id: String,
}

/// Multi-carrier discovery (YP §27.5.2 — Phase 1, 2026-05-14).
///
/// ANTIE pushes the operator's configured inbound carrier set to Lambda
/// at gateway startup, in canonical URI form (`tcp:H:P`, `ws:H:P`,
/// `email:<address>`). The list flows out through `validator_status`
/// (VSP) so peers and clients can route via any supported channel.
///
/// Empty list is permitted but logs a loud warning at Lambda; VSP will
/// emit an empty `carriers` Vec so downstream tools can flag the
/// validator as discovery-incomplete without breaking the rest of the
/// VSP response (peer hints, fee config, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetCarriersRequest {
    pub request_id: String,
    /// Canonical YP §27.5.2 URI strings. Order is preserved for VSP.
    pub carriers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetCarriersAck {
    pub request_id: String,
    /// Number of carriers Lambda accepted (echo of `carriers.len()`).
    pub accepted: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    pub request_id: String,
    pub error_response: axiom_errors::ErrorResponse,
}

/// Gateway response envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[allow(clippy::large_enum_variant)]
pub enum GatewayResponse {
    #[serde(rename = "witness_result")]
    WitnessResult(Box<WitnessResponse>),
    
    #[serde(rename = "state_result")]
    StateResult(StateQueryResponse),
    
    #[serde(rename = "redeem_result")]
    RedeemResult(RedeemResponse),
    
    #[serde(rename = "ack_result")]
    AckResult(AckResponse),


    #[serde(rename = "health_result")]
    HealthResult(HealthResponse),
    
    #[serde(rename = "shutdown_ack")]
    ShutdownAck(ShutdownAck),

    /// Multi-carrier discovery ack (YP §27.5.2 — Phase 1).
    #[serde(rename = "set_carriers_ack")]
    SetCarriersAck(SetCarriersAck),

    /// VSP: Validator Status Protocol response
    #[serde(rename = "validator_status_result")]
    ValidatorStatusResult(ValidatorStatusResponse),

    #[serde(rename = "init_genesis_dev_result")]
    InitGenesisResult(InitGenesisResponse),

    #[serde(rename = "load_test_state_result")]
    LoadTestStateResult(LoadTestStateResponse),

    /// Error variant — structured error response is the sole source of
    /// truth. The legacy `message: String` field was removed in Phase
    /// 2b.15. Clients read `error_response.code` for dispatch and
    /// `error_response.message` for display.
    #[serde(rename = "error")]
    Error(ErrorEnvelope),

    /// Phase 1: Lambda's business decision on VBC signing
    #[serde(rename = "vbc_sign_approval")]
    VBCSignApprovalResult(VBCSignApprovalResponse),

    /// Phase 2: Core's VBC signature (after Lambda approved)
    #[serde(rename = "vbc_sign_commit_result")]
    VBCSignCommitResult(VBCSignCommitResponse),

    /// §23.14.6: Peer audit result (response to inbound peer audit request)
    #[serde(rename = "peer_audit_result")]
    PeerAuditResult(PeerAuditResultPayload),

    /// §23.14.6: Peer audit response acknowledgement
    #[serde(rename = "peer_audit_response_ack")]
    PeerAuditResponseAck(PeerAuditResponseAck),

    /// §4.5: Set auth_hash result
    #[serde(rename = "set_auth_hash_result")]
    SetAuthHashResult(SetAuthHashResponse),

    #[serde(rename = "fanout_dedup_result")]
    FanOutDedupResult(FanOutDedupResponse),

    #[serde(rename = "fanout_mark_result")]
    FanOutMarkResult(FanOutMarkResponse),
}

// ============================================================================
// VBC Signing Types (for new validator onboarding)
// ============================================================================

/// Lambda's business decision on whether to sign a VBC
/// Lambda ONLY approves/rejects — Core does the actual cryptography
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VBCSignApproval {
    pub approved: bool,
    /// Reason for rejection (None if approved)
    pub reason: Option<String>,
    /// How many VBC signs this validator has remaining
    pub signs_remaining: u8,
    /// Our chain depth (new validator will be depth + 1)
    pub our_chain_depth: u8,
    /// Accepted proof capability ("dmap" or "zkvm")
    #[serde(default)]
    pub accepted_proof_cap: String,
}



#[cfg(test)]
mod canonical_cbor_tests {
    use super::*;

    /// Encode with the PRODUCTION encoder, decode with the PRODUCTION typed
    /// decoder, for every `TxKind`.
    ///
    /// ⚠ This is the guard for the total-outage class CLAUDE.md records. It
    /// replaces `every_tx_kind_round_trips_through_its_discriminators`, which
    /// drove `kind -> discriminators -> kind` — a mapping that existed only to
    /// serve the wire, and so could pass while the wire itself was broken. This
    /// one goes through `to_canonical_cbor_bytes` and `ciborium::from_reader`
    /// into a `deny_unknown_fields` `Transaction`: the exact pair of steps a
    /// validator performs. A field the encoder emits that the struct does not
    /// accept fails here, and so does a `kind` that does not survive.
    ///
    /// Mutation-verified 2026-09-07: replacing the emitted `kind` with
    /// `Value::serialized(&TxKind::Normal)` turns THIS test red on the first
    /// non-Normal variant (`Heal`), and dropping the `kind` entry entirely turns
    /// it red the same way.
    #[test]
    fn every_tx_kind_survives_the_real_canonical_wire() {
        assert_eq!(TxKind::ALL.len(), 9,
            "a TxKind was added without adding it to ALL — this guard would then \
             pass over a smaller set, which is a check that cannot fail");
        for k in TxKind::ALL {
            let mut tx = Transaction::default();
            tx.kind = k.clone();
            let bytes = tx.to_canonical_cbor_bytes();
            let back: Transaction = ciborium::from_reader(&bytes[..]).unwrap_or_else(|e| {
                panic!("{k:?}: the canonical bytes do not decode into the typed \
                        Transaction: {e}. Every field the encoder emits must be a \
                        field the struct accepts — `deny_unknown_fields` rejects \
                        the WHOLE transaction, not just the offending key.")
            });
            assert_eq!(back.kind, k,
                "{k:?} did not survive the canonical wire — it decoded as \
                 {:?}. A degraded kind is SILENT: a claim is debited instead of \
                 credited, and HAL/RECALL lose their overlap relaxation.",
                back.kind);
        }
    }

    /// No `is_*` discriminator bool may come back onto the wire.
    ///
    /// The seven bools were removed on 2026-09-07 because they needed four
    /// hand-maintained decoders to strip them — one of them inside ANTIE, which
    /// is a carrier and has no business reading a payload. Re-adding one is not
    /// a small change; it recreates that whole apparatus. This fails if anyone
    /// does, without needing to know which kind they added.
    #[test]
    fn the_canonical_wire_carries_no_discriminator_bools() {
        let tx = Transaction::default();
        let ciborium::Value::Map(pairs) = tx.to_canonical_cbor_value() else {
            panic!("the canonical encoding must be a CBOR map");
        };
        for (k, _) in &pairs {
            let key = k.as_text().expect("canonical keys are text");
            assert!(!key.starts_with("is_"),
                "`{key}` is a discriminator bool on the canonical wire. `kind` \
                 travels whole now — see the note on TxKind. Adding one back \
                 means every decoder must strip it or reject EVERY transaction.");
        }
        assert!(pairs.iter().any(|(k, _)| k.as_text() == Some("kind")),
            "the canonical encoding must carry `kind`");
    }
}

#[cfg(test)]
mod one_hibernation_path_tests {
    use super::*;

    /// `hibernation_until_for` is the ONLY path that stamps a hibernation, so a
    /// change to it moves HAL, RECALL and the stake CLAIM together (the owner,
    /// 2026-09-05). This drives all four kinds through the PRODUCTION entry point
    /// (`Transaction::produced_hibernation_until`) and pins each against its own
    /// window — so a kind that stops routing through the shared function, or grows
    /// a private formula, goes red here.
    ///
    /// It deliberately asserts `base + WINDOW * TICK_INTERVAL_SECS` rather than
    /// calling the function again: re-deriving with the code under test is the
    /// check-that-cannot-fail shape (RULE 6 §3a).
    #[test]
    fn every_hibernating_kind_goes_through_the_one_path() {
        let base = 1_000_000u64;
        let t = TICK_INTERVAL_SECS;
        let mk = |kind: TxKind| {
            let mut tx = Transaction::default();
            tx.epoch = base;
            tx.kind = kind;
            tx.sender_wallet_id = "someone@example.net".to_string(); // public, not dev-class
            tx
        };

        assert_eq!(mk(TxKind::HalReanchor).produced_hibernation_until(),
            base + HIBERNATION_WINDOW * t, "HAL");
        assert_eq!(mk(TxKind::Recall).produced_hibernation_until(),
            base + RECALL_HIBERNATION_WINDOW * t, "RECALL");
        assert_eq!(mk(TxKind::ValidatorFoundationStakeClaim).produced_hibernation_until(),
            base + crate::validation::protocol_gen::TIER2_STAKE_LOCK_TICKS * t,
            "tier-2 stake claim must hibernate by the SAME path as HAL/RECALL");
        assert_eq!(mk(TxKind::ValidatorCommunityStakeClaim).produced_hibernation_until(),
            base + crate::validation::protocol_gen::TIER3_STAKE_LOCK_TICKS * t,
            "tier-3 stake claim must hibernate by the SAME path as HAL/RECALL");

        // Everything else stays non-hibernating — the shared function returns 0,
        // so adding a kind never accidentally locks an ordinary send.
        for kind in [TxKind::Normal, TxKind::Heal, TxKind::GenesisClaim,
                     TxKind::ValidatorWithdrawalMint, TxKind::VbcRequest,
                     TxKind::EmissionClaim] {
            assert_eq!(mk(kind.clone()).produced_hibernation_until(), 0,
                "{:?} must not hibernate", kind);
        }
    }
}

#[cfg(test)]
mod dev_wallet_hibernation_tests {
    use super::*;

    // SAFETY PROOF: the dev-wallet short hibernation window applies ONLY to an
    // `@axiom.internal` (dev-class) wallet and can NEVER shorten a public wallet's
    // window — i.e. it cannot touch real money.
    #[test]
    fn dev_wallet_gate_never_shortens_public_money() {
        let base = 1_000_000u64;
        let t = TICK_INTERVAL_SECS;

        // ── hibernation_until_for routing: is_dev_class selects the window ──
        assert_eq!(hibernation_until_for(base, true, false, false, false, false), base + HIBERNATION_WINDOW * t,
            "PUBLIC HAL → FULL window (never shortened)");
        assert_eq!(hibernation_until_for(base, true, false, true, false, false), base + DEV_WALLET_HIBERNATION_WINDOW * t,
            "DEV HAL → dev-wallet window");
        assert_eq!(hibernation_until_for(base, false, true, false, false, false), base + RECALL_HIBERNATION_WINDOW * t,
            "PUBLIC recall → FULL window");
        assert_eq!(hibernation_until_for(base, false, true, true, false, false), base + DEV_WALLET_RECALL_HIBERNATION_WINDOW * t,
            "DEV recall → dev-wallet window");
        assert_eq!(hibernation_until_for(base, false, false, true, false, false), 0, "non-reanchor → 0 (dev)");
        assert_eq!(hibernation_until_for(base, false, false, false, false, false), 0, "non-reanchor → 0 (public)");

        // Dev-wallet window is never LONGER than the public one (real never shortened /
        // dev never lengthened). PROD invariant only: dev-mode deliberately gives dev
        // wallets a LONGER recall window (60) than the minimal public dev window (20)
        // so a dev recall survives a dev witness round (§2.2.4 dev tables).
        if cfg!(not(feature = "dev-mode")) {
            assert!(DEV_WALLET_HIBERNATION_WINDOW <= HIBERNATION_WINDOW);
            assert!(DEV_WALLET_RECALL_HIBERNATION_WINDOW <= RECALL_HIBERNATION_WINDOW);
        }

        // ── the gate is is_dev_wallet(@axiom.internal) EXACTLY — nothing else ──
        assert!(crate::wallet_id::is_dev_wallet("bob@axiom.internal"));
        assert!(!crate::wallet_id::is_dev_wallet("alice@example.net"));
        assert!(!crate::wallet_id::is_dev_wallet("x@axiom.io"));           // near-miss domain
        assert!(!crate::wallet_id::is_dev_wallet("m@axiom.internal.evil")); // suffix trick
        assert!(!crate::wallet_id::is_dev_wallet(""));                      // no domain

        // ── Core path (produced_hibernation_until) routes a PUBLIC sender to FULL ──
        let mut pub_hal = Transaction::default();
        pub_hal.sender_wallet_id = "alice@example.net".into();
        pub_hal.epoch = base;
        pub_hal.kind = TxKind::HalReanchor;
        assert_eq!(pub_hal.produced_hibernation_until(), base + HIBERNATION_WINDOW * t,
            "Core: PUBLIC HAL sender gets the FULL window — real money cannot be shortened");

        let mut dev_hal = pub_hal.clone();
        dev_hal.sender_wallet_id = "bob@axiom.internal".into();
        assert_eq!(dev_hal.produced_hibernation_until(), base + DEV_WALLET_HIBERNATION_WINDOW * t,
            "Core: @axiom.internal HAL sender gets the dev-wallet window");
    }

    // P3.1 (YPX-010 §11): the Quorum Gate floor relaxes to 1 for a k=0 Ark ⟠-trade
    // anchor (receiver-as-witness) and STAYS at 3 for everything else. This is the
    // single source `validate_witnesses` calls; a floor regression fails here first.
    #[test]
    fn required_witness_floor_is_1_only_for_k0_ark_trade() {
        use crate::wallet_id::K_ARK;
        assert_eq!(K_ARK, 0, "Ark tier is k=0");

        // The ONE relaxation: k=0 endpoint whose anchor is an offline ⟠-trade.
        assert_eq!(required_witness_floor(K_ARK, WitnessOp::ArkTrade), 1,
            "k=0 Ark ⟠-trade anchor → floor 1 (the receiver is the sole witness)");

        // A k=0 wallet doing anything ONLINE (charge / unload / settlement) keeps 3.
        assert_eq!(required_witness_floor(K_ARK, WitnessOp::Online), NORMAL_WITNESS_FLOOR,
            "k=0 but online-witnessed → absolute 3-floor");

        // EVERY k≥3 tier needs ITS OWN k (YP §17.3.1.4 v2.19.0, KI#150) — never
        // below 3, never relaxed by an ArkTrade op label.
        for k in [3u8, 4, 5, 8, 255] {
            assert_eq!(required_witness_floor(k, WitnessOp::ArkTrade), k.max(NORMAL_WITNESS_FLOOR),
                "k={k} never relaxes below max(k, 3) regardless of op");
            assert_eq!(required_witness_floor(k, WitnessOp::Online), k.max(NORMAL_WITNESS_FLOOR),
                "k={k} online → max(k, 3)");
        }
        assert_eq!(required_witness_floor(1, WitnessOp::Online), NORMAL_WITNESS_FLOOR,
            "a tier below 3 is floored at 3");
        assert_eq!(NORMAL_WITNESS_FLOOR, 3, "absolute quorum floor is 3");
    }
}

#[cfg(test)]
mod canonical_tx_cbor_tests {
    use super::*;

    /// A fully-populated Transaction fixture — every field set to a
    /// non-default value where possible. Used by the round-trip test
    /// to catch "field added to struct but encoder doesn't emit it"
    /// drift mechanically: if a field is in the struct but not the
    /// encoder, its value gets lost on round-trip and the assertion
    /// fails with a clear key list.
    fn populated_tx_fixture() -> Transaction {
        Transaction {
            consumed_state_id: [0xAA; 32],
            client_pk: vec![0xBB; 32],
            sender_wallet_id: "alice@axiom/abcd1234".to_string(),
            wallet_seq: 7,
            receiver_wallet_id: "bob@axiom/deadbeef".to_string(),
            receiver_address: Some("override@example.com".to_string()),
            amount: 10_000_000_000,
            reference: "lunch".to_string(),
            nonce: 42,
            epoch: 1_700_000_000,
            client_sig: vec![0xCC; 64],
            scar_passcode: Some(123456),
            burn_target_tx_id: Some([0xEE; 32]),
            recall_target_tx_id: Some([0xDD; 32]),
            oracle_claim: None,
            required_k: 3,
            proof_type: 1,
            core_version: crate::version::CORE_VERSION_TAG.to_string(),
            core_id: [0u8; 32],
            kind: TxKind::Normal,
        }
    }

    /// The canonical encoder is the single source of truth for the
    /// SDK ↔ validator wire format. This test pins it to a byte-stable
    /// fixture: if the encoded length or any byte changes, a downstream
    /// breakage is imminent. Update the fixture only when intentionally
    /// changing the wire format (which requires a soak gate).
    #[test]
    fn canonical_encoder_is_byte_stable() {
        let tx = populated_tx_fixture();
        let bytes = tx.to_canonical_cbor_bytes();
        // Array-of-int byte representation: 32-byte consumed_state_id, 32-byte
        // client_pk, 64-byte client_sig, 32-byte
        // burn_target_tx_id and 32-byte recall_target_tx_id (all CBOR arrays of
        // Integer), plus scalars, field-name keys, and `kind`.
        //
        // Bumping this number is a WIRE-FORMAT CHANGE — say why, in one line,
        // right here. The pin firing is the pin working.
        //
        // 2026-09-07: 1070 -> 922 (-148). The seven `is_*` discriminant bools
        // were REPLACED by a single `kind` field carrying the serde variant
        // name. Every byte accounted for (verified, not derived):
        //   -159  the seven key+False pairs, which cost the SAME on every
        //         transaction whether or not it used them:
        //           is_heal 9, is_validator_withdrawal_mint 31,
        //           is_hal_reanchor 17, is_recall 11,
        //           is_validator_foundation_stake_claim 38,
        //           is_validator_community_stake_claim 37, is_vbc_request 16
        //   -1    the CBOR map header shrank from two bytes to one: the map
        //         dropped from 26 entries to 20, back under the 23-entry
        //         boundary. (Crossing it upward is why the 24th field once cost
        //         a byte on EVERY transaction.)
        //   +12   the "kind" entry: 5-byte Text key + the fixture's
        //         `TxKind::Normal` as a 7-byte Text value. This is the only
        //         part that varies by kind — the widest variant name
        //         (`ValidatorFoundationStakeClaim`, 29 chars) costs 24 more,
        //         so even the worst case is ~135 bytes SMALLER than the bools.
        //
        // ⚠ The previous history of this constant is preserved below, because it
        // records what each bool cost and is the clearest statement of why they
        // are gone. The numbers no longer add to the assertion.
        //   828 = 786 + 42 (core_id: 8-byte key + 34-byte 32-Integer array)
        //   859 = 828 + 31 (is_validator_withdrawal_mint)
        //   861 = 859 + 2  (CORE_VERSION_TAG "Kyoto/1.1" -> "Kyoto/1.1/GENESIS")
        //   878 = 861 + 17 (YPX-020 HAL: is_hal_reanchor)
        //   889 = 878 + 11 (YPX-022 RECALL: is_recall)
        //   975 = 889 + 86 (YPX-022 RECALL: recall_target_tx_id, a REAL field)
        //   978 = 975 + 3  (CORE_VERSION_TAG -> "Kyoto/2.12.0/GENESIS")
        //  1054 = 978 + 76 (ValidatorJoin §5.2.3: the two stake-claim bools,
        //                   incl. the +1 map-header byte at the 24th entry)
        //  1070 = 1054 + 16 (§5.2.2d: is_vbc_request)
        // Note the shape of that list: SIX of the nine bumps were a bool, and
        // each one had to be added to five separate builders and four decoders.
        //
        // 2026-09-25: 922 -> 780 (-142). `owner_proof` DELETED (KI#108): the
        // 12-byte "owner_proof" Text key + a 64-Integer array of 0xDD (2-byte
        // header + 64 x 2 bytes = 130). Not a bool this time — a real field
        // that duplicated `client_sig` under a key derived from the same
        // private key.
        assert_eq!(
            bytes.len(),
            780,
            "canonical encoder byte length changed — check this is intentional"
        );
    }

    /// Round-trip: encode via canonical encoder, decode to a CBOR
    /// `Value` map, assert every emitted key survives with the expected
    /// value. Validates that the encoder produces well-formed CBOR a
    /// downstream verifier can read.
    ///
    /// 9B.1 note: the canonical encoder emits `is_heal` (derived from
    /// `kind`) for receipt-commitment stability, but the `Transaction`
    /// struct no longer has a top-level `is_heal` field. We can't decode
    /// straight into `Transaction` via serde anymore (the field-name
    /// mismatch is intentional — the encoder is a signing payload, not
    /// a wire format). Decode into `ciborium::Value` and compare the
    /// emitted fields by name.
    #[test]
    fn canonical_encoder_round_trips_through_serde() {
        let tx = populated_tx_fixture();
        let bytes = tx.to_canonical_cbor_bytes();
        let decoded: ciborium::Value = ciborium::de::from_reader(bytes.as_slice())
            .expect("canonical CBOR must decode as a CBOR Value");
        let map = decoded.as_map().expect("Transaction encoded as CBOR map");

        let get = |key: &str| -> &ciborium::Value {
            map.iter()
                .find(|(k, _)| k.as_text() == Some(key))
                .map(|(_, v)| v)
                .unwrap_or_else(|| panic!("missing key {key}"))
        };
        // Scalar / string fields.
        assert_eq!(get("sender_wallet_id").as_text(), Some(tx.sender_wallet_id.as_str()));
        assert_eq!(get("wallet_seq").as_integer(), Some(tx.wallet_seq.into()));
        assert_eq!(get("receiver_wallet_id").as_text(), Some(tx.receiver_wallet_id.as_str()));
        assert_eq!(get("amount").as_integer(), Some(tx.amount.into()));
        assert_eq!(get("reference").as_text(), Some(tx.reference.as_str()));
        assert_eq!(get("nonce").as_integer(), Some(tx.nonce.into()));
        assert_eq!(get("epoch").as_integer(), Some(tx.epoch.into()));
        assert_eq!(get("required_k").as_integer(), Some(tx.required_k.into()));
        assert_eq!(get("proof_type").as_integer(), Some(tx.proof_type.into()));
        assert_eq!(get("core_version").as_text(), Some(tx.core_version.as_str()));
        // The discriminant, carried whole (2026-09-07). This used to be four
        // `is_*` bool assertions covering four of the SEVEN emitted bools — the
        // three it missed were the two stake claims and the VBC request, i.e.
        // the newest and least-exercised kinds. `canonical_cbor_tests` above
        // covers all nine kinds against the typed decoder; this pins the on-wire
        // spelling for the fixture.
        assert_eq!(get("kind").as_text(), Some("Normal"));
    }

    /// Drift-prevention check (the whole point of this consolidation):
    /// every field on `Transaction` is either (a) emitted by the canonical
    /// encoder, or (b) explicitly listed in `INTENTIONALLY_UNEMITTED`.
    /// Adding a field to the struct without touching either fails this
    /// test — same shape as the CLAUDE.md §13 recurring drift class fix.
    ///
    /// The trick: serde's default `Serialize` impl emits every public
    /// field that doesn't have `#[serde(skip)]`. Decode the serde output
    /// to a map and we have the authoritative key list. The canonical
    /// encoder's key list must be a subset, with any missing keys
    /// enumerated.
    #[test]
    fn canonical_encoder_covers_all_struct_fields() {
        let tx = populated_tx_fixture();

        let mut serde_buf = Vec::new();
        ciborium::ser::into_writer(&tx, &mut serde_buf)
            .expect("serde Transaction encode");
        let serde_value: ciborium::Value =
            ciborium::de::from_reader(serde_buf.as_slice())
                .expect("re-decode serde Transaction");
        let serde_keys: Vec<String> = serde_value
            .as_map()
            .expect("Transaction is a CBOR map")
            .iter()
            .filter_map(|(k, _)| k.as_text().map(String::from))
            .collect();

        let canonical_value = tx.to_canonical_cbor_value();
        let canonical_keys: std::collections::HashSet<String> = canonical_value
            .as_map()
            .expect("canonical encoder produces a CBOR map")
            .iter()
            .filter_map(|(k, _)| k.as_text().map(String::from))
            .collect();

        let mut missing: Vec<String> = Vec::new();
        for key in &serde_keys {
            if canonical_keys.contains(key) {
                continue;
            }
            if Transaction::INTENTIONALLY_UNEMITTED.contains(&key.as_str()) {
                continue;
            }
            missing.push(key.clone());
        }

        assert!(
            missing.is_empty(),
            "Transaction fields exist in the struct but the canonical \
             encoder doesn't emit them: {:?}.\n\
             Either add them to `to_canonical_cbor_value` (intentional wire \
             extension — requires soak validation) or add them to \
             `INTENTIONALLY_UNEMITTED` with a clear reason. This is the \
             CLAUDE.md §13 drift class — silent default-fill on the receiver \
             side has bitten us five times pre-mainnet.",
            missing
        );
    }
}


#[cfg(test)]
mod response_payload_tests {
    use super::*;

    fn witness_response() -> WitnessResponse {
        WitnessResponse {
            sender_state: Some(vec![9u8; 32]),
            request_id: "r-1".into(),
            success: false,
            witness_signature: None,
            overlapped_signatures: vec![],
            rejection: Some(RejectionInfo { code: "E_X".into(), message: "no".into() }),
            cheque_for_receiver: None,
            receipt: None,
            produced_state_id: Some(vec![3u8; 32]),
            commitment_hash: Some(vec![4u8; 32]),
            state_hash: Some(vec![5u8; 32]),
            receipt_commitment: Some(vec![6u8; 32]),
            txid: vec![8u8; 32],
            validator_hints: vec![],
            sender_fact_chain: None,
            audit_demand: None,
            audit_request: None,
            nonce_challenge: None,
            pulse_proof: None,
            audit_failed: false,
            outbound_peer_audit: None,
            confidence_index: None,
            scar_consent_for_receiver: None,
            scar_consent_voucher: None,
            vbc_signature: None,
        }
    }

    /// KI#173 — the sender leg carries `sender_state` (ANTIE's former copy
    /// of the envelope dropped it) and every value the SDK reads by name.
    #[test]
    fn sender_leg_carries_sender_state_and_the_read_fields() {
        let p = ResponsePayload::sender_leg(witness_response());
        assert_eq!(p.sender_state, Some(vec![9u8; 32]));
        assert_eq!(p.request_id, "r-1");
        assert!(!p.success);
        assert_eq!(p.txid, Some(vec![8u8; 32]));
        assert_eq!(p.produced_state_id, Some(vec![3u8; 32]));
        assert_eq!(p.commitment_hash, Some(vec![4u8; 32]));
        assert_eq!(p.state_hash, Some(vec![5u8; 32]));
        assert_eq!(p.receipt_commitment, Some(vec![6u8; 32]));
        assert_eq!(p.error.as_deref(), Some("no"));
        assert_eq!(p.rejection_code.as_deref(), Some("E_X"));
        assert!(p.cheque_for_receiver.is_none());
        assert!(p.vbc_signature.is_none());
        assert!(p.query_data.is_none());
    }

    /// KI#173 — `sender_state` rides the CBOR reply under its own key, and a
    /// reply without it decodes (the field is optional on the wire).
    #[test]
    fn sender_state_is_on_the_wire_and_optional() {
        let p = ResponsePayload::sender_leg(witness_response());
        let mut bytes = Vec::new();
        ciborium::into_writer(&p, &mut bytes).unwrap();
        let back: ResponsePayload = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back.sender_state, Some(vec![9u8; 32]));

        let mut q = ResponsePayload::sender_leg(witness_response());
        q.sender_state = None;
        let mut bytes = Vec::new();
        ciborium::into_writer(&q, &mut bytes).unwrap();
        let v: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        let has_key = v.as_map().unwrap().iter()
            .any(|(k, _)| k.as_text() == Some("sender_state"));
        assert!(!has_key);
        let back: ResponsePayload = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert!(back.sender_state.is_none());
    }
}


#[cfg(test)]
mod scar_definition_divergence {
    use super::*;

    /// ⚠ THE TWO SCAR DEFINITIONS DISAGREE, AND THIS PINS BY HOW MUCH (KI#197).
    ///
    /// The ordinary failure in this system is a link that collected its k
    /// witnesses and then failed to REGISTER with Nabla. Measured 2026-09-17:
    ///
    ///     has_scars()             false   <- the Ark-unload gate sees nothing
    ///     scar_count()            0
    ///     fact::link_is_scarred   TRUE    <- it IS a scar
    ///
    /// `has_scars` additionally requires `witnesses.len() < required_k`, which
    /// the Quorum Gate (YP §17.1.2) makes unreachable: state advances ONLY on k
    /// fresh witnesses, so a committed link always has them. The predicate is
    /// effectively constant `false`, and it guards §11.9.3 Ark unload.
    ///
    /// If someone "fixes" this by making the two agree, THIS TEST MUST BE
    /// UPDATED DELIBERATELY — it is the record of what the divergence was, and
    /// the Ark rules' behaviour changes with it.
    #[test]
    fn a_fully_witnessed_unregistered_link_is_a_scar_to_fact_and_invisible_to_has_scars() {
        let mut l = FactLink {
            tx_id: [1u8; 32], previous_state_id: [0u8; 32], new_state_id: [2u8; 32],
            amount: 500, required_k: 3, tick: 0, witnesses: Vec::new(),
            nabla_confirmation: None, burn_proof: None, burn_target_tx_id: None,
            sender_anchor: None, is_dev_class: false, recall_proof: None, out_of_order_confirmation: None,
            inherited_scar_txids: Vec::new(), inherited_scar_resolutions: Vec::new(),
            receiver_witness: None,
        };
        for i in 0..3u8 {
            l.witnesses.push(FactWitness {
                validator_id: [i; 32], validator_pk: alloc::vec![0u8; 1952],
                signature: alloc::vec![0u8; 3309], vbc_hash: [0u8; 32],
            });
        }
        let chain = FactChain { links: alloc::vec![l], ..Default::default() };

        assert!(crate::fact::link_is_scarred(&chain.links[0]),
                "no confirmation, no burn, no recall — this IS an unresolved link");
        assert!(!chain.has_scars(),
                "has_scars() cannot see it: the Quorum Gate makes its \
                 witnesses<required_k clause unreachable (KI#197)");
        assert_eq!(chain.scar_count(), 0, "same clause, same blind spot");
    }
}

#[cfg(test)]
mod opening_state {
    use super::*;

    const PK: [u8; 32] = [7u8; 32];
    const K: u8 = crate::wallet_id::K_DEFAULT;
    const PT: u8 = crate::wallet_id::PROOF_TYPE_DMAP;

    fn opening() -> WalletState {
        WalletState {
            public_key: PK.to_vec(),
            balance: crate::genesis::genesis_opening_balance(&PK),
            wallet_seq: 0,
            state_id: crate::genesis::opening_state_id_for(&PK, K, PT),
            auth_hash: None,
            wallet_id: None,
            group_members: None,
            hibernation_until: 0,
            wall_clock_lock: 0,
            emission_claimed_epoch: 0,
            stake_floor_until: 0,
            wallet_format: WalletFormat::CURRENT,
        }
    }

    /// F-1 (Fable 2026-10-01): the opening shape is the SDK's fresh wallet
    /// (opening id, opening balance) or the zero label; each history-bearing
    /// field, set alone, makes the state NOT opening — a field this predicate
    /// forgot is a field a returning wallet could hide behind a "first-time"
    /// declaration (e.g. a floored wallet declaring only `stake_floor_until`).
    /// Mutation-tested: dropping any clause turns the matching row red;
    /// requiring `state_id == 0` (the first build) turns the opening-id row red.
    #[test]
    fn opening_state_is_exactly_the_key_derived_opening() {
        assert!(opening().is_opening_state(&PK, K, PT), "the SDK's fresh wallet (opening id)");
        let zero_label = WalletState { state_id: [0u8; 32], ..opening() };
        assert!(zero_label.is_opening_state(&PK, K, PT), "the zero label (CLAUDE.md §15 wording)");
        let cases: [(&str, fn(&mut WalletState)); 7] = [
            ("balance", |s| s.balance += 1),
            ("wallet_seq", |s| s.wallet_seq = 1),
            ("state_id", |s| s.state_id = [1u8; 32]),
            ("hibernation_until", |s| s.hibernation_until = 1),
            ("wall_clock_lock", |s| s.wall_clock_lock = 1),
            ("emission_claimed_epoch", |s| s.emission_claimed_epoch = 1),
            ("stake_floor_until", |s| s.stake_floor_until = 1),
        ];
        for (name, set) in cases {
            let mut s = opening();
            set(&mut s);
            assert!(!s.is_opening_state(&PK, K, PT), "{} alone must make the declared state non-opening", name);
        }
        // Judged for the DECLARED key, not the client-supplied `public_key`.
        assert!(!opening().is_opening_state(&[8u8; 32], K, PT), "another key's opening id is not this key's");
    }
}
