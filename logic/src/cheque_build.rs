//! Cheque construction — single source of truth (P3.5, BUILD_ARK §3.2).
//!
//! The witness round builds a `ValidatorCheque` from the transaction plus the
//! *issuer's* identity + carrier/fee context. Two callers now need this exact
//! construction:
//!
//!   1. **Lambda** (online, k≥3): `create_validator_cheque` — the issuer is the
//!      witnessing validator (its `validator_id` / Ed25519 pk / VBC bundle / configured
//!      `rate_bps`), signed with the validator's key.
//!   2. **The Ark session** (offline, k=0): the issuer is the SENDER's own wallet — the
//!      k=0 ⟠ trade has no validators, so the sender's Core builds and its wallet key
//!      signs the single cheque the receiver redeems locally (YPX-010 §11.2, leg S3).
//!
//! Per BUILD_ARK Rule 0.1 (the `cl5_inputs` precedent) the shared construction lives
//! HERE in `core/logic`, not copied into the SDK. Both callers build the *unsigned*
//! cheque with this function, then compute the commitment via
//! [`crate::compute::compute_cheque_commitment`] and sign it with their own key — the
//! private key never crosses into Core, so signing stays with the caller while the
//! byte-for-byte struct shape is defined once.
//!
//! no_std + alloc clean: `created_at` (a wall-clock second) is a PARAMETER, not read
//! from `SystemTime` here (Core has no clock; the SDK/Lambda caller supplies it), and
//! the oracle payout is pre-computed by the caller (Lambda owns `oracle_config`).

use alloc::string::String;
use alloc::vec::Vec;

use crate::types::{
    FactChain, NablaHint, OracleClaimData, Transaction, VBCProofBundle, ValidatorCheque,
};

/// Everything the *issuer* of a cheque contributes that is not derived from the
/// transaction: identity (`issuer_id`/`issuer_pk`), the online provenance bundle
/// (`vbc_bundle`, `None` for a k=0 offline issuer), the carrier the receiver reaches
/// the issuer through, the issuer's configured fee rate, and the wall-clock stamp.
pub struct ChequeIssuerContext {
    /// Validator id (`BLAKE3(sphincs_pk)`) online, or the sender's identity for k=0.
    pub issuer_id: [u8; 32],
    /// Issuer's Ed25519 public key (validator key online; sender wallet key for k=0).
    pub issuer_pk: Vec<u8>,
    /// VBC provenance chain — `Some` for a validator, `None` for a k=0 offline issuer
    /// (there are no validators offline; the receiver-witness FACT link is the proof).
    pub vbc_bundle: Option<VBCProofBundle>,
    /// Carrier the receiver uses to reach the issuer (advisory, unsigned).
    pub carrier_type: String,
    /// Carrier address (advisory, unsigned).
    pub carrier_address: String,
    /// Fee rate the issuer applies, bound into the cheque commitment. A k=0 offline
    /// trade charges no online fee (0); fees settle at reconciliation (§12).
    pub rate_bps: u32,
    /// Wall-clock seconds at issuance. A parameter (Core has no clock): the caller
    /// supplies `SystemTime::now()` (Lambda) or its platform clock (SDK).
    pub created_at: u64,
}

/// Build the UNSIGNED `ValidatorCheque` (`signature: vec![]`). The caller then computes
/// [`crate::compute::compute_cheque_commitment`] over it and signs with its own key.
///
/// Everything derivable from the transaction is derived here (sender/receiver wallet
/// ids, amount, reference, epoch, `recall_target_tx_id`, `sender_wallet_pk`); everything
/// contributed by the issuer arrives via [`ChequeIssuerContext`]. `oracle_claim` is the
/// caller-adjusted claim (Lambda has already stamped `payout_amount` from its
/// `oracle_config`; a k=0 caller passes `None`).
#[allow(clippy::too_many_arguments)]
pub fn build_cheque_unsigned(
    transaction: &Transaction,
    txid: [u8; 32],
    state_hash: [u8; 32],
    produced_state_id: [u8; 32],
    sender_fact_chain: Option<FactChain>,
    execution_proof_bytes: &[u8],
    zkp_nonce: Option<[u8; 32]>,
    proof_type: u8,
    dmap_input_hash: [u8; 32],
    dmap_output_hash: [u8; 32],
    nabla_hint: Option<NablaHint>,
    oracle_claim: Option<OracleClaimData>,
    // YP §26.17.6.5 B4 — the certificates this validator verified
    // `sender_fact_chain` against; travel beside the chain to the receiver.
    fact_certificates: alloc::vec::Vec<crate::types::VBCProofBundle>,
    issuer: &ChequeIssuerContext,
) -> ValidatorCheque {
    ValidatorCheque {
        fact_certificates,
        txid,
        validator_id: issuer.issuer_id,
        validator_pk: issuer.issuer_pk.clone(),
        signature: Vec::new(), // caller signs the commitment
        execution_proof: execution_proof_bytes.to_vec(),
        vbc_bundle: issuer.vbc_bundle.clone(),
        carrier_type: issuer.carrier_type.clone(),
        carrier_address: issuer.carrier_address.clone(),
        // YPX-018 Phase 5f: the transaction's real sender_wallet_id (CL1 §11.9,
        // client-set and Core-verified against the pk binding).
        sender_wallet_id: transaction.sender_wallet_id.clone(),
        receiver_wallet_id: transaction.receiver_wallet_id.clone(),
        amount: transaction.amount,
        // Bound into the cheque commitment so the receiver's Core CL5 computes the
        // total fee deterministically without trusting any client proposal.
        rate_bps: issuer.rate_bps,
        reference: transaction.reference.clone(),
        epoch: transaction.epoch,
        created_at: issuer.created_at,
        state_hash,
        produced_state_id,
        sender_fact_chain,
        zkp_nonce,
        proof_type,
        dmap_input_hash,
        dmap_output_hash,
        // YPX-002 §3.2 sticky Nabla — pass-through, never validated by Core.
        nabla_hint,
        // YPX-002 §4.6 — sender's raw Ed25519 wallet_pk for the receiver's §4.6
        // /query. Advisory, unsigned. None if the pk is not a well-formed 32 bytes.
        sender_wallet_pk: <[u8; 32]>::try_from(transaction.client_pk.as_slice()).ok(),
        oracle_claim,
        // YPX-022 RECALL: stamp the recalled txid onto a recall cheque (bound into the
        // commitment). None for every non-recall cheque → byte-identical.
        recall_target_tx_id: if transaction.is_recall() {
            transaction.recall_target_tx_id
        } else {
            None
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Transaction, TxKind};

    fn tx() -> Transaction {
        Transaction {
            sender_wallet_id: "alice@a/00000000".into(),
            receiver_wallet_id: "bob@b/11111111".into(),
            client_pk: alloc::vec![0x42u8; 32],
            amount: 5_000,
            reference: "trade".into(),
            epoch: 1_700_000_000,
            kind: TxKind::Normal,
            ..Default::default()
        }
    }

    // The shared builder derives every tx-side field and takes the rest from the
    // issuer context — the k=0 offline issuer (sender's wallet key, no VBC, 0 fee).
    #[test]
    fn build_cheque_unsigned_k0_issuer_maps_fields() {
        let t = tx();
        let issuer = ChequeIssuerContext {
            issuer_id: [0x11u8; 32],
            issuer_pk: alloc::vec![0x42u8; 32], // sender's wallet key
            vbc_bundle: None,                   // offline: no validators
            carrier_type: "ark".into(),
            carrier_address: String::new(),
            rate_bps: 0, // no online fee offline
            created_at: 12_345,
        };
        let c = build_cheque_unsigned(
            &t, [0xABu8; 32], [1u8; 32], [2u8; 32], None, &[9u8; 4], None, 0,
            [3u8; 32], [4u8; 32], None, None, alloc::vec::Vec::new(), &issuer,
        );

        assert!(c.signature.is_empty(), "builder leaves signing to the caller");
        assert_eq!(c.validator_id, [0x11u8; 32]);
        assert!(c.vbc_bundle.is_none(), "k=0 offline cheque has no VBC bundle");
        assert_eq!(c.rate_bps, 0);
        assert_eq!(c.created_at, 12_345);
        // Derived from the tx:
        assert_eq!(c.txid, [0xABu8; 32]);
        assert_eq!(c.sender_wallet_id, t.sender_wallet_id);
        assert_eq!(c.receiver_wallet_id, t.receiver_wallet_id);
        assert_eq!(c.amount, 5_000);
        assert_eq!(c.sender_wallet_pk, Some([0x42u8; 32]));
        assert!(c.recall_target_tx_id.is_none());
        // The commitment is computable over the built cheque (what the caller signs).
        let _ = crate::compute::compute_cheque_commitment(
            &c.txid, &c.state_hash, &c.produced_state_id, &c.sender_wallet_id, &c.receiver_wallet_id,
            c.amount, c.epoch, c.created_at, c.rate_bps, &c.dmap_input_hash, &c.dmap_output_hash,
            c.oracle_claim.as_ref(), c.recall_target_tx_id.as_ref(),
        );
    }
}
