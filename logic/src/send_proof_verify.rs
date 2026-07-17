//! Offline, Core-attested verification of a retained Send Proof.
//!
//! The SDK-side `axiom_sdk_core::send_proof::verify_send_proof` is a *library*
//! check: it confirms k keys signed the commitment, but NOT that those keys
//! belong to real validators. A forger can therefore mint a "VALID" proof with
//! throwaway keys (see `sdk/examples/real_proof_demo.rs`).
//!
//! This function runs INSIDE the Core ELF (mode `CL12`) and adds the decisive
//! check the library path omits: **every witnessing validator must present a
//! VBC that chains to the genesis `ROOT_AUTHORITY_PKS`** (the same anchor CL2/CL3
//! enforce during the live witness round). Forging that requires the genesis
//! root authority's SPHINCS+ keys, which exist only in the ceremony — so a
//! fabricated proof is rejected.
//!
//! Because it is an ordinary Core mode, the verdict is produced by the canonical
//! ELF and is reproducible by the DMAP-VM (fast, local) or attestable by the
//! zkVM (a zero-knowledge receipt a third party verifies against the published
//! CoreID without trusting the verifier's machine). The verdict is Core's, not
//! the SDK's.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::errors::CoreResult;
use crate::types::{Receipt, Transaction, ValidationError};

/// Distinct-witness floor — mirrors the consensus k=3 minimum.
const MIN_WITNESSES: usize = 3;

/// Recompute the `AXIOM_WITNESS_V2` commitment a validator signs. Byte-identical
/// to the consensus commitment in `validation.rs` — the source of truth.
fn witness_commitment(tx: &Transaction) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_WITNESS_V2");
    h.update(&tx.consumed_state_id);
    h.update(&tx.client_pk);
    h.update(&tx.wallet_seq.to_le_bytes());
    h.update(tx.receiver_wallet_id.as_bytes());
    h.update(&tx.amount.to_le_bytes());
    h.update(&tx.nonce.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Verify a retained Send Proof (signed transaction + finalized receipt) to
/// Core's standard, INCLUDING validator legitimacy.
///
/// `now` is the time used for VBC expiry. Pass the **receipt's epoch** so the
/// question asked is "were these legitimate validators *when they witnessed*
/// this transaction?", not "are their VBCs still unexpired today" — a validator
/// whose VBC has since expired still validly witnessed the historical send.
///
/// Returns `Ok(())` only if ALL hold:
///  1. the receipt attests this exact transaction (txid binds),
///  2. the payer's client signature authorizes the terms,
///  3. the witnessed commitment binds this tx's receiver + amount,
///  4. the receipt's own commitment binds all its fields,
///  5. every witness is distinct, validly signed the commitment, AND presents a
///     VBC chaining to `ROOT_AUTHORITY_PKS` whose subject key is the signer,
///  6. at least `max(required_k, 3)` witnesses are present.
pub fn verify_send_proof_core(tx: &Transaction, receipt: &Receipt, now: u64) -> CoreResult<()> {
    // (1) the receipt attests THIS transaction.
    if crate::compute::compute_txid(tx) != receipt.txid {
        return Err(ValidationError::InvalidWitnessSignature);
    }
    // (2) the payer authorized these exact terms (binds receiver, amount, reference).
    crate::validation::verify_client_signature_public(tx)?;
    // (3) the witnessed commitment binds this tx's receiver + amount.
    let commitment = witness_commitment(tx);
    if receipt.commitment_hash == [0u8; 32] || commitment != receipt.commitment_hash {
        return Err(ValidationError::InvalidWitnessSignature);
    }
    // (4) the receipt's own commitment binds all its fields (k validators signed it).
    if !crate::receipt::verify_receipt_commitment(receipt) {
        return Err(ValidationError::InvalidWitnessSignature);
    }
    // (5) every witness: distinct + valid Ed25519 over the commitment + a VBC
    //     chaining to the genesis root authority. (5) is the forgery-closer.
    let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
    for ws in &receipt.witness_sigs {
        if !seen.insert(ws.validator_pk.clone()) {
            return Err(ValidationError::DuplicateValidator);
        }
        crate::verify::verify_ed25519(&ws.validator_pk, &receipt.commitment_hash, &ws.signature)
            .map_err(|_| ValidationError::InvalidWitnessSignature)?;
        // The decisive check: the signer must be a legitimate validator, proven
        // by a VBC that recursively verifies (SPHINCS+) back to ROOT_AUTHORITY_PKS.
        let bundle = ws.vbc_bundle.as_ref().ok_or(ValidationError::InvalidVBC)?;
        crate::vbc::verify_vbc_bundle(bundle, now)?;
        // Bind the signing key to the VBC subject — no key swap.
        if bundle.target_vbc.subject_pubkey_ed25519 != ws.validator_pk {
            return Err(ValidationError::InvalidVBC);
        }
    }
    // (6) k floor.
    let need = (receipt.required_k as usize).max(MIN_WITNESSES);
    if receipt.witness_sigs.len() < need {
        return Err(ValidationError::InvalidVBCCount);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Receipt, Transaction, WitnessSig};
    use alloc::string::ToString;
    use alloc::{vec, vec::Vec};
    use ed25519_dalek::{Signer, SigningKey};

    /// Build a proof with ALL signatures valid — real client sig, real Ed25519
    /// witness sigs over the real commitment, valid receipt_commitment — but
    /// `vbc_bundle: None` on every witness. This is EXACTLY the shape a forger
    /// produces (and that the SDK-only `verify_send_proof` accepts): k throwaway
    /// keys signing a well-formed commitment. Core must reject it.
    fn forged_proof_all_sigs_valid_no_vbc() -> (Transaction, Receipt) {
        let core_id = [9u8; 32];
        let client = SigningKey::from_bytes(&[7u8; 32]);
        let message = b"Invoice INV-2026-0815";
        let reference = blake3::hash(message).to_hex().to_string();
        let mut tx = Transaction {
            consumed_state_id: [4u8; 32],
            client_pk: client.verifying_key().to_bytes().to_vec(),
            sender_wallet_id: "treasury@acme-bank.com/a3f7b2c1".to_string(),
            wallet_seq: 7,
            receiver_wallet_id: "payments@vendor-co.com/9e4d1f08".to_string(),
            amount: 250_000_000_000,
            reference,
            nonce: 4_418_205,
            epoch: 1771,
            core_id,
            ..Default::default()
        };
        let sig_msg = crate::validation::compute_signing_message_public(&tx);
        tx.client_sig = client.sign(&sig_msg).to_bytes().to_vec();

        let txid = crate::compute::compute_txid(&tx);
        let commitment = witness_commitment(&tx);
        let mk_ws = |seed: u8| -> WitnessSig {
            let v = SigningKey::from_bytes(&[seed; 32]);
            WitnessSig {
                validator_id: [seed; 32],
                validator_pk: v.verifying_key().to_bytes().to_vec(),
                vbc_bundle: None, // <-- forger has no genesis-anchored VBC
                carrier_type: alloc::string::String::new(),
                carrier_address: alloc::string::String::new(),
                signature: v.sign(&commitment).to_bytes().to_vec(),
                execution_proof: Vec::new(),
                proof_type: 0,
                availability_attestation: None,
                validator_hints: Vec::new(),
                fact_signature: None,
                checkpoint_sig: None,
                receipt_signature: None,
                receipt_commitment_sig: None,
                rate_bps: 0,
                slot_amount: 0,
            }
        };
        let state_hash = [1u8; 32];
        let receipt = Receipt {
            oods_flag: None,
            txid,
            state_hash,
            produced_state_id: [2u8; 32],
            new_wallet_seq: tx.wallet_seq,
            commitment_hash: commitment,
            sdid: [3u8; 32],
            lineage_hash: [0u8; 32],
            core_version: alloc::string::String::new(),
            core_id,
            witness_sigs: vec![mk_ws(11), mk_ws(12), mk_ws(13)],
            epoch: tx.epoch,
            fact_proof: None,
            required_k: 3,
            receipt_commitment: crate::compute::compute_receipt_commitment(
                &txid, &state_hash, tx.wallet_seq, &commitment, tx.epoch, false, None,
            ),
            fee_breakdown: Vec::new(),
            is_dev_class: false,
        };
        (tx, receipt)
    }

    #[test]
    fn forged_proof_with_valid_sigs_but_no_vbc_is_rejected() {
        let (tx, receipt) = forged_proof_all_sigs_valid_no_vbc();
        // Every signature is cryptographically valid — the SDK verifier accepts
        // this exact proof. Core rejects it because no witness proves it is a
        // real validator (no VBC chaining to ROOT_AUTHORITY_PKS).
        let verdict = verify_send_proof_core(&tx, &receipt, receipt.epoch);
        assert_eq!(verdict, Err(ValidationError::InvalidVBC), "forged proof must be rejected at the VBC gate");
    }

    #[test]
    fn tampered_transaction_is_rejected_before_the_vbc_gate() {
        let (mut tx, receipt) = forged_proof_all_sigs_valid_no_vbc();
        // Flip the amount after signing — txid/commitment no longer match.
        tx.amount += 1;
        assert!(verify_send_proof_core(&tx, &receipt, receipt.epoch).is_err());
    }

    #[test]
    fn fewer_than_k_witnesses_is_rejected() {
        let (tx, mut receipt) = forged_proof_all_sigs_valid_no_vbc();
        receipt.witness_sigs.truncate(1);
        // Still fails (at the VBC gate, before the count gate — both reject).
        assert!(verify_send_proof_core(&tx, &receipt, receipt.epoch).is_err());
    }
}
