//! AXIOM zkVM Guest — Minimal ZK Boundary
//!
//! This guest runs inside the RISC Zero zkVM. It implements a MINIMAL
//! ZK checkpoint that proves the essential transaction invariants:
//!
//!   1. Client authorized the transaction (Ed25519 signature — precompile)
//!   2. Balance cannot be inflated (S-ABR state binding + balance check)
//!   3. State chain is continuous (produced_state_id via SHA3)
//!   4. Anti-replay (zkp_nonce + wallet_seq)
//!   5. Protocol rules (dust limit, scar cap, burn consistency, VBC expiry)
//!
//! Everything else (Dilithium FACT signing, FACT chain verification,
//! witness validation, txid, commitment_hash) is executed by Core NATIVELY
//! on the host. The txid is passed as lightweight FactCargo.
//!
//! # Precompiles Used (all zero circuit overhead)
//!
//! - Ed25519 signature verification (curve25519-dalek risc0 fork)
//! - SHA256 for input_hash (risc0 built-in, guest-internal — not cross-checked)
//!
//! # Software Crypto (runs in RISC-V, counted as cycles)
//!
//! - SHA3-256 for produced_state_id (tiny-keccak, protocol-defined)
//! - BLAKE3 for zkp_nonce_hash, fact_commitment (protocol-defined)
//! - Ed25519 derived key for auth_hash / owner_proof (see axiom_core_logic::owner_proof)
//!
//! # Hash Function Rules
//!
//! Any hash that is CROSS-CHECKED by Lambda/Nabla MUST use the same function
//! and domain tag as the protocol definition. Currently:
//!   - zkp_nonce_hash: BLAKE3("AXIOM_ZKP_NONCE" || nonce) — verified by Lambda
//!   - fact_commitment: BLAKE3("AXIOM_FACT" || ...) — verified by Lambda
//!   - input_hash: SHA256 precompile (guest-internal, not cross-checked)

#![no_main]
#![no_std]

extern crate alloc;
use alloc::vec::Vec;

use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256};
use axiom_dmap_vm::PublicInputs;
use axiom_core_logic::{FactCargo, execute_cl3_zkp_checkpoint};

risc0_zkvm::guest::entry!(main);

/// SHA256 hash via risc0 built-in precompile (zero cycle cost).
/// ONLY for guest-internal hashes (input_hash). NOT for protocol hashes.
fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let digest = Impl::hash_bytes(data);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(digest.as_bytes());
    hash
}

pub fn main() {
    // 1. Read inputs from host as a CBOR-bytes frame (self-describing — matches
    //    the DMAP guest at core/avm-guest/src/main.rs:78). The OUTER carrier is a
    //    plain `Vec<u8>` over risc0's stable word-serde (a byte vec round-trips
    //    symmetrically); the INNER payload is CBOR. We must NOT word-serde the
    //    struct directly: that format is non-self-describing and silently drops
    //    `#[serde(skip_serializing_if = "Option::is_none")]` fields (e.g.
    //    WalletState.wallet_id), which desyncs the positional read from the
    //    host's write and trips DeserializeUnexpectedEnd. CBOR honors the attr.
    let inputs_frame: alloc::vec::Vec<u8> = env::read();
    let inputs: PublicInputs = ciborium::de::from_reader(&inputs_frame[..])
        .expect("guest: decode PublicInputs CBOR frame");

    // 2. Read FACT cargo — lightweight struct with just txid — same CBOR framing.
    //    fact_signature (3,309 bytes) stays on host — attached post-proving.
    let cargo_frame: alloc::vec::Vec<u8> = env::read();
    let fact_cargo: Option<FactCargo> = ciborium::de::from_reader(&cargo_frame[..])
        .expect("guest: decode FactCargo CBOR frame");

    // 3. Compute input_hash — SHA256 of canonical transaction fields (precompile)
    //    This is guest-internal (not cross-checked by anyone), so SHA256 is fine.
    let input_hash = {
        let mut buf = Vec::with_capacity(512);
        buf.extend_from_slice(b"AXIOM_ZKP_INPUT_V2");
        buf.extend_from_slice(&inputs.transaction.consumed_state_id);
        buf.extend_from_slice(&inputs.transaction.client_pk);
        buf.extend_from_slice(&inputs.transaction.wallet_seq.to_le_bytes());
        buf.extend_from_slice(inputs.transaction.receiver_wallet_id.as_bytes());
        buf.extend_from_slice(&inputs.transaction.amount.to_le_bytes());
        buf.extend_from_slice(inputs.transaction.reference.as_bytes());
        buf.extend_from_slice(&inputs.transaction.nonce.to_le_bytes());
        buf.extend_from_slice(&inputs.transaction.epoch.to_le_bytes());
        buf.extend_from_slice(&inputs.transaction.client_sig);
        if let Some(ref state) = inputs.current_state {
            buf.extend_from_slice(&state.public_key);
            buf.extend_from_slice(&state.balance.to_le_bytes());
            buf.extend_from_slice(&state.wallet_seq.to_le_bytes());
            buf.extend_from_slice(&state.state_id);
        }
        if let Some(ref proof) = inputs.transaction.owner_proof {
            buf.extend_from_slice(proof);
        }
        if let Some(ref nonce) = inputs.zkp_nonce {
            buf.extend_from_slice(nonce);
        }
        sha256_hash(&buf)
    };

    // 4. Run minimal ZK checkpoint — 14 cheap checks
    let mut checkpoint = execute_cl3_zkp_checkpoint(&inputs, None);

    // 5. Fill in caller-computed values
    checkpoint.input_hash = input_hash;

    // 5a. ZKP nonce hash — BLAKE3, protocol-defined, cross-checked by Lambda
    //     Lambda recomputes BLAKE3("AXIOM_ZKP_NONCE" || nonce) at CL1 and CL5.
    if let Some(nonce) = inputs.zkp_nonce {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AXIOM_ZKP_NONCE");
        hasher.update(&nonce);
        checkpoint.zkp_nonce_hash = Some(*hasher.finalize().as_bytes());
    }

    // 5b. FACT txid passthrough + fact_commitment binding
    //     fact_signature (3,309 bytes) is NOT inside the guest — host attaches post-proving.
    if let Some(cargo) = fact_cargo {
        checkpoint.txid = cargo.txid;

        // fact_commitment — BLAKE3, protocol-defined, cross-checked by Lambda.
        // Must match compute_fact_commitment() in core/logic/src/fact.rs
        // (AXIOM_FACT_v2 — sender_anchor included; None encodes as 32 zeros).
        if let (Some(produced_sid), Some(txid)) = (checkpoint.produced_state_id, checkpoint.txid) {
            // sender_anchor: extracted from cheque_bundle.fact_chain.tip()
            // for redeem TXs; None (zeros) otherwise.
            let sender_anchor: [u8; 32] = inputs
                .cheque_bundle
                .as_ref()
                .and_then(|cb| cb.fact_chain.as_ref())
                .and_then(|fc| fc.links.last())
                .map(|l| l.new_state_id)
                .unwrap_or([0u8; 32]);
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"AXIOM_FACT_v2");
            hasher.update(&txid);
            hasher.update(&inputs.transaction.consumed_state_id);
            hasher.update(&produced_sid);
            hasher.update(&inputs.transaction.amount.to_le_bytes());
            hasher.update(&sender_anchor);
            checkpoint.fact_commitment = Some(*hasher.finalize().as_bytes());
        }
    }

    // 6. Commit checkpoint outputs to the journal
    env::commit(&checkpoint);
}
