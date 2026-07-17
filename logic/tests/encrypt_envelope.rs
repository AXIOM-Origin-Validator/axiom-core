//! Integration tests for the forward-direction UMP envelope.
//!
//! Pins the wire-format and seal/unseal contract from
//! `docs/AXIOM_DESIGN_PublicMailCarriers.md` §3.  These run in the host
//! `std` build only — the AVM guest doesn't see envelope code (it's
//! transport-layer, not protocol).

use axiom_core_logic::envelope::UmpEnvelope;
use axiom_core_logic::transport_crypto::{
    ed25519_pk_to_x25519_pk, ed25519_sk_to_x25519_sk,
    open_for_validator, seal_to_validator, EnvelopeCryptoError,
};
use ed25519_dalek::SigningKey;

fn validator_kp(seed: u8) -> ([u8; 32], [u8; 32]) {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    (sk.to_bytes(), sk.verifying_key().to_bytes())
}

#[test]
fn wallet_to_validator_round_trip() {
    let (alpha_sk_seed, alpha_pk) = validator_kp(0x11);
    let plaintext = b"the inner CBOR-UMP body the wallet wants to deliver".to_vec();

    // Wallet seals to alpha.
    let env = seal_to_validator(&alpha_pk, &plaintext).expect("seal");
    // Wire round-trip through CBOR (every hop encodes once).
    let cbor = env.to_cbor().expect("envelope encode");
    let on_the_wire = UmpEnvelope::from_cbor(&cbor).expect("envelope decode");

    // Alpha's ANTIE derives X25519 from its own Ed25519 seed and opens.
    let alpha_xsk = ed25519_sk_to_x25519_sk(&alpha_sk_seed);
    let opened = open_for_validator(&on_the_wire, &alpha_pk, &alpha_xsk).expect("open");
    assert_eq!(opened, plaintext, "round-trip plaintext must match");
}

#[test]
fn cross_validator_decrypt_fails() {
    // Beta cannot open a message sealed to alpha — §3.5 cross-validator
    // pollution defence.
    let (_alpha_sk, alpha_pk) = validator_kp(0x11);
    let (beta_sk, beta_pk) = validator_kp(0x22);
    let env = seal_to_validator(&alpha_pk, b"for alpha only").expect("seal");
    let beta_xsk = ed25519_sk_to_x25519_sk(&beta_sk);
    let err = open_for_validator(&env, &beta_pk, &beta_xsk).unwrap_err();
    assert_eq!(err, EnvelopeCryptoError::WrongRecipient);
}

#[test]
fn forged_recipient_id_still_aead_rejects() {
    // Attacker rewrites recipient_id to look like Beta's pubkey, but
    // the ciphertext stays sealed to alpha's X25519.  Beta's fast
    // pre-check passes (matching id) → AEAD fails → silent drop.
    let (_alpha_sk, alpha_pk) = validator_kp(0x11);
    let (beta_sk, beta_pk) = validator_kp(0x22);
    let mut env = seal_to_validator(&alpha_pk, b"target alpha").expect("seal");
    if let UmpEnvelope::Encrypted { ref mut recipient_id, .. } = env {
        *recipient_id = beta_pk;
    }
    let beta_xsk = ed25519_sk_to_x25519_sk(&beta_sk);
    let err = open_for_validator(&env, &beta_pk, &beta_xsk).unwrap_err();
    assert_eq!(err, EnvelopeCryptoError::DecryptFailed);
}

#[test]
fn pubkey_conversion_round_trip_is_consistent() {
    // The Ed25519 SK→X25519 derivation must produce a key whose public
    // counterpart matches the Ed25519 PK→X25519 derivation.  If this
    // breaks, every encrypted envelope ends up undecryptable — the
    // most load-bearing invariant in the whole feature.
    for seed_byte in [0x42u8, 0x99, 0xAB, 0x01, 0xFE] {
        let (sk_seed, pk) = validator_kp(seed_byte);
        let x_sk = ed25519_sk_to_x25519_sk(&sk_seed);
        let x_pub_from_sk = {
            let s = x25519_dalek::StaticSecret::from(x_sk);
            *x25519_dalek::PublicKey::from(&s).as_bytes()
        };
        let x_pub_from_pk = ed25519_pk_to_x25519_pk(&pk).expect("ed25519 pk valid");
        assert_eq!(
            x_pub_from_sk, x_pub_from_pk,
            "seed 0x{:02x}: sk-derived and pk-derived X25519 pubkeys must agree",
            seed_byte,
        );
    }
}

#[test]
fn distinct_seals_to_same_validator_yield_distinct_ciphertexts() {
    // Two seals of the same plaintext to the same recipient must
    // produce different ephemerals and different ciphertexts — catches
    // an accidental RNG replacement with something deterministic.
    let (_sk, pk) = validator_kp(0x11);
    let a = seal_to_validator(&pk, b"same input").expect("seal");
    let b = seal_to_validator(&pk, b"same input").expect("seal");
    let (ea, ca) = match a {
        UmpEnvelope::Encrypted { ephemeral_pk, ciphertext, .. } => (ephemeral_pk, ciphertext),
        _ => panic!("expected Encrypted"),
    };
    let (eb, cb) = match b {
        UmpEnvelope::Encrypted { ephemeral_pk, ciphertext, .. } => (ephemeral_pk, ciphertext),
        _ => panic!("expected Encrypted"),
    };
    assert_ne!(ea, eb, "fresh ephemeral per message");
    assert_ne!(ca, cb, "distinct ciphertexts");
}

#[test]
fn envelope_wire_size_overhead_is_reasonable() {
    // Sanity check on transport bloat — Encrypted is recipient_id (32) +
    // ephemeral_pk (32) + ciphertext (plaintext + 16 AEAD tag) + CBOR
    // map overhead.  An empty body shouldn't balloon to kilobytes.
    let (_sk, pk) = validator_kp(0x11);
    let env = seal_to_validator(&pk, b"").expect("seal");
    let cbor = env.to_cbor().expect("encode");
    // Conservative upper bound: 32 + 32 + 16 + ~32 CBOR overhead = ~112.
    // Leave a wide margin for serde-derive's external-tag encoding.
    assert!(cbor.len() < 256, "empty seal exploded to {} bytes", cbor.len());
}
