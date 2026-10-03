//! DEV / TEST TOOL — re-seal a captured UMP envelope for a different validator.
//!
//! Used ONLY by the soak's double-redeem adversary (`tests/soak_test_v2.py`,
//! 2026-09-26). A wallet's redeem envelope is sealed to ONE validator
//! (`transport_crypto::seal_to_validator`), so a byte-for-byte copy sent to
//! another validator is dropped at ANTIE as undecryptable — it never reaches
//! the replay defence under test. A real attacker is the wallet owner and
//! holds the plaintext it built; this tool recovers that plaintext with the
//! ORIGINAL recipient's key (which the local test harness has) and seals it to
//! the new recipient — exactly what a patched SDK would send. It uses Core's
//! own seal/open (one builder, RULE 1); it adds no capability to any shipped
//! binary.
//!
//!   reseal_envelope <body.b64> <orig_ed25519_seed_file> <new_recipient_ed25519_pk_hex>
//!   → the new body (base64) on stdout
use axiom_core_logic::envelope::UmpEnvelope;
use axiom_core_logic::transport_crypto::{ed25519_sk_to_x25519_sk, open_for_validator, seal_to_validator};
use base64::Engine as _;
use std::process::exit;

fn die(msg: &str) -> ! {
    eprintln!("reseal_envelope: {msg}");
    exit(2)
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 4 {
        die("usage: reseal_envelope <body.b64> <orig_ed25519_seed_file> <new_recipient_ed25519_pk_hex>");
    }
    let b64: String = std::fs::read_to_string(&a[1]).unwrap_or_else(|e| die(&format!("read body: {e}")))
        .chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).unwrap_or_else(|e| die(&format!("base64: {e}")));
    let env = UmpEnvelope::from_cbor(&bytes).unwrap_or_else(|| die("body is not a UmpEnvelope"));
    let seed = std::fs::read(&a[2]).unwrap_or_else(|e| die(&format!("read key: {e}")));
    let seed: [u8; 32] = seed.as_slice().try_into().unwrap_or_else(|_| die("key file is not a 32-byte Ed25519 seed"));
    let orig_pk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let plain = match &env {
        UmpEnvelope::Plain { ump_bytes } => ump_bytes.clone(),
        UmpEnvelope::Encrypted { .. } => open_for_validator(&env, &orig_pk, &ed25519_sk_to_x25519_sk(&seed))
            .unwrap_or_else(|e| die(&format!("open with the original recipient's key failed: {e:?}"))),
    };
    let new_pk: [u8; 32] = hex::decode(a[3].trim()).ok().and_then(|v| v.try_into().ok())
        .unwrap_or_else(|| die("new recipient pk must be 64 hex chars"));
    let sealed = seal_to_validator(&new_pk, &plain).unwrap_or_else(|e| die(&format!("seal: {e:?}")));
    let out = sealed.to_cbor().unwrap_or_else(|| die("encode"));
    println!("{}", base64::engine::general_purpose::STANDARD.encode(out));
}
