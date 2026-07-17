//! Transport-layer encryption helpers for UMP envelopes (host only).
//!
//! Sealing primitive is a sealed-box construction with:
//!   - X25519 ECDH (per-message ephemeral × static recipient pubkey)
//!   - ChaCha20-Poly1305 AEAD
//!   - Deterministic 12-byte nonce derived from
//!     `blake3(ephemeral_pk || recipient_x25519_pk)[..12]`
//!
//! Per-message ephemerals make the nonce-derivation safe under a
//! single recipient (no nonce-reuse: every ephemeral_pk is fresh).
//!
//! See `docs/AXIOM_DESIGN_PublicMailCarriers.md` §3.2.  This module
//! is **transport** crypto — it does not touch Core's protocol crypto
//! and never compiles into the AVM guest.

use crate::envelope::UmpEnvelope;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::VerifyingKey;
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XSecret};

/// Errors returned by transport-crypto helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeCryptoError {
    /// The Ed25519 pubkey bytes did not decode as a valid curve point.
    InvalidEd25519Pubkey,
    /// AEAD encryption failed (out-of-memory or internal error — never
    /// returned in practice for well-formed inputs).
    EncryptFailed,
    /// AEAD decryption failed: wrong key, ciphertext tampered, or
    /// envelope addressed to a different recipient.
    DecryptFailed,
    /// The envelope's `recipient_id` did not match our validator pubkey.
    /// Fast pre-check before attempting decryption.
    WrongRecipient,
    /// Caller asked to unseal a `Plain` envelope (programmer error —
    /// route Plain via the existing unencrypted path).
    NotEncrypted,
}

impl core::fmt::Display for EnvelopeCryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidEd25519Pubkey => write!(f, "invalid Ed25519 pubkey"),
            Self::EncryptFailed => write!(f, "envelope encryption failed"),
            Self::DecryptFailed => write!(f, "envelope decryption failed"),
            Self::WrongRecipient => write!(f, "envelope recipient_id does not match this validator"),
            Self::NotEncrypted => write!(f, "envelope is Plain, not Encrypted"),
        }
    }
}

impl std::error::Error for EnvelopeCryptoError {}

/// Convert an Ed25519 public key (32 bytes) to its X25519 equivalent.
///
/// Both keys share the same underlying Curve25519 group; `to_montgomery`
/// performs the deterministic map.  Returns 32 raw bytes of X25519 pubkey.
pub fn ed25519_pk_to_x25519_pk(ed_pk: &[u8; 32]) -> Result<[u8; 32], EnvelopeCryptoError> {
    let vk = VerifyingKey::from_bytes(ed_pk).map_err(|_| EnvelopeCryptoError::InvalidEd25519Pubkey)?;
    Ok(vk.to_montgomery().to_bytes())
}

/// Convert an Ed25519 secret key seed (32 bytes) to its X25519
/// equivalent.  Standard NaCl conversion:
///   `x25519_sk = clamp(SHA-512(seed)[..32])`
///
/// The clamping (clear low 3 bits, clear high bit, set second-high bit)
/// is what X25519 expects — `StaticSecret::from(bytes)` does the clamp
/// itself, but we apply it explicitly here so the value matches what
/// `crypto_sign_ed25519_sk_to_curve25519` would emit byte-for-byte.
pub fn ed25519_sk_to_x25519_sk(ed_sk_seed: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha512};
    let mut h = Sha512::new();
    h.update(ed_sk_seed);
    let out = h.finalize();
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&out[..32]);
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
    sk
}

/// 12-byte ChaCha20Poly1305 nonce derived deterministically from the
/// envelope's public values.  Safe under the per-message ephemeral
/// (a fresh `ephemeral_pk` ⇒ a fresh nonce) — no global counter needed.
fn derive_nonce(ephemeral_pk: &[u8; 32], recipient_x25519_pk: &[u8; 32]) -> [u8; 12] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_UMP_ENVELOPE_NONCE_v1");
    hasher.update(ephemeral_pk);
    hasher.update(recipient_x25519_pk);
    let h = hasher.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&h.as_bytes()[..12]);
    nonce
}

/// Derive the ChaCha20Poly1305 symmetric key from the X25519 shared
/// secret.  BLAKE3 with a domain tag — never hand the raw DH output to
/// AEAD directly.
fn derive_aead_key(shared: &[u8; 32]) -> Key {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_UMP_ENVELOPE_KEY_v1");
    hasher.update(shared);
    let h = hasher.finalize();
    *Key::from_slice(h.as_bytes())
}

/// Seal a UMP body to a recipient validator's Ed25519 pubkey.
///
/// `recipient_ed25519_pk` is read from `seeds/validators.list` (4th
/// column).  Returns a fully-formed `UmpEnvelope::Encrypted`.
pub fn seal_to_validator(
    recipient_ed25519_pk: &[u8; 32],
    ump_bytes: &[u8],
) -> Result<UmpEnvelope, EnvelopeCryptoError> {
    let recipient_x = ed25519_pk_to_x25519_pk(recipient_ed25519_pk)?;
    let recipient_xpub = XPublicKey::from(recipient_x);

    // Per-message ephemeral X25519 keypair.  StaticSecret (not
    // EphemeralSecret) so we can read the public side and serialize.
    let mut eph_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut eph_bytes);
    let eph_secret = XSecret::from(eph_bytes);
    let eph_public = XPublicKey::from(&eph_secret);

    let shared = eph_secret.diffie_hellman(&recipient_xpub);
    let key = derive_aead_key(shared.as_bytes());
    let nonce_bytes = derive_nonce(eph_public.as_bytes(), &recipient_x);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new(&key);
    let ciphertext = cipher
        .encrypt(nonce, ump_bytes)
        .map_err(|_| EnvelopeCryptoError::EncryptFailed)?;

    Ok(UmpEnvelope::Encrypted {
        recipient_id: *recipient_ed25519_pk,
        ephemeral_pk: *eph_public.as_bytes(),
        ciphertext,
    })
}

/// Unseal an `Encrypted` envelope using this validator's Ed25519 secret.
///
/// `our_ed25519_pk` is the validator's Ed25519 pubkey — checked against
/// the envelope's `recipient_id` for a fast misroute reject before
/// attempting decryption.
pub fn open_for_validator(
    env: &UmpEnvelope,
    our_ed25519_pk: &[u8; 32],
    our_x25519_sk: &[u8; 32],
) -> Result<Vec<u8>, EnvelopeCryptoError> {
    let (recipient_id, ephemeral_pk, ciphertext) = match env {
        UmpEnvelope::Encrypted { recipient_id, ephemeral_pk, ciphertext } => {
            (recipient_id, ephemeral_pk, ciphertext)
        }
        UmpEnvelope::Plain { .. } => return Err(EnvelopeCryptoError::NotEncrypted),
    };
    if recipient_id != our_ed25519_pk {
        return Err(EnvelopeCryptoError::WrongRecipient);
    }
    let our_xsk = XSecret::from(*our_x25519_sk);
    let their_xpub = XPublicKey::from(*ephemeral_pk);
    let shared = our_xsk.diffie_hellman(&their_xpub);
    let key = derive_aead_key(shared.as_bytes());
    let our_xpub_bytes = ed25519_pk_to_x25519_pk(our_ed25519_pk)?;
    let nonce_bytes = derive_nonce(ephemeral_pk, &our_xpub_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = ChaCha20Poly1305::new(&key);
    cipher
        .decrypt(nonce, ciphertext.as_slice())
        .map_err(|_| EnvelopeCryptoError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn alpha_keypair() -> ([u8; 32], [u8; 32]) {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let pk = sk.verifying_key();
        (sk.to_bytes(), pk.to_bytes())
    }

    fn beta_keypair() -> ([u8; 32], [u8; 32]) {
        let sk = SigningKey::from_bytes(&[0x99; 32]);
        let pk = sk.verifying_key();
        (sk.to_bytes(), pk.to_bytes())
    }

    #[test]
    fn ed25519_to_x25519_pk_is_deterministic() {
        let (_, pk) = alpha_keypair();
        let x1 = ed25519_pk_to_x25519_pk(&pk).unwrap();
        let x2 = ed25519_pk_to_x25519_pk(&pk).unwrap();
        assert_eq!(x1, x2);
    }

    #[test]
    fn ed25519_to_x25519_sk_is_deterministic_and_clamped() {
        let (sk, _) = alpha_keypair();
        let x1 = ed25519_sk_to_x25519_sk(&sk);
        let x2 = ed25519_sk_to_x25519_sk(&sk);
        assert_eq!(x1, x2);
        // Clamp invariants
        assert_eq!(x1[0] & 0b00000111, 0, "low 3 bits must be clear");
        assert_eq!(x1[31] & 0b10000000, 0, "high bit must be clear");
        assert_eq!(x1[31] & 0b01000000, 0b01000000, "bit 6 of last byte must be set");
    }

    #[test]
    fn sk_pk_conversion_agrees() {
        // The X25519 public key derived from the converted Ed25519
        // secret must equal the X25519 public key derived directly
        // from the Ed25519 public key.  This is the load-bearing
        // invariant for the whole construction.
        let (sk, pk) = alpha_keypair();
        let x_sk = ed25519_sk_to_x25519_sk(&sk);
        let xsk = XSecret::from(x_sk);
        let xpub_from_sk = XPublicKey::from(&xsk).to_bytes();
        let xpub_from_pk = ed25519_pk_to_x25519_pk(&pk).unwrap();
        assert_eq!(xpub_from_sk, xpub_from_pk,
            "Ed25519→X25519 secret/public derivations must agree");
    }

    #[test]
    fn seal_and_open_round_trip() {
        let (alpha_sk, alpha_pk) = alpha_keypair();
        let plaintext = b"hello UMP world".to_vec();
        let env = seal_to_validator(&alpha_pk, &plaintext).unwrap();
        let alpha_xsk = ed25519_sk_to_x25519_sk(&alpha_sk);
        let opened = open_for_validator(&env, &alpha_pk, &alpha_xsk).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn seal_and_open_round_trip_through_cbor() {
        let (alpha_sk, alpha_pk) = alpha_keypair();
        let plaintext = b"survives a CBOR round trip".to_vec();
        let env = seal_to_validator(&alpha_pk, &plaintext).unwrap();
        let cbor = env.to_cbor().unwrap();
        let back = UmpEnvelope::from_cbor(&cbor).unwrap();
        let alpha_xsk = ed25519_sk_to_x25519_sk(&alpha_sk);
        let opened = open_for_validator(&back, &alpha_pk, &alpha_xsk).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn wrong_recipient_fails_fast() {
        // Beta cannot open a message sealed to Alpha.
        let (_alpha_sk, alpha_pk) = alpha_keypair();
        let (beta_sk, beta_pk) = beta_keypair();
        let env = seal_to_validator(&alpha_pk, b"for alpha only").unwrap();
        let beta_xsk = ed25519_sk_to_x25519_sk(&beta_sk);
        let err = open_for_validator(&env, &beta_pk, &beta_xsk).unwrap_err();
        assert_eq!(err, EnvelopeCryptoError::WrongRecipient);
    }

    #[test]
    fn forged_recipient_id_still_fails() {
        // An attacker rewrites recipient_id to look like Beta's pubkey
        // but the ciphertext is still sealed to Alpha's X25519.
        // Beta's fast pre-check passes (matching pubkey), then AEAD fails.
        let (_alpha_sk, alpha_pk) = alpha_keypair();
        let (beta_sk, beta_pk) = beta_keypair();
        let env = seal_to_validator(&alpha_pk, b"target alpha").unwrap();
        let mut forged = env;
        if let UmpEnvelope::Encrypted { ref mut recipient_id, .. } = forged {
            *recipient_id = beta_pk;
        }
        let beta_xsk = ed25519_sk_to_x25519_sk(&beta_sk);
        let err = open_for_validator(&forged, &beta_pk, &beta_xsk).unwrap_err();
        assert_eq!(err, EnvelopeCryptoError::DecryptFailed);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (alpha_sk, alpha_pk) = alpha_keypair();
        let env = seal_to_validator(&alpha_pk, b"original").unwrap();
        let mut tampered = env;
        if let UmpEnvelope::Encrypted { ref mut ciphertext, .. } = tampered {
            ciphertext[0] ^= 0x01;
        }
        let alpha_xsk = ed25519_sk_to_x25519_sk(&alpha_sk);
        let err = open_for_validator(&tampered, &alpha_pk, &alpha_xsk).unwrap_err();
        assert_eq!(err, EnvelopeCryptoError::DecryptFailed);
    }

    #[test]
    fn open_rejects_plain_variant() {
        let (alpha_sk, alpha_pk) = alpha_keypair();
        let env = UmpEnvelope::Plain { ump_bytes: vec![1, 2, 3] };
        let alpha_xsk = ed25519_sk_to_x25519_sk(&alpha_sk);
        let err = open_for_validator(&env, &alpha_pk, &alpha_xsk).unwrap_err();
        assert_eq!(err, EnvelopeCryptoError::NotEncrypted);
    }

    #[test]
    fn distinct_seals_produce_distinct_ephemerals() {
        // Two seals of the same plaintext to the same recipient must
        // produce different ephemeral_pk (and thus different nonces /
        // ciphertexts).  Catches a regression where someone replaces
        // OsRng with a deterministic source.
        let (_, alpha_pk) = alpha_keypair();
        let a = seal_to_validator(&alpha_pk, b"same").unwrap();
        let b = seal_to_validator(&alpha_pk, b"same").unwrap();
        match (a, b) {
            (
                UmpEnvelope::Encrypted { ephemeral_pk: ea, ciphertext: ca, .. },
                UmpEnvelope::Encrypted { ephemeral_pk: eb, ciphertext: cb, .. },
            ) => {
                assert_ne!(ea, eb, "two seals must use fresh ephemerals");
                assert_ne!(ca, cb, "two seals must produce distinct ciphertext");
            }
            _ => panic!("expected Encrypted variants"),
        }
    }
}
