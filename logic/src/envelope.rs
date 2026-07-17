//! UMP transport-envelope wire type.
//!
//! Wraps the existing CBOR-UMP body so the wallet→validator path can
//! carry either a plaintext payload (`Plain`) or one encrypted to the
//! recipient validator's X25519 pubkey (`Encrypted`).  See
//! `docs/AXIOM_DESIGN_PublicMailCarriers.md` §3.
//!
//! This module is `no_std`-clean on purpose: the type is part of the
//! wire format and must round-trip identically on every consumer
//! (SDK, ANTIE, future Mac wallet, Python harness via pyo3).  All
//! crypto helpers — Ed25519↔X25519 conversion and the seal/unseal
//! primitives — live in [`crate::transport_crypto`] and are gated to
//! `std`, so the AVM guest never compiles them.
//!
//! Wire encoding: serde external-tag CBOR, one of:
//!
//! ```text
//!   { "plain":    { "ump_bytes": <bytes> } }
//!   { "encrypted": { "recipient_id": <[u8;32]>,
//!                    "ephemeral_pk": <[u8;32]>,
//!                    "ciphertext":   <bytes> } }
//! ```
//!
//! `recipient_id` is the recipient validator's Ed25519 pubkey — it is
//! an UNencrypted hint so ANTIE can fail fast on misdelivery; the
//! authoritative recipient check is decryption itself (AEAD failure ⇒
//! drop).

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// One UMP message on the wire — either plaintext or sealed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UmpEnvelope {
    /// Plaintext UMP body (existing wire format, wrapped only).
    /// `ump_bytes` is the CBOR-encoded UMP payload exactly as Lambda
    /// and the validator gateway parse it today.
    Plain {
        #[serde(with = "serde_bytes")]
        ump_bytes: Vec<u8>,
    },
    /// UMP body encrypted to the recipient validator's X25519 pubkey.
    /// Sender produced a per-message ephemeral X25519 keypair, ran ECDH
    /// against the validator's X25519 pubkey (derived deterministically
    /// from its Ed25519 pubkey), and sealed with ChaCha20Poly1305.
    Encrypted {
        /// Recipient's Ed25519 pubkey — anti-misroute hint (32 bytes).
        recipient_id: [u8; 32],
        /// Sender's per-message X25519 ephemeral pubkey (32 bytes).
        ephemeral_pk: [u8; 32],
        /// AEAD ciphertext: ChaCha20Poly1305 over the inner UMP bytes,
        /// with a nonce derived deterministically from
        /// `blake3(ephemeral_pk || recipient_x25519_pk)[..12]`.
        #[serde(with = "serde_bytes")]
        ciphertext: Vec<u8>,
    },
}

impl UmpEnvelope {
    /// Encode this envelope as canonical CBOR bytes for the wire.
    /// Returns `None` on serializer error (out-of-memory etc) — the
    /// caller should treat that as a fatal local error.
    pub fn to_cbor(&self) -> Option<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).ok()?;
        Some(buf)
    }

    /// Decode a CBOR-encoded envelope.  Returns `None` if the input is
    /// not a valid `UmpEnvelope`.  Callers that need to support the
    /// pre-envelope wire format (raw UMP CBOR) can fall back to the
    /// existing parse path on `None`.
    pub fn from_cbor(bytes: &[u8]) -> Option<Self> {
        ciborium::from_reader(bytes).ok()
    }
}

// The `serde_bytes` shim is bundled here so the workspace doesn't need
// the separate `serde_bytes` crate.  Wraps `Vec<u8>` so ciborium emits
// it as a CBOR byte-string (major type 2) rather than an array of u8.
mod serde_bytes {
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
                f.write_str("a byte string")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_round_trip() {
        let env = UmpEnvelope::Plain { ump_bytes: vec![1, 2, 3, 4, 5] };
        let cbor = env.to_cbor().expect("encode");
        let back = UmpEnvelope::from_cbor(&cbor).expect("decode");
        assert_eq!(env, back);
    }

    #[test]
    fn encrypted_round_trip() {
        let env = UmpEnvelope::Encrypted {
            recipient_id: [0xAA; 32],
            ephemeral_pk: [0xBB; 32],
            ciphertext: vec![0xCC; 64],
        };
        let cbor = env.to_cbor().expect("encode");
        let back = UmpEnvelope::from_cbor(&cbor).expect("decode");
        assert_eq!(env, back);
    }

    #[test]
    fn plain_and_encrypted_are_distinguishable() {
        let plain = UmpEnvelope::Plain { ump_bytes: vec![1, 2, 3] };
        let encrypted = UmpEnvelope::Encrypted {
            recipient_id: [1; 32],
            ephemeral_pk: [2; 32],
            ciphertext: vec![3, 4, 5],
        };
        let p = plain.to_cbor().unwrap();
        let e = encrypted.to_cbor().unwrap();
        assert_ne!(p, e);
        // A Plain encoding must not parse as an Encrypted variant by accident.
        match UmpEnvelope::from_cbor(&p).unwrap() {
            UmpEnvelope::Plain { .. } => {}
            UmpEnvelope::Encrypted { .. } => panic!("plain decoded as encrypted"),
        }
        match UmpEnvelope::from_cbor(&e).unwrap() {
            UmpEnvelope::Encrypted { .. } => {}
            UmpEnvelope::Plain { .. } => panic!("encrypted decoded as plain"),
        }
    }

    #[test]
    fn raw_ump_does_not_parse_as_envelope() {
        // The shadow-mode rollout depends on this: if a sender ships
        // the old "raw UMP CBOR" body (no envelope wrapper), the new
        // ANTIE parser must NOT misinterpret it as an envelope.
        // A raw UMP body is a CBOR map with text keys like
        // `transaction`, `declared_balance`, etc — none of which
        // match the "plain" / "encrypted" variant tags.
        let mut raw = Vec::new();
        let mut map = std::collections::BTreeMap::new();
        map.insert("transaction".to_string(), "fake".to_string());
        ciborium::into_writer(&map, &mut raw).unwrap();
        // from_cbor returns None OR a value where neither variant matches.
        // ciborium's external-tag enum parser will reject this as an unknown variant.
        assert!(UmpEnvelope::from_cbor(&raw).is_none());
    }
}
