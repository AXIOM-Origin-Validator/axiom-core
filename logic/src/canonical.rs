//! Canonical JSON (RFC 8785 JCS Profile)
//!
//! AXIOM uses Canonical JSON for ALL serialization.
//! This ensures identical bytes for identical data across all implementations.
//!
//! Rules:
//! - Keys sorted by Unicode codepoint (ascending)
//! - No whitespace between tokens
//! - Integers only (no floats)
//! - Binary data with "b64u:" prefix (base64url, no padding)
//! - NFC normalized strings

use crate::errors::CoreResult;
use crate::types::ValidationError;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// Magic bytes for Canonical Bytes (CB) framing
pub const CB_MAGIC: [u8; 4] = [0x4C, 0x41, 0x4D, 0x42]; // "LAMB"

/// Current CB version
pub const CB_VERSION: u8 = 0x01;

/// Codec for Canonical JSON
pub const CB_CODEC_JSON: u8 = 0x01;

/// Canonical Bytes structure
///
/// CB := MAGIC(4) || CB_VERSION(1) || CODEC(1) || LEN(varint) || PAYLOAD || CRC32C(4)
#[derive(Debug, Clone)]
pub struct CanonicalBytes {
    pub payload: Vec<u8>,
}

impl CanonicalBytes {
    /// Create new CanonicalBytes from a payload
    pub fn new(payload: Vec<u8>) -> Self {
        Self { payload }
    }
    
    /// Encode to wire format
    pub fn encode(&self) -> Vec<u8> {
        use crate::crypto::crc32c;
        
        let mut result = Vec::new();
        
        // Magic
        result.extend_from_slice(&CB_MAGIC);
        
        // Version
        result.push(CB_VERSION);
        
        // Codec
        result.push(CB_CODEC_JSON);
        
        // Length (LEB128 varint)
        let len = self.payload.len() as u64;
        result.extend_from_slice(&encode_varint(len));
        
        // Payload
        result.extend_from_slice(&self.payload);
        
        // CRC32C over everything before it
        let crc = crc32c(&result);
        result.extend_from_slice(&crc.to_le_bytes());
        
        result
    }
    
    /// Decode from wire format
    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        use crate::crypto::crc32c;
        
        // Minimum size: 4 (magic) + 1 (version) + 1 (codec) + 1 (len) + 4 (crc) = 11
        if data.len() < 11 {
            return Err(ValidationError::InvalidCanonicalJson);
        }
        
        // Check magic
        if data[0..4] != CB_MAGIC {
            return Err(ValidationError::InvalidCanonicalJson);
        }
        
        // Check version
        if data[4] != CB_VERSION {
            return Err(ValidationError::InvalidCanonicalJson);
        }
        
        // Check codec
        if data[5] != CB_CODEC_JSON {
            return Err(ValidationError::InvalidCanonicalJson);
        }
        
        // Decode length
        let (len, varint_size) = decode_varint(&data[6..])
            .ok_or(ValidationError::InvalidCanonicalJson)?;
        
        let payload_start = 6 + varint_size;
        let payload_end = payload_start + len as usize;
        
        // Check we have enough data
        if data.len() < payload_end + 4 {
            return Err(ValidationError::InvalidCanonicalJson);
        }
        
        // Verify CRC32C
        let stored_crc = u32::from_le_bytes(
            data[payload_end..payload_end + 4]
                .try_into()
                .map_err(|_| ValidationError::InvalidCanonicalJson)?
        );
        let computed_crc = crc32c(&data[0..payload_end]);
        
        if stored_crc != computed_crc {
            return Err(ValidationError::InvalidCanonicalJson);
        }
        
        // Extract payload
        let payload = data[payload_start..payload_end].to_vec();
        
        Ok(Self { payload })
    }
}

/// Encode a varint (LEB128)
fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut result = Vec::new();
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        result.push(byte);
        if value == 0 {
            break;
        }
    }
    result
}

/// Decode a varint (LEB128)
/// Returns (value, bytes_consumed)
fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0;
    
    for (i, &byte) in data.iter().enumerate() {
        if shift >= 64 {
            return None; // Overflow
        }
        
        result |= ((byte & 0x7F) as u64) << shift;
        
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
        
        shift += 7;
    }
    
    None // Incomplete
}

/// Encode binary data with b64u prefix
pub fn encode_binary(data: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    
    let encoded = URL_SAFE_NO_PAD.encode(data);
    format!("b64u:{}", encoded)
}

/// Decode binary data with b64u prefix
pub fn decode_binary(s: &str) -> CoreResult<Vec<u8>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    
    if !s.starts_with("b64u:") {
        return Err(ValidationError::InvalidCanonicalJson);
    }
    
    let encoded = &s[5..];
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ValidationError::InvalidCanonicalJson)
}

/// Check if a string has b64u prefix
pub fn is_binary_encoded(s: &str) -> bool {
    s.starts_with("b64u:")
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_varint_encoding() {
        // Single byte
        assert_eq!(encode_varint(0), vec![0x00]);
        assert_eq!(encode_varint(1), vec![0x01]);
        assert_eq!(encode_varint(127), vec![0x7F]);
        
        // Two bytes
        assert_eq!(encode_varint(128), vec![0x80, 0x01]);
        assert_eq!(encode_varint(255), vec![0xFF, 0x01]);
        
        // Larger values
        assert_eq!(encode_varint(300), vec![0xAC, 0x02]);
    }
    
    #[test]
    fn test_varint_roundtrip() {
        for value in [0, 1, 127, 128, 255, 256, 1000, 10000, u64::MAX] {
            let encoded = encode_varint(value);
            let (decoded, _) = decode_varint(&encoded).unwrap();
            assert_eq!(value, decoded);
        }
    }
    
    #[test]
    fn test_canonical_bytes_roundtrip() {
        let payload = b"Hello, AXIOM!".to_vec();
        let cb = CanonicalBytes::new(payload.clone());
        
        let encoded = cb.encode();
        let decoded = CanonicalBytes::decode(&encoded).unwrap();
        
        assert_eq!(decoded.payload, payload);
    }
    
    #[test]
    fn test_canonical_bytes_magic() {
        let cb = CanonicalBytes::new(b"test".to_vec());
        let encoded = cb.encode();
        
        // Check magic bytes
        assert_eq!(&encoded[0..4], b"LAMB");
    }
    
    #[test]
    fn test_canonical_bytes_crc_validation() {
        let cb = CanonicalBytes::new(b"test".to_vec());
        let mut encoded = cb.encode();
        
        // Corrupt the payload
        encoded[10] ^= 0xFF;
        
        // Should fail CRC check
        assert!(CanonicalBytes::decode(&encoded).is_err());
    }
    
    #[test]
    fn test_binary_encoding() {
        let data = vec![0x00, 0x01, 0x02, 0xFF];
        let encoded = encode_binary(&data);
        
        assert!(encoded.starts_with("b64u:"));
        
        let decoded = decode_binary(&encoded).unwrap();
        assert_eq!(decoded, data);
    }
    
    #[test]
    fn test_binary_encoding_no_prefix() {
        let result = decode_binary("not_valid");
        assert!(result.is_err());
    }
}
