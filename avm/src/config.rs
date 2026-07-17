//! AVM Configuration — ELF Artifact Loading
//!
//! Loads the Core AVM ELF binary and computes the CoreID (BLAKE3 hash).
//! Configuration is driven by environment variables, matching the zkVM pattern.
//!
//! # IMAGE_ID (Trust Anchor)
//!
//! The IMAGE_ID file contains the expected BLAKE3 hash of the Core ELF binary.
//! It is a **build artifact** — produced during release builds, NOT stored in source.
//!
//! **When IMAGE_ID is generated:**
//! - During `cargo build --release` of the AVM guest (core/avm-guest)
//! - During the G1 Genesis Ceremony (`scripts/g1-ceremony.sh`)
//! - During zkVM proof generation (`core/zkvm-host` build)
//!
//! **At runtime:**
//! - `core_id = BLAKE3(elf_bytes)` is computed from the loaded ELF
//! - If IMAGE_ID file exists, `core_id` is cross-checked against it
//! - Mismatch = fatal error (binary tampered or wrong ELF)
//! - If IMAGE_ID file is absent, cross-check is skipped (dev/test mode)
//!
//! **For production:** IMAGE_ID MUST be present. Operators should verify
//! their ELF's `core_id` against the published canonical fingerprint.
//!
//! # Environment Variables
//!
//! - `AXIOM_AVM_ELF`: Path to compiled axiom-core.elf (RV32IM binary)
//! - `AXIOM_AVM_IMAGE_ID`: Path to image-id.hex (BLAKE3 hash of ELF, hex-encoded)

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;

/// AVM artifact configuration
#[derive(Debug, Clone)]
pub struct AvmConfig {
    /// Raw ELF bytes of axiom-core.elf
    pub elf_bytes: Vec<u8>,

    /// CoreID = BLAKE3(elf_bytes) — identifies which code runs inside AVM
    pub core_id: [u8; 32],
}

impl AvmConfig {
    /// Create config from raw ELF bytes
    pub fn from_elf(elf_bytes: Vec<u8>) -> Self {
        let core_id = *blake3::hash(&elf_bytes).as_bytes();
        AvmConfig { elf_bytes, core_id }
    }

    /// Load from environment variables (std only)
    ///
    /// Reads `AXIOM_AVM_ELF` and optionally `AXIOM_AVM_IMAGE_ID`.
    /// If IMAGE_ID is provided, cross-checks against computed BLAKE3.
    #[cfg(feature = "std")]
    pub fn from_env() -> Result<Self, String> {
        let elf_path = std::env::var("AXIOM_AVM_ELF")
            .map_err(|_| "AXIOM_AVM_ELF not set".to_string())?;

        let elf_bytes = std::fs::read(&elf_path)
            .map_err(|e| format!("Failed to read {}: {}", elf_path, e))?;

        let config = Self::from_elf(elf_bytes);

        // Cross-check IMAGE_ID if provided
        if let Ok(id_path) = std::env::var("AXIOM_AVM_IMAGE_ID") {
            let id_hex = std::fs::read_to_string(&id_path)
                .map_err(|e| format!("Failed to read {}: {}", id_path, e))?;
            let id_hex = id_hex.trim();
            let expected = hex::decode(id_hex)
                .map_err(|e| format!("Invalid hex in {}: {}", id_path, e))?;
            if expected.len() != 32 {
                return Err(format!("IMAGE_ID must be 32 bytes, got {}", expected.len()));
            }
            let mut expected_arr = [0u8; 32];
            expected_arr.copy_from_slice(&expected);
            if config.core_id != expected_arr {
                return Err(format!(
                    "CoreID mismatch: ELF hashes to {} but IMAGE_ID says {}",
                    hex::encode(config.core_id),
                    id_hex,
                ));
            }
        }

        Ok(config)
    }

    /// Load from explicit paths (std only)
    #[cfg(feature = "std")]
    pub fn from_paths(elf_path: &str, image_id_path: Option<&str>) -> Result<Self, String> {
        let elf_bytes = std::fs::read(elf_path)
            .map_err(|e| format!("Failed to read {}: {}", elf_path, e))?;

        let config = Self::from_elf(elf_bytes);

        if let Some(id_path) = image_id_path {
            let id_hex = std::fs::read_to_string(id_path)
                .map_err(|e| format!("Failed to read {}: {}", id_path, e))?;
            let expected = hex::decode(id_hex.trim())
                .map_err(|e| format!("Invalid hex in {}: {}", id_path, e))?;
            if expected.len() != 32 {
                return Err(format!("IMAGE_ID must be 32 bytes, got {}", expected.len()));
            }
            let mut expected_arr = [0u8; 32];
            expected_arr.copy_from_slice(&expected);
            if config.core_id != expected_arr {
                return Err(format!(
                    "CoreID mismatch: computed {} but file says {}",
                    hex::encode(config.core_id),
                    hex::encode(expected_arr),
                ));
            }
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_elf() {
        let fake_elf = vec![0x7F, b'E', b'L', b'F', 0x01, 0x02, 0x03];
        let config = AvmConfig::from_elf(fake_elf.clone());
        let expected_id = *blake3::hash(&fake_elf).as_bytes();
        assert_eq!(config.core_id, expected_id);
        assert_eq!(config.elf_bytes, fake_elf);
    }

    #[test]
    fn test_core_id_deterministic() {
        let elf = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let c1 = AvmConfig::from_elf(elf.clone());
        let c2 = AvmConfig::from_elf(elf);
        assert_eq!(c1.core_id, c2.core_id);
    }

    #[test]
    fn test_different_elf_different_id() {
        let c1 = AvmConfig::from_elf(vec![1, 2, 3]);
        let c2 = AvmConfig::from_elf(vec![4, 5, 6]);
        assert_ne!(c1.core_id, c2.core_id);
    }
}
