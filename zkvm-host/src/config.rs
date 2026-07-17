//! zkVM Configuration
//!
//! Allows loading the axiom-core.elf and IMAGE_ID from external paths,
//! so zkvm-methods doesn't need to be in the workspace.
//!
//! # IMAGE_ID — Release Build Artifact
//!
//! IMAGE_ID is the RISC Zero guest image hash. It is NOT in source code.
//! It is produced during release builds when the zkVM guest is compiled:
//!   `cd core/zkvm-guest && cargo build --release --target riscv32im-unknown-none-elf`
//!
//! The IMAGE_ID file must be distributed alongside the ELF binary.
//! At runtime, the prover/verifier loads IMAGE_ID and uses it to:
//! - Bind STARK proofs to the specific Core binary
//! - Detect ELF tampering (different binary = different IMAGE_ID = proof fails)
//!
//! # Configuration
//!
//! Set these environment variables or use the config file:
//!
//! ```bash
//! export AXIOM_ZKVM_ELF=/path/to/axiom-core.elf
//! export AXIOM_ZKVM_IMAGE_ID=/path/to/image-id.hex
//! ```
//!
//! Or create `~/.axiom/zkvm.toml`:
//!
//! ```toml
//! [zkvm]
//! elf_path = "/path/to/axiom-core.elf"
//! image_id_path = "/path/to/image-id.hex"
//! ```

use std::path::PathBuf;
use std::fs;
use crate::ZkvmError;

/// Default paths for zkVM artifacts
pub const DEFAULT_ELF_PATH: &str = "~/.axiom/zkvm/axiom-core.elf";
pub const DEFAULT_IMAGE_ID_PATH: &str = "~/.axiom/zkvm/image-id.hex";

/// Environment variable names
pub const ENV_ELF_PATH: &str = "AXIOM_ZKVM_ELF";
pub const ENV_IMAGE_ID_PATH: &str = "AXIOM_ZKVM_IMAGE_ID";

/// zkVM Configuration
#[derive(Debug, Clone)]
pub struct ZkvmConfig {
    /// Path to the axiom-core.elf binary
    pub elf_path: PathBuf,
    
    /// Path to the IMAGE_ID file (32 bytes hex)
    pub image_id_path: PathBuf,
    
    /// Cached ELF bytes (loaded lazily)
    elf_bytes: Option<Vec<u8>>,
    
    /// Cached IMAGE_ID (loaded lazily)
    image_id: Option<[u8; 32]>,
}

impl ZkvmConfig {
    /// Create config from environment variables or defaults
    pub fn from_env() -> Self {
        let elf_path = std::env::var(ENV_ELF_PATH)
            .map(PathBuf::from)
            .unwrap_or_else(|_| expand_tilde(DEFAULT_ELF_PATH));
        
        let image_id_path = std::env::var(ENV_IMAGE_ID_PATH)
            .map(PathBuf::from)
            .unwrap_or_else(|_| expand_tilde(DEFAULT_IMAGE_ID_PATH));
        
        Self {
            elf_path,
            image_id_path,
            elf_bytes: None,
            image_id: None,
        }
    }
    
    /// Create config with explicit paths
    pub fn new(elf_path: impl Into<PathBuf>, image_id_path: impl Into<PathBuf>) -> Self {
        Self {
            elf_path: elf_path.into(),
            image_id_path: image_id_path.into(),
            elf_bytes: None,
            image_id: None,
        }
    }
    
    /// Check if zkVM artifacts are available
    pub fn is_available(&self) -> bool {
        self.elf_path.exists() && self.image_id_path.exists()
    }
    
    /// Load the ELF binary
    pub fn load_elf(&mut self) -> Result<&[u8], ZkvmError> {
        if self.elf_bytes.is_none() {
            let bytes = fs::read(&self.elf_path)
                .map_err(|e| ZkvmError::ExecutionFailed(
                    format!("Failed to load ELF from {:?}: {}", self.elf_path, e)
                ))?;
            self.elf_bytes = Some(bytes);
        }
        Ok(self.elf_bytes.as_ref().unwrap())
    }
    
    /// Load the IMAGE_ID
    pub fn load_image_id(&mut self) -> Result<[u8; 32], ZkvmError> {
        if self.image_id.is_none() {
            let hex_str = fs::read_to_string(&self.image_id_path)
                .map_err(|e| ZkvmError::ExecutionFailed(
                    format!("Failed to load IMAGE_ID from {:?}: {}", self.image_id_path, e)
                ))?;
            
            let hex_str = hex_str.trim();
            let bytes = hex::decode(hex_str)
                .map_err(|e| ZkvmError::ExecutionFailed(
                    format!("Invalid IMAGE_ID hex: {}", e)
                ))?;
            
            if bytes.len() != 32 {
                return Err(ZkvmError::ExecutionFailed(
                    format!("IMAGE_ID must be 32 bytes, got {}", bytes.len())
                ));
            }
            
            let mut id = [0u8; 32];
            id.copy_from_slice(&bytes);
            self.image_id = Some(id);
        }
        Ok(self.image_id.unwrap())
    }
    
    /// Get status message for diagnostics
    pub fn status(&self) -> String {
        let elf_status = if self.elf_path.exists() { "✓" } else { "✗" };
        let id_status = if self.image_id_path.exists() { "✓" } else { "✗" };
        
        format!(
            "zkVM Config:\n  ELF: {} {:?}\n  IMAGE_ID: {} {:?}",
            elf_status, self.elf_path,
            id_status, self.image_id_path
        )
    }
}

impl Default for ZkvmConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

/// Expand ~ to home directory
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(stripped) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(stripped);
        }
    }
    PathBuf::from(path)
}

/// Create the default zkVM directory structure
pub fn init_zkvm_dir() -> Result<PathBuf, ZkvmError> {
    let zkvm_dir = expand_tilde("~/.axiom/zkvm");
    
    fs::create_dir_all(&zkvm_dir)
        .map_err(|e| ZkvmError::ExecutionFailed(
            format!("Failed to create zkVM directory: {}", e)
        ))?;
    
    // Create a README
    let readme_path = zkvm_dir.join("README.md");
    if !readme_path.exists() {
        let readme = r#"# AXIOM zkVM Artifacts

Place the following files here after building zkvm-methods:

1. `axiom-core.elf` - The compiled Core.bin guest program
2. `image-id.hex` - The IMAGE_ID (32 bytes, hex encoded)

## Building

```bash
# Install RISC Zero toolchain
curl -L https://risczero.com/install | bash
rzup install

# Build the guest
cd axiom-core/zkvm-methods
cargo build --release

# Copy artifacts here
cp target/riscv-guest/riscv32im-risc0-zkvm-elf/release/axiom-core-guest ~/.axiom/zkvm/axiom-core.elf
# IMAGE_ID is printed during build, or extract from methods crate
```

## Environment Variables

Alternatively, set these environment variables:

```bash
export AXIOM_ZKVM_ELF=/path/to/axiom-core.elf
export AXIOM_ZKVM_IMAGE_ID=/path/to/image-id.hex
```
"#;
        fs::write(&readme_path, readme)
            .map_err(|e| ZkvmError::ExecutionFailed(
                format!("Failed to write README: {}", e)
            ))?;
    }
    
    Ok(zkvm_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_expand_tilde() {
        let path = expand_tilde("~/.axiom/zkvm");
        assert!(!path.to_string_lossy().starts_with("~"));
    }
    
    #[test]
    fn test_config_from_env() {
        let config = ZkvmConfig::from_env();
        // Should not panic
        let _ = config.status();
    }
    
    #[test]
    fn test_config_not_available() {
        let config = ZkvmConfig::new("/nonexistent/path.elf", "/nonexistent/id.hex");
        assert!(!config.is_available());
    }
}
