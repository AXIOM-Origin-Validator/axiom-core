//! Host Functions for core.bin
//!
//! These are functions that core.bin (eBPF) can call into the host (AVM).
//! They provide cryptographic primitives and other capabilities that
//! cannot be implemented in pure eBPF.
//!
//! # Design
//!
//! eBPF programs are sandboxed and cannot access external resources.
//! Host functions are the ONLY way for core.bin to:
//! - Compute cryptographic hashes
//! - Verify signatures
//! - Get injected time
//!
//! This maintains determinism because:
//! - All inputs come from AVM (controlled)
//! - All outputs go to AVM (recorded)
//! - No side effects

use alloc::vec::Vec;
use alloc::vec;

/// Host function IDs
/// core.bin uses these to request specific operations
pub mod function_ids {
    /// SHA3-256 hash
    pub const SHA3_256: u64 = 1;
    
    /// BLAKE3 hash
    pub const BLAKE3: u64 = 2;
    
    /// Ed25519 signature verification
    pub const ED25519_VERIFY: u64 = 10;
    
    /// Dilithium signature verification (post-quantum)
    pub const DILITHIUM_VERIFY: u64 = 11;
    
    /// Get injected time
    pub const GET_TIME: u64 = 20;
    
    /// Get zkVM runtime fingerprint (for verification)
    pub const GET_RUNTIME_FINGERPRINT: u64 = 30;

    /// Guest panic marker — guest's panic_handler ecalls this with
    /// `input` = formatted panic info (file:line + message). Host
    /// logs it; the guest then exits with code 1 so the host
    /// surfaces `AvmError::ExecutionError("Guest exited with code 1")`.
    /// KnownIssue #2 fix: pre-fix the marker was a static
    /// `b"AVM_GUEST_PANIC"` and func_id = 0xFF was not handled —
    /// host treated it as Unknown and dropped the message.
    pub const GUEST_PANIC: u64 = 0xFF;
}

/// Host function context
/// Passed to the eBPF VM to handle function calls
pub struct HostFunctions {
    /// Injected time (deterministic)
    injected_time: u64,
    
    /// Runtime fingerprint (for verification by core.bin)
    runtime_fingerprint: [u8; 32],
}

impl HostFunctions {
    pub fn new(injected_time: u64, runtime_fingerprint: [u8; 32]) -> Self {
        Self {
            injected_time,
            runtime_fingerprint,
        }
    }
    
    /// Handle a host function call from core.bin
    pub fn call(&self, function_id: u64, input: &[u8]) -> Result<Vec<u8>, &'static str> {
        match function_id {
            function_ids::SHA3_256 => Ok(self.sha3_256(input)),
            function_ids::BLAKE3 => Ok(self.blake3(input)),
            function_ids::ED25519_VERIFY => self.ed25519_verify(input),
            function_ids::DILITHIUM_VERIFY => self.dilithium_verify(input),
            function_ids::GET_TIME => Ok(self.injected_time.to_le_bytes().to_vec()),
            function_ids::GET_RUNTIME_FINGERPRINT => Ok(self.runtime_fingerprint.to_vec()),
            function_ids::GUEST_PANIC => {
                // KnownIssue #2 fix: log the panic info (file:line + message)
                // shipped by the guest's panic_handler. Host returns Ok so
                // the guest's ecall completes; the guest then exits with
                // code 1 and the executor surfaces the standard
                // `Guest exited with code 1` error to the validator.
                #[cfg(feature = "std")]
                {
                    extern crate std;
                    let msg = core::str::from_utf8(input).unwrap_or("<non-utf8 panic info>");
                    std::eprintln!("[AVM guest panic] {}", msg);
                }
                Ok(Vec::new())
            }
            _ => Err("Unknown function ID"),
        }
    }
    
    fn sha3_256(&self, data: &[u8]) -> Vec<u8> {
        use tiny_keccak::{Hasher, Sha3};
        let mut hasher = Sha3::v256();
        hasher.update(data);
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        output.to_vec()
    }
    
    fn blake3(&self, data: &[u8]) -> Vec<u8> {
        blake3::hash(data).as_bytes().to_vec()
    }
    
    fn ed25519_verify(&self, input: &[u8]) -> Result<Vec<u8>, &'static str> {
        // Input format: public_key (32) || signature (64) || message
        if input.len() < 96 {
            return Err("Invalid ed25519 input length");
        }
        
        let public_key = &input[0..32];
        let signature = &input[32..96];
        let message = &input[96..];
        
        use ed25519_dalek::{Signature, VerifyingKey, Verifier};
        
        let pk = VerifyingKey::from_bytes(public_key.try_into().unwrap())
            .map_err(|_| "Invalid public key")?;
        let sig = Signature::from_bytes(signature.try_into().unwrap());
        
        match pk.verify(message, &sig) {
            Ok(_) => Ok(vec![1]), // Valid
            Err(_) => Ok(vec![0]), // Invalid
        }
    }
    
    #[cfg(feature = "dilithium")]
    fn dilithium_verify(&self, input: &[u8]) -> Result<Vec<u8>, &'static str> {
        // Input format: public_key || signature || message
        // Dilithium public key and signature sizes depend on security level
        
        use fips204::ml_dsa_65;
        use fips204::traits::Verifier;
        
        // ML-DSA-65: pk=1952 bytes, sig=3309 bytes
        const PK_LEN: usize = 1952;
        const SIG_LEN: usize = 3309;
        
        if input.len() < PK_LEN + SIG_LEN {
            return Err("Invalid dilithium input length");
        }
        
        let pk_bytes: [u8; PK_LEN] = input[0..PK_LEN]
            .try_into()
            .map_err(|_| "Invalid public key length")?;
        
        let sig_bytes: [u8; SIG_LEN] = input[PK_LEN..PK_LEN + SIG_LEN]
            .try_into()
            .map_err(|_| "Invalid signature length")?;
        
        let message = &input[PK_LEN + SIG_LEN..];
        
        use fips204::traits::SerDes;
        let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_bytes)
            .map_err(|_| "Invalid Dilithium public key")?;
        
        // verify takes message, signature bytes, and context
        if pk.verify(message, &sig_bytes, &[]) {
            Ok(vec![1]) // Valid
        } else {
            Ok(vec![0]) // Invalid
        }
    }
    
    #[cfg(not(feature = "dilithium"))]
    fn dilithium_verify(&self, _input: &[u8]) -> Result<Vec<u8>, &'static str> {
        // Dilithium not available in this build
        Err("Dilithium verification not available (feature disabled)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sha3_256() {
        let host = HostFunctions::new(0, [0u8; 32]);
        let result = host.call(function_ids::SHA3_256, b"hello").unwrap();
        assert_eq!(result.len(), 32);
    }
    
    #[test]
    fn test_blake3() {
        let host = HostFunctions::new(0, [0u8; 32]);
        let result = host.call(function_ids::BLAKE3, b"hello").unwrap();
        assert_eq!(result.len(), 32);
    }
    
    #[test]
    fn test_get_time() {
        let host = HostFunctions::new(1234567890, [0u8; 32]);
        let result = host.call(function_ids::GET_TIME, &[]).unwrap();
        let time = u64::from_le_bytes(result.try_into().unwrap());
        assert_eq!(time, 1234567890);
    }
    
    #[test]
    fn test_get_runtime_fingerprint() {
        let fingerprint = [0xABu8; 32];
        let host = HostFunctions::new(0, fingerprint);
        let result = host.call(function_ids::GET_RUNTIME_FINGERPRINT, &[]).unwrap();
        assert_eq!(result.as_slice(), fingerprint.as_slice());
    }
}
