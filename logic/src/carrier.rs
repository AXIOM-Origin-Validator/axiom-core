//! Carrier URI validation
//!
//! Carriers define how to reach a validator. Core only validates total size
//! to prevent bloat. Format/scheme validation is the client's responsibility.
//! See Yellow Paper Section 26.9.3 for specification.

use crate::types::ValidationError;
use alloc::string::String;

/// Maximum total bytes for all carriers in a receipt
pub const MAX_CARRIERS_TOTAL_BYTES: usize = 512;

/// Validate a list of carrier URIs
///
/// Core only enforces total size limit. Scheme/format is client's responsibility.
///
/// # Validation Rules (NORMATIVE)
/// 1. Max 512 bytes total for all carriers
pub fn validate_carriers(carriers: &[String]) -> Result<(), ValidationError> {
    let total_bytes: usize = carriers.iter().map(|c| c.len()).sum();
    if total_bytes > MAX_CARRIERS_TOTAL_BYTES {
        return Err(ValidationError::CarriersTooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;
    
    #[test]
    fn test_valid_carriers() {
        let carriers = vec![
            "mailto:v1@axiom.validators".to_string(),
            "p2p:192.168.1.100:3030".to_string(),
            "https://v1.axiom.network/api".to_string(),
        ];
        assert!(validate_carriers(&carriers).is_ok());
    }
    
    #[test]
    fn test_carriers_too_large() {
        // Create carriers that total > 512
        let carriers: Vec<String> = (0..10)
            .map(|_| format!("mailto:{}@{}.com", "a".repeat(30), "b".repeat(30)))
            .collect();
        assert!(matches!(
            validate_carriers(&carriers),
            Err(ValidationError::CarriersTooLarge)
        ));
    }
    
    #[test]
    fn test_empty_carriers_ok() {
        let carriers: Vec<String> = vec![];
        assert!(validate_carriers(&carriers).is_ok());
    }
    
    #[test]
    fn test_many_small_carriers_ok() {
        // Many small carriers that fit within 512 bytes - should be OK
        let carriers: Vec<String> = (0..20)
            .map(|i| format!("mailto:v{}@a.co", i))
            .collect();
        let total: usize = carriers.iter().map(|c| c.len()).sum();
        assert!(total < MAX_CARRIERS_TOTAL_BYTES);
        assert!(validate_carriers(&carriers).is_ok());
    }
    
    #[test]
    fn test_any_scheme_ok() {
        // Core doesn't validate scheme - client's responsibility
        let carriers = vec![
            "ftp://whatever.com".to_string(),
            "custom://my-protocol".to_string(),
            "weird-scheme:data".to_string(),
        ];
        assert!(validate_carriers(&carriers).is_ok());
    }
    
    #[test]
    fn test_one_large_carrier_ok() {
        // One large carrier under 512 bytes is fine
        let carrier = format!("mailto:{}", "a".repeat(400));
        assert!(carrier.len() < MAX_CARRIERS_TOTAL_BYTES);
        assert!(validate_carriers(&[carrier]).is_ok());
    }
}
