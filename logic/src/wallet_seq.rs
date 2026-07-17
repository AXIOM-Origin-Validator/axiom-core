//! wallet_seq enforcement
//!
//! wallet_seq provides defense-in-depth against parallel transaction attacks.
//!
//! Rules (NORMATIVE):
//! 1. Genesis state: wallet_seq = 0 (unfunded, balance=0)
//! 2. Every transaction: wallet_seq MUST be prev_wallet_seq + 1
//! 3. First funded TX: wallet_seq = 1 (prev=0), MUST have 3 witnesses
//! 4. Maximum: 2^48 (281,474,976,710,656)
//!
//! There is NO special genesis case. All transactions follow the same rule.
//! wallet_seq is verified ONLY by Core.bin, not Lambda.

// CONSENSUS_CRITICAL

use crate::errors::CoreResult;
use crate::types::ValidationError;

/// Maximum wallet_seq value
///
/// At 2^48, even 1 transaction per second would take ~9 million years to overflow.
/// This is effectively "forever" and provides protection against overflow attacks.
pub const MAX_WALLET_SEQ: u64 = 1 << 48; // 281,474,976,710,656

/// Verify wallet_seq is valid
///
/// # Arguments
/// * `seq` - The wallet_seq in the transaction
/// * `prev_seq` - The previous wallet_seq (from prev_receipts or state)
///
/// # Rules
/// - seq MUST be prev_seq + 1 (no exceptions, no genesis bypass)
/// - seq MUST be < MAX_WALLET_SEQ
pub fn verify_wallet_seq(
    seq: u64,
    prev_seq: u64,
) -> CoreResult<()> {
    // Check overflow first
    if seq >= MAX_WALLET_SEQ {
        return Err(ValidationError::WalletSeqOverflow);
    }
    
    // Every transaction: must be exactly prev_seq + 1
    // seq=1 with prev=0 (first funded TX) follows the same rule
    if seq != prev_seq.saturating_add(1) {
        return Err(ValidationError::InvalidWalletSeq);
    }
    
    Ok(())
}

/// Check if a wallet_seq value is approaching overflow
///
/// Returns true if within 1 billion of the maximum.
/// This is informational, not a validation error.
pub fn is_approaching_overflow(seq: u64) -> bool {
    seq >= MAX_WALLET_SEQ.saturating_sub(1_000_000_000)
}

/// Compute the next valid wallet_seq
pub fn next_wallet_seq(current: u64) -> Option<u64> {
    let next = current.saturating_add(1);
    if next >= MAX_WALLET_SEQ {
        None
    } else {
        Some(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_first_funded_tx() {
        // First funded TX: seq=1, prev=0 — same rule as everything else
        assert!(verify_wallet_seq(1, 0).is_ok());
    }
    
    #[test]
    fn test_seq_zero_rejected() {
        // seq=0 is genesis state, never valid in a transaction
        assert!(matches!(
            verify_wallet_seq(0, 0),
            Err(ValidationError::InvalidWalletSeq)
        ));
    }
    
    #[test]
    fn test_skip_from_zero_rejected() {
        // Can't skip from 0 to 2
        assert!(matches!(
            verify_wallet_seq(2, 0),
            Err(ValidationError::InvalidWalletSeq)
        ));
    }
    
    #[test]
    fn test_sequential_increment() {
        // All transactions must increment by exactly 1
        assert!(verify_wallet_seq(1, 0).is_ok());
        assert!(verify_wallet_seq(2, 1).is_ok());
        assert!(verify_wallet_seq(100, 99).is_ok());
        assert!(verify_wallet_seq(1000000, 999999).is_ok());
    }
    
    #[test]
    fn test_sequential_wrong() {
        // Skip a number - should fail
        assert!(matches!(
            verify_wallet_seq(3, 1),
            Err(ValidationError::InvalidWalletSeq)
        ));
        
        // Go backwards - should fail
        assert!(matches!(
            verify_wallet_seq(1, 2),
            Err(ValidationError::InvalidWalletSeq)
        ));
        
        // Same number - should fail (reuse)
        assert!(matches!(
            verify_wallet_seq(5, 5),
            Err(ValidationError::InvalidWalletSeq)
        ));
    }
    
    #[test]
    fn test_overflow_protection() {
        // At max, should fail
        assert!(matches!(
            verify_wallet_seq(MAX_WALLET_SEQ, MAX_WALLET_SEQ - 1),
            Err(ValidationError::WalletSeqOverflow)
        ));
        
        // Above max, should fail
        assert!(matches!(
            verify_wallet_seq(MAX_WALLET_SEQ + 1, MAX_WALLET_SEQ),
            Err(ValidationError::WalletSeqOverflow)
        ));
    }
    
    #[test]
    fn test_one_before_max() {
        // One before max should be valid
        assert!(verify_wallet_seq(MAX_WALLET_SEQ - 1, MAX_WALLET_SEQ - 2).is_ok());
    }
    
    #[test]
    fn test_approaching_overflow() {
        assert!(!is_approaching_overflow(0));
        assert!(!is_approaching_overflow(1_000_000));
        assert!(is_approaching_overflow(MAX_WALLET_SEQ - 1));
        assert!(is_approaching_overflow(MAX_WALLET_SEQ - 999_999_999));
    }
    
    #[test]
    fn test_next_wallet_seq() {
        assert_eq!(next_wallet_seq(0), Some(1));
        assert_eq!(next_wallet_seq(100), Some(101));
        assert_eq!(next_wallet_seq(MAX_WALLET_SEQ - 2), Some(MAX_WALLET_SEQ - 1));
        assert_eq!(next_wallet_seq(MAX_WALLET_SEQ - 1), None);
        assert_eq!(next_wallet_seq(MAX_WALLET_SEQ), None);
    }
}
