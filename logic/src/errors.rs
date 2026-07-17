//! Error types for AXIOM Core
//!
//! Re-exports ValidationError from types for convenience.

pub use crate::types::ValidationError;

/// Result type for Core operations
pub type CoreResult<T> = Result<T, ValidationError>;
