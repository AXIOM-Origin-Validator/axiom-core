//! CoreHandle — The One Core
//!
//! Single shared Core instance used by both ANTIE (CL2) and Lambda (CL3/CL5).
//! There is ONE core.bin per validator. Gateway and Lambda both talk to it.
//!
//! ```text
//!                    ┌──────────────┐
//!   ANTIE (CL2) ──► │              │
//!                    │  CoreHandle  │ ── one AVM, one VBC, one TTL
//!   Lambda(CL3) ──► │  (Mutex)     │
//!   Lambda(CL5) ──► │              │
//!                    └──────────────┘
//! ```
//!
//! # Protocol
//!
//! - `execute(PublicInputs) -> Result<PublicOutputs>` — the ONLY entry point
//! - VBC verified ONCE at construction (YP §23.13.11)
//! - Internal TTL: 2,000 requests or 24 hours → returns CoreTTLExpired error
//! - Caller sees TTL error, respawns fresh CoreHandle
//! - Mutex serializes all access (YP §5.10.4: one request in-flight at a time)
//!
//! # Future
//!
//! When core.bin becomes a real subprocess, CoreHandle spawns it and
//! communicates via stdin/stdout length-prefixed JSON frames (YP §5.10.1).
//! The interface stays the same — callers don't know or care.

use alloc::string::String;
use alloc::format;
use axiom_core_logic::{PublicInputs, PublicOutputs};
use axiom_core_logic::types::VBCProofBundle;
use crate::interpreter::AvmInterpreter;

/// Maximum requests before Core must die and be reborn.
/// Forces VBC re-verification. YP §23.13.11.
pub const MAX_REQUESTS: u64 = 2_000;

/// Maximum lifetime in seconds (24 hours). YP §23.13.11.
pub const MAX_LIFETIME_SECS: u64 = 24 * 60 * 60;

/// Core TTL expired — caller must respawn a fresh CoreHandle.
#[derive(Debug)]
pub enum CoreError {
    /// TTL expired (request count or lifetime). Respawn me.
    TTLExpired(String),
    /// VBC verification failed at load. Cannot start.
    VBCInvalid(String),
    /// Core execution error
    ExecutionError(String),
}

impl core::fmt::Display for CoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TTLExpired(s) => write!(f, "E_CORE_TTL_EXPIRED: {}", s),
            Self::VBCInvalid(s) => write!(f, "E_VBC_INVALID: {}", s),
            Self::ExecutionError(s) => write!(f, "E_CORE_EXEC: {}", s),
        }
    }
}

/// The One Core.
///
/// Both ANTIE and Lambda hold an `Arc<CoreHandle>` to the same instance.
/// All access serialized through internal Mutex-like pattern.
/// (Actual Mutex is at the caller level since we're no_std compatible here.)
pub struct CoreHandle {
    /// AVM interpreter — executes core-logic
    avm: AvmInterpreter,

    /// VBC verified at birth. Passed into every request.
    vbc_bundle: Option<VBCProofBundle>,

    /// Request counter (Core's own bookkeeping)
    request_count: u64,

    /// When this Core was born (seconds since some epoch)
    /// Using u64 instead of Instant for no_std compatibility.
    /// Caller sets this via new().
    born_at_secs: u64,

    /// External time provider (seconds since epoch)
    /// Core asks "what time is it now?" before each request.
    /// In std mode, this is just SystemTime. In no_std, injected.
    current_time_secs: u64,
}

impl CoreHandle {
    /// Birth a new Core. VBC verified ONCE here.
    ///
    /// Returns Err if VBC is structurally invalid — can't start without identity.
    /// `born_at_secs`: current time in seconds since epoch.
    pub fn new(vbc_bundle: Option<VBCProofBundle>, born_at_secs: u64) -> Result<Self, CoreError> {
        // Verify VBC at birth — "verify once, use many" (YP §23.13.11)
        if let Some(ref vbc) = vbc_bundle {
            axiom_core_logic::vbc::verify_vbc_bundle_structure_only_DANGER_no_sig(vbc)
                .map_err(|e| CoreError::VBCInvalid(format!("{:?}", e)))?;
        }

        Ok(Self {
            avm: AvmInterpreter::new(b"AXIOM_CORE_V2".to_vec(), [0u8; 32]),
            vbc_bundle,
            request_count: 0,
            born_at_secs,
            current_time_secs: born_at_secs,
        })
    }

    /// Update the clock. Caller must call this before execute().
    /// Core doesn't own a clock — time is injected (deterministic execution).
    pub fn set_current_time(&mut self, now_secs: u64) {
        self.current_time_secs = now_secs;
    }

    /// The ONLY entry point. Send PublicInputs, get PublicOutputs.
    ///
    /// Core checks its own TTL first. If expired, returns CoreError::TTLExpired.
    /// Caller sees this, respawns fresh CoreHandle, retries.
    ///
    /// Core decides when to die. Caller just reacts.
    pub fn execute(&mut self, inputs: PublicInputs) -> Result<PublicOutputs, CoreError> {
        // Check TTL before doing any work
        self.check_ttl()?;

        // Count this request
        self.request_count += 1;

        // Execute via AVM
        let outputs = self.avm.execute(inputs)
            .map_err(|e| CoreError::ExecutionError(format!("{}", e)))?;

        Ok(outputs)
    }

    /// Get the verified VBC bundle (for callers that need to pass it through).
    pub fn vbc_bundle(&self) -> Option<&VBCProofBundle> {
        self.vbc_bundle.as_ref()
    }

    /// Internal TTL check. Core decides for itself.
    fn check_ttl(&self) -> Result<(), CoreError> {
        if self.request_count >= MAX_REQUESTS {
            return Err(CoreError::TTLExpired(format!(
                "{} requests (max {})", self.request_count, MAX_REQUESTS
            )));
        }
        let elapsed = self.current_time_secs.saturating_sub(self.born_at_secs);
        if elapsed >= MAX_LIFETIME_SECS {
            return Err(CoreError::TTLExpired(format!(
                "{}s lifetime (max {}s)", elapsed, MAX_LIFETIME_SECS
            )));
        }
        Ok(())
    }

    /// How many requests processed so far
    pub fn request_count(&self) -> u64 {
        self.request_count
    }
}
