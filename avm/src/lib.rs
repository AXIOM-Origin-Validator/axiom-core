//! AXIOM Virtual Machine (AVM)
//!
//! AVM executes axiom-core.elf validation logic.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │  zkVM (proof wrapper)                                       │
//! │                                                             │
//! │  ┌───────────────────────────────────────────────────────┐  │
//! │  │  AVM (this crate)                                     │  │
//! │  │  - Executes validation logic                          │  │
//! │  │  - Provides host functions (crypto, etc.)             │  │
//! │  │                                                       │  │
//! │  │  ┌─────────────────────────────────────────────────┐  │  │
//! │  │  │  core-logic (validation rules)                  │  │  │
//! │  │  │  - Transaction validation                       │  │  │
//! │  │  │  - CL1/CL2/CL3/CL4 modes                        │  │  │
//! │  │  └─────────────────────────────────────────────────┘  │  │
//! │  └───────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Implementation Modes
//!
//! - **Default:** Executes core-logic directly as native Rust (fast, dev/test).
//! - **`riscv-interpreter` feature:** Real RV32IM interpretation of axiom-core.elf
//!   (§31 compliant, enables DMAP attestation).
//!
//! Both modes produce identical PublicOutputs for identical PublicInputs.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod interpreter;
pub mod host_functions;
pub mod core_handle;
pub mod config;
pub mod riscv;
pub mod dmap;

// Re-export core-logic types for convenience
pub use axiom_core_logic::{
    CoreLogicMode,
    PublicInputs,
    PublicOutputs,
    Transaction,
    TxKind,
    Receipt,
    WalletState,
    ValidationResult,
    ValidationError,
    ChequeBundle,
    ValidatorCheque,
    VBCProofBundle,
    VBC,
    execute_core,
};

pub use interpreter::{AvmInterpreter, AvmExecutionResult};
pub use core_handle::{CoreHandle, CoreError};
pub use config::AvmConfig;
pub use dmap::ProofType;

// ── YPX-009 Pulse benchmark, process-global accessor ──────────────────
// The AVM runs an Argon2id throughput self-benchmark once at startup
// (interpreter.rs `run_pulse_benchmark`) and eprintln's the result. The
// number is also a useful hardware-fitness signal for the operator
// dashboard. Park it in a process-global atomic so the admin /capacity
// endpoint can read it without threading a pointer through every layer.
use core::sync::atomic::{AtomicU64, Ordering};
pub static LAST_ARGON2ID_PER_SEC: AtomicU64 = AtomicU64::new(0);
/// Last measured Argon2id throughput from the YPX-009 pulse self-benchmark
/// (Argon2id ops/sec), or 0 if the benchmark hasn't run yet in this process.
pub fn last_argon2id_per_sec() -> u64 { LAST_ARGON2ID_PER_SEC.load(Ordering::Relaxed) }
