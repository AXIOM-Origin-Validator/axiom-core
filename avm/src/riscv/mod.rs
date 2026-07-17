//! RISC-V RV32IM Interpreter for AVM
//!
//! This module implements a minimal RISC-V interpreter that executes
//! axiom-core.elf inside AVM. It provides:
//!
//! - RV32IM instruction decoding and execution (~50 instructions)
//! - Page-tracked guest memory (for DMAP Merkle attestation)
//! - ELF loading for RISC-V binaries
//! - ecall-based host function interface
//!
//! # Yellow Paper §31 Compliance
//!
//! §31.6 Invariant 1: "Core is compiled to RISC-V ELF exactly once per release."
//! This interpreter executes that ELF on every platform, ensuring deterministic
//! cross-platform behavior regardless of the host architecture.

pub mod decoder;
pub mod executor;
pub mod fast_executor;
#[cfg(feature = "cranelift-jit-backend")]
pub mod jit;
pub mod memory;
pub mod elf_loader;

pub use executor::{CpuState, ExitReason};
pub use fast_executor::{FastCpu, InstructionCache};
pub use memory::GuestMemory;
pub use elf_loader::load_elf;
