//! Host functions the DMAP-VM serves to the Core guest — there is exactly ONE, and it
//! carries nothing INTO Core.
//!
//! Core has ONE input (`PublicInputs`, syscall READ_INPUTS) and ONE output
//! (`PublicOutputs`, syscall WRITE_OUTPUTS). Arch. Rule 8; the owner, 2026-09-19: "there is
//! only 1 input and 1 output from the core." The HOST_CALL syscall exists for the guest's
//! panic marker alone: the guest hands the host a message to log, and gets nothing back.
//!
//! ⚠ DELETED 2026-09-19 (the owner's ruling): SHA3_256, BLAKE3, ED25519_VERIFY,
//! DILITHIUM_VERIFY, GET_TIME, GET_RUNTIME_FINGERPRINT — with the `injected_time` /
//! `runtime_fingerprint` fields only they read. They were a leftover of the eBPF-era
//! design ("core.bin cannot hash or verify, so the host does it"). The RISC-V guest does
//! ALL its cryptography itself and takes its time from `PublicInputs`; MEASURED in the
//! source and in the committed ELF, it never called one of them. Served anyway, they were
//! crypto and a clock OUTSIDE Core, on offer to Core — a verdict the host could answer
//! instead of Core, and a second input. Do NOT add a host function that RETURNS data to
//! the guest: whatever Core needs arrives in `PublicInputs`. `scripts/check_core_surface.py`
//! (preflight) fails on any host function the guest does not call.

use alloc::vec::Vec;

/// Host function IDs.
pub mod function_ids {
    /// Guest panic marker — the guest's panic_handler ecalls this with `input` =
    /// formatted panic info (file:line + message). The host logs it; the guest then
    /// exits with code 1 so the host surfaces
    /// `AvmError::ExecutionError("Guest exited with code 1")`. (KnownIssue #2.)
    pub const GUEST_PANIC: u64 = 0xFF;
}

/// Host function context, handed to the executors. Holds nothing: a host function has
/// no state to return to the guest.
#[derive(Default)]
pub struct HostFunctions;

impl HostFunctions {
    pub fn new() -> Self {
        Self
    }

    /// Handle a host function call from the guest. Every id but the panic marker is
    /// refused — the executor then returns `u32::MAX` in a0.
    pub fn call(&self, function_id: u64, input: &[u8]) -> Result<Vec<u8>, &'static str> {
        match function_id {
            function_ids::GUEST_PANIC => {
                #[cfg(feature = "std")]
                {
                    extern crate std;
                    let msg = core::str::from_utf8(input).unwrap_or("<non-utf8 panic info>");
                    std::eprintln!("[AVM guest panic] {}", msg);
                }
                #[cfg(not(feature = "std"))]
                let _ = input;
                Ok(Vec::new())
            }
            _ => Err("Unknown function ID"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_marker_returns_nothing_to_the_guest() {
        assert_eq!(HostFunctions::new().call(function_ids::GUEST_PANIC, b"at x.rs:1:1 - boom").unwrap(), Vec::<u8>::new());
    }

    /// The six deleted ids (and any other) are REFUSED: the host computes nothing for Core
    /// and tells it nothing. Mutation: re-add `20 => Ok(7u64.to_le_bytes().to_vec())` to
    /// `call` — this test goes red.
    #[test]
    fn host_serves_no_crypto_no_time_no_fingerprint() {
        let host = HostFunctions::new();
        for id in [1u64, 2, 10, 11, 20, 30, 0, 0xFE, u64::MAX] {
            assert!(host.call(id, &[0u8; 5400]).is_err(), "host function {id} answered the guest");
        }
    }
}
