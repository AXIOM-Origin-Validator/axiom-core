//! AXIOM AVM Guest — Standalone RISC-V Binary
//!
//! This is the §31-compliant Core binary that runs inside AVM's RISC-V
//! interpreter. It executes `execute_core(PublicInputs) → PublicOutputs`
//! using ecall syscalls for I/O.
//!
//! # I/O Convention (ecall)
//!
//! - ecall a7=0x01 (READ_INPUTS):   Read PublicInputs from host
//! - ecall a7=0x02 (WRITE_OUTPUTS): Write PublicOutputs to host
//! - ecall a7=0x10 (HOST_CALL):     Call host function (crypto, time)
//! - ecall a7=0x5D (EXIT):          Exit guest execution
//!
//! # Differences from zkvm-guest
//!
//! - Uses ecall for I/O (not risc0_zkvm::guest::env)
//! - No STARK proof generation
//! - Runs all CL1-CL8 modes (not just CL3 checkpoint)
//! - Used for DMAP attestation, not ZK proofs

#![no_std]
#![no_main]

extern crate alloc;

// Custom getrandom backend for bare-metal RISC-V.
// The guest only verifies signatures — never generates keys — so getrandom
// is never called at runtime. This satisfies the linker requirement from
// ed25519-dalek, fips204, and fips205 which pull in rand_core → getrandom.
use getrandom::register_custom_getrandom;

fn avm_guest_getrandom(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    // Should never be called — guest does verification only, no key generation.
    // If this fires, something in execute_core() is trying to generate randomness,
    // which would be a protocol violation (Core is deterministic).
    panic!("getrandom called in AVM guest — Core must be deterministic");
}

register_custom_getrandom!(avm_guest_getrandom);

use alloc::vec;
use axiom_core_logic::{PublicInputs, PublicOutputs, execute_core};

/// Syscall numbers matching AVM host expectations
const SYS_READ_INPUTS: usize = 0x01;
const SYS_WRITE_OUTPUTS: usize = 0x02;
const SYS_EXIT: usize = 0x5D;

/// Maximum buffer size for I/O.
/// PublicInputs with overlapped_signatures carrying VBC bundles (SPHINCS+ keys + sigs)
/// can exceed 128KB when serialized as JSON. CL5 redeems with k=5 cheques + full VBC
/// chains + 6-link FACT chains can exceed 4MB in CBOR. 8MB provides headroom.
const IO_BUFFER_SIZE: usize = 8 * 1024 * 1024;

/// Perform an ecall syscall
///
/// # Safety
/// This is the only way to communicate with the AVM host.
#[inline(always)]
unsafe fn ecall(syscall: usize, a0: usize, a1: usize) -> usize {
    let ret: usize;
    core::arch::asm!(
        "ecall",
        in("a7") syscall,
        inlateout("a0") a0 => ret,
        in("a1") a1,
    );
    ret
}

/// Read PublicInputs from host (CBOR — no JSON in Core)
fn read_inputs() -> PublicInputs {
    let mut buf = vec![0u8; IO_BUFFER_SIZE];
    let bytes_read = unsafe {
        ecall(SYS_READ_INPUTS, buf.as_mut_ptr() as usize, buf.len())
    };
    buf.truncate(bytes_read);
    match ciborium::de::from_reader(&buf[..]) {
        Ok(inputs) => inputs,
        Err(_) => {
            // Cannot deserialize — exit with code 2 (distinguishable from
            // panic exit code 1). Host catches this as AvmError::ExecutionError.
            // Prevents guest panic on oversized or malformed inputs.
            unsafe { ecall(SYS_EXIT, 2, 0); }
            unreachable!()
        }
    }
}

/// Write PublicOutputs to host (CBOR — no JSON in Core)
fn write_outputs(outputs: &PublicOutputs) {
    let mut buf = alloc::vec::Vec::new();
    ciborium::ser::into_writer(outputs, &mut buf).expect("Failed to serialize PublicOutputs");
    unsafe {
        ecall(SYS_WRITE_OUTPUTS, buf.as_ptr() as usize, buf.len());
    }
}

/// Exit guest execution
fn exit(code: usize) -> ! {
    unsafe {
        ecall(SYS_EXIT, code, 0);
    }
    // Should never reach here
    loop {}
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 0. Initialize BSS and heap (bare metal — no runtime does this for us)
    unsafe {
        extern "C" {
            static mut __bss_start: u8;
            static mut __bss_end: u8;
        }
        let bss_start = &raw mut __bss_start as *mut u8;
        let bss_end = &raw mut __bss_end as *mut u8;
        let bss_len = bss_end as usize - bss_start as usize;
        if bss_len > 0 {
            core::ptr::write_bytes(bss_start, 0, bss_len);
        }
        // Set heap start to end of BSS (aligned to 16 bytes)
        let heap_start = (bss_end as usize + 15) & !15;
        allocator::init_heap(heap_start);
    }

    // 1. Read inputs from host
    let inputs = read_inputs();

    // 2. Execute Core validation logic (all CL1-CL8 modes)
    let outputs = execute_core(inputs);

    // 3. Write outputs back to host
    write_outputs(&outputs);

    // 4. Exit successfully
    exit(0);
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // KnownIssue #2 fix: ship the panic location to host so future
    // panics are diagnosable. Pre-fix this handler sent only the
    // static `AVM_GUEST_PANIC` marker — every panic looked identical
    // on host and localizing required rebuilding with debug symbols.
    //
    // We can't allocate here (the panic might itself be alloc OOM
    // → double-fault), so the message is built into a fixed-size
    // stack buffer via core::fmt::Write. If formatting fails or
    // location is unknown, we fall back to the static marker.
    use core::fmt::Write;

    struct StackBuf<const N: usize> {
        buf: [u8; N],
        len: usize,
    }
    impl<const N: usize> Write for StackBuf<N> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let bytes = s.as_bytes();
            let room = N.saturating_sub(self.len);
            let n = bytes.len().min(room);
            self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
            self.len += n;
            if n < bytes.len() {
                Err(core::fmt::Error)
            } else {
                Ok(())
            }
        }
    }

    let mut sb = StackBuf::<512> { buf: [0u8; 512], len: 0 };
    let _ = write!(&mut sb, "AVM_GUEST_PANIC ");
    if let Some(loc) = info.location() {
        let _ = write!(&mut sb, "at {}:{}:{}", loc.file(), loc.line(), loc.column());
    } else {
        let _ = write!(&mut sb, "at <unknown>");
    }
    // Note: PanicInfo::message() is &PanicMessage which Display-formats
    // the panic args. write! handles the formatting via Display.
    let _ = write!(&mut sb, " — {}", info.message());

    // Static fallback in case formatting somehow produced 0 bytes
    // (shouldn't happen given the literal above always writes bytes).
    static FALLBACK: &[u8] = b"AVM_GUEST_PANIC";
    let (ptr, len) = if sb.len > 0 {
        (sb.buf.as_ptr() as usize, sb.len)
    } else {
        (FALLBACK.as_ptr() as usize, FALLBACK.len())
    };

    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") 0x10usize, // HOST_CALL
            in("a0") 0xFFusize, // panic func_id (unused, just a marker)
            in("a1") ptr,
            in("a2") len,
        );
    }
    exit(1);
}

/// Simple bump allocator for no_std RISC-V guest
pub(crate) mod allocator {
    use core::alloc::{GlobalAlloc, Layout};
    use core::cell::UnsafeCell;

    /// Bump allocator: simple, fast, no deallocation.
    /// Fine for short-lived guest execution (allocate → run → exit).
    struct BumpAllocator {
        heap_pos: UnsafeCell<usize>,
    }

    unsafe impl Sync for BumpAllocator {}

    /// Initialize the heap start position. Must be called before any allocation.
    pub(crate) unsafe fn init_heap(start: usize) {
        *ALLOCATOR.heap_pos.get() = start;
    }

    unsafe impl GlobalAlloc for BumpAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let pos = &mut *self.heap_pos.get();
            let align = layout.align();
            let aligned = (*pos + align - 1) & !(align - 1);
            let new_pos = aligned + layout.size();

            // Simple bounds check against stack (leave 64KB guard)
            extern "C" {
                static __stack_top: u8;
            }
            let stack_limit = &__stack_top as *const u8 as usize - 65536;
            if new_pos > stack_limit {
                return core::ptr::null_mut();
            }

            *pos = new_pos;
            aligned as *mut u8
        }

        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
            // Bump allocator: no deallocation (guest is short-lived)
        }
    }

    #[global_allocator]
    static ALLOCATOR: BumpAllocator = BumpAllocator {
        heap_pos: UnsafeCell::new(0),
    };
}
