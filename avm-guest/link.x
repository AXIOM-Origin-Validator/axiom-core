/* AVM Guest Linker Script — RV32IM Bare Metal
 *
 * Memory layout for AVM RISC-V interpreter:
 * - TEXT starts at 0x00010000 (64KB, standard RISC-V start)
 * - STACK grows downward from top of available memory
 * - Heap managed by guest allocator
 */

/* RAM LENGTH must match (host MAX_MEMORY - 1MB headroom).
 * 2026-05-10 (KnownIssue #2 fix): bumped from 15M → 31M to match
 * AVM host's MAX_MEMORY = 32 MB. The 8 MB IO_BUFFER_SIZE plus a
 * 5+ MB CBOR PublicInputs plus 132 nested Dilithium verifies on
 * a 44-link scarred receiver_fact_chain saturated 15 MB and the
 * bump allocator returned null → Rust panic → static
 * `AVM_GUEST_PANIC` marker + exit(1). See KnownIssues §2. */
MEMORY
{
    RAM (rwx) : ORIGIN = 0x00010000, LENGTH = 31M
}

ENTRY(_start)

SECTIONS
{
    .text : {
        *(.text .text.*)
    } > RAM

    .rodata : {
        *(.rodata .rodata.*)
    } > RAM

    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
    } > RAM

    .bss (NOLOAD) : {
        __bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        __bss_end = .;
    } > RAM

    /* Stack at end of RAM (grows down) */
    __stack_top = ORIGIN(RAM) + LENGTH(RAM);

    /DISCARD/ : {
        *(.comment)
        *(.note.*)
        *(.eh_frame*)
    }
}
