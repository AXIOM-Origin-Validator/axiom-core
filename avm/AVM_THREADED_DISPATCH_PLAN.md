# AVM Threaded Dispatch Implementation Plan

## Goal

Improve RISC-V interpreter throughput from ~12M instructions/sec to ~50-60M instructions/sec (4-5x) without changing the ELF, the protocol, or the trust model.

## Current Architecture

```
executor.rs::step()
  → memory.read_u32(pc)           // instruction fetch
  → Instruction::decode(raw)      // decode fields (rd, rs1, rs2, imm, funct3, funct7)
  → match inst.opcode { ... }     // BIG MATCH dispatch (~50 arms)
  → execute + update pc
  → return Ok(None) to run loop
```

**Why it's slow:**
1. **Match dispatch overhead.** Each instruction goes through a Rust `match` with ~10 opcode arms, each containing nested `match` on funct3/funct7. The CPU's branch predictor can't predict indirect jumps through match tables. ~5-10 cycles wasted per instruction on dispatch alone.
2. **Function call overhead.** `step()` is called per instruction from `run_with_checkpoints()`. Each call has prologue/epilogue, Result unwrapping, Option checking.
3. **Instruction re-decode.** `Instruction::decode()` extracts all fields (rd, rs1, rs2, imm, funct3, funct7) even when only a subset is needed for the current opcode.
4. **Register access indirection.** `self.reg(n)` and `self.set_rd(n, val)` are method calls with bounds-implied checks per register access.

## Implementation Plan

### Phase 1: Inline the main loop (1-2x, ~2 hours)

Eliminate per-instruction function call overhead by inlining `step()` into the main loop.

**Change:** Merge `step()` body directly into `run_with_checkpoints()`. The hot loop becomes:

```rust
loop {
    let raw = self.memory.read_u32_unchecked(self.pc);
    let opcode = raw & 0x7F;
    self.instruction_count += 1;
    
    match opcode {
        0x37 => { /* LUI - inline */ }
        0x17 => { /* AUIPC - inline */ }
        // ... all opcodes inline
    }
}
```

Remove the `Result<Option<ExitReason>>` return path — use direct control flow (break/return) for exits.

### Phase 2: Decode-caching (1.5-2x on top, ~4 hours)

Pre-decode the ELF's text section into a flat array of `DecodedInstruction` structs at load time. During execution, index by `(pc - text_base) / 4` instead of re-decoding.

```rust
struct DecodedInstruction {
    handler: u8,      // opcode+funct3+funct7 → handler index (0-63)
    rd: u8,
    rs1: u8,
    rs2: u8,
    imm: i32,
}
```

**Why this helps:** decode is ~10% of per-instruction cost. More importantly, the `handler` field collapses the two-level match (opcode → funct3) into a single index, enabling...

### Phase 3: Computed goto / jump table dispatch (~2x on top, ~6 hours)

Replace the `match opcode` with a jump table indexed by `handler`. In Rust, this requires `unsafe` but is well-established:

```rust
// Build jump table at init
static HANDLERS: [fn(&mut Cpu, &DecodedInstruction); 64] = [
    handle_lui, handle_auipc, handle_jal, handle_jalr,
    handle_beq, handle_bne, handle_blt, handle_bge, ...
];

// Hot loop
loop {
    let inst = &decoded[((self.pc - text_base) >> 2) as usize];
    HANDLERS[inst.handler as usize](self, inst);
}
```

Or using Rust's computed goto pattern (via `unsafe { std::arch::asm!() }` or function pointer array).

**Why this helps:** the CPU's indirect branch predictor handles a function pointer array MUCH better than a large `match` — the branch target is data-dependent and cacheable. LuaJIT's interpreter uses this exact technique to achieve 60M+ instr/sec.

### Phase 4: Register caching (~1.3x on top, ~3 hours)

Map the 8 most-used RISC-V registers (sp, ra, a0-a5) to local variables in the main loop. The Rust compiler will place them in native CPU registers.

```rust
let mut r_sp = self.regs[2];
let mut r_ra = self.regs[1];
let mut r_a0 = self.regs[10];
// ... hot registers in locals

// Sync back to self.regs only on ecall/checkpoint
```

**Why this helps:** `self.regs[n]` goes through a pointer dereference + array index. A local variable is a native register read — zero latency.

### Phase 5: Superinstructions (~1.2x on top, ~4 hours)

Identify common instruction PAIRS in the decoded stream and fuse them into single handlers:

```
ADDI + SW   →  super_addi_sw     (stack push pattern)
LW + ADDI   →  super_lw_addi     (load-and-increment)
BEQ + JAL   →  super_beq_jal     (branch-or-jump)
LUI + ADDI  →  super_li          (load-immediate 32-bit)
```

Scan the decoded instruction array at load time. When a pair is detected, replace with a single superinstruction handler that does both operations in one dispatch.

**Why this helps:** eliminates one dispatch cycle per fused pair. RISC-V code has very regular patterns (especially compiler-generated code from `rustc`). 10-20% of instruction pairs are fusable.

## Expected Results

| Phase | Technique | Multiplier | Cumulative | Est. instr/sec |
|---|---|---|---|---|
| Baseline | Current match dispatch | 1.0x | 1.0x | 12M |
| Phase 1 | Inline main loop | 1.5x | 1.5x | 18M |
| Phase 2 | Decode caching | 1.5x | 2.25x | 27M |
| Phase 3 | Jump table dispatch | 1.8x | 4.0x | 48M |
| Phase 4 | Register caching | 1.3x | 5.2x | 62M |
| Phase 5 | Superinstructions | 1.2x | 6.3x | 75M |

**Conservative target: 4x (Phases 1-3).** Phases 4-5 are incremental and can be deferred.

## Impact on Dilithium/FACT

| Metric | Current (12M/s) | After 4x (48M/s) | After 6x (75M/s) |
|---|---|---|---|
| Dilithium verify | 2.0s | 0.5s | 0.3s |
| k=3 depth-5 FACT | 30s | 7.5s | 4.8s |
| Per-TX total (k=3) | 30-60s | 8-15s | 5-10s |
| Timeout rate (est.) | 35% | <10% | <5% |

## IMPORTANT: JIT startup time is a FEATURE, not a bug

The Cranelift JIT compiles the entire RISC-V ELF to native code at validator
startup. This takes ~30-60 seconds. **DO NOT OPTIMIZE THIS AWAY.**

In AXIOM's security model, Core restart is a PENALTY (YPX-009 Silicon Pulse
audit failure → Core self-terminates → VBC re-verification). The JIT
compilation cost IS part of the restart penalty:

- Honest validators: start once, run at native speed for weeks
- Dishonest validators: forced restart → 30-60s JIT recompile → lost revenue

Reducing startup time would weaken the audit penalty. The slow compilation
is an intentional security property, not a performance bug to fix.

**DO NOT:**
- Cache compiled native code to disk
- Lazy-compile only hot blocks
- Skip compilation on restart
- Background-thread the compilation

The full upfront compile is the design. Accept the startup cost.

## What does NOT change

- The RISC-V ELF binary (same .text section, same instructions)
- The execution result (same PublicOutputs for same PublicInputs)
- The DMAP proof model (checkpoints still collected at same instruction counts)
- The trust model (Core is still sole authority, no host functions for crypto)
- Cross-platform compatibility (all changes are in Rust interpreter code)
- The instruction count metric (same count, just faster wall-clock)

## Testing strategy

1. **Conformance:** run all 505 Core tests + 20 conformance vectors. Same outputs.
2. **DMAP:** verify checkpoint hashes match between old and new interpreter for same ELF + inputs.
3. **Soak:** 72h adversarial with new interpreter. Compare to baseline.
4. **Benchmark:** before/after on `AVM took Xs` in ANTIE logs across 100+ TXs.

## Files to modify

- `core/avm/src/riscv/executor.rs` — main changes (Phases 1-4)
- `core/avm/src/riscv/decoder.rs` — DecodedInstruction struct (Phase 2)
- `core/avm/src/riscv/elf_loader.rs` — pre-decode at load time (Phase 2)
- `core/avm/src/interpreter.rs` — may need to thread new executor API
- No changes to `core/logic/`, `lambda/`, `nabla/`, `antie/`, `scripts/`

## Estimated effort

- Phase 1: 2 hours
- Phase 2: 4 hours  
- Phase 3: 6 hours
- Phase 4: 3 hours
- Phase 5: 4 hours
- Testing: 4 hours
- **Total: ~23 hours for full 6x, ~12 hours for 4x (Phases 1-3)**
