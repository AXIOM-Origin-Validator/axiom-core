//! Fast RV32IM CPU Executor — Threaded Dispatch
//!
//! Drop-in replacement for executor.rs with 4-5x throughput via:
//!   Phase 1: Inlined main loop (no per-instruction function call overhead)
//!   Phase 2: Pre-decoded instruction cache (decode once at load time)
//!   Phase 3: Jump table dispatch (function pointer array, not match)
//!
//! Produces identical results to the original executor for any input.
//! The RISC-V ELF, DMAP proof model, and trust model are unchanged.

use alloc::format;
use alloc::vec::Vec;
use super::decoder::Instruction;
use super::memory::GuestMemory;
use crate::host_functions::HostFunctions;
use super::executor::{ExitReason, CpuState, MAX_INSTRUCTIONS, syscall, decimate_reservoir};

/// Pre-decoded instruction for fast dispatch.
/// Collapses opcode+funct3+funct7 into a single handler index.
#[derive(Clone, Copy)]
struct DecodedOp {
    handler: u8,
    rd: u8,
    rs1: u8,
    rs2: u8,
    imm: i32,
    raw: u32,
}

/// Handler indices — one per unique instruction variant.
/// Collapsed from the two-level opcode → funct3 dispatch.
mod handlers {
    pub const LUI: u8 = 0;
    pub const AUIPC: u8 = 1;
    pub const JAL: u8 = 2;
    pub const JALR: u8 = 3;
    pub const BEQ: u8 = 4;
    pub const BNE: u8 = 5;
    pub const BLT: u8 = 6;
    pub const BGE: u8 = 7;
    pub const BLTU: u8 = 8;
    pub const BGEU: u8 = 9;
    pub const LB: u8 = 10;
    pub const LH: u8 = 11;
    pub const LW: u8 = 12;
    pub const LBU: u8 = 13;
    pub const LHU: u8 = 14;
    pub const SB: u8 = 15;
    pub const SH: u8 = 16;
    pub const SW: u8 = 17;
    pub const ADDI: u8 = 18;
    pub const SLTI: u8 = 19;
    pub const SLTIU: u8 = 20;
    pub const XORI: u8 = 21;
    pub const ORI: u8 = 22;
    pub const ANDI: u8 = 23;
    pub const SLLI: u8 = 24;
    pub const SRLI: u8 = 25;
    pub const SRAI: u8 = 26;
    pub const ADD: u8 = 27;
    pub const SUB: u8 = 28;
    pub const SLL: u8 = 29;
    pub const SLT: u8 = 30;
    pub const SLTU: u8 = 31;
    pub const XOR: u8 = 32;
    pub const SRL: u8 = 33;
    pub const SRA: u8 = 34;
    pub const OR: u8 = 35;
    pub const AND: u8 = 36;
    pub const MUL: u8 = 37;
    pub const MULH: u8 = 38;
    pub const MULHSU: u8 = 39;
    pub const MULHU: u8 = 40;
    pub const DIV: u8 = 41;
    pub const DIVU: u8 = 42;
    pub const REM: u8 = 43;
    pub const REMU: u8 = 44;
    pub const FENCE: u8 = 45;
    pub const ECALL: u8 = 46;
    pub const EBREAK: u8 = 47;
    pub const CSR_NOP: u8 = 48;
    pub const ILLEGAL: u8 = 63;
    // Phase 5: Superinstructions (fused pairs)
    pub const SUPER_ADDI_ADDI: u8 = 50;
    pub const SUPER_LW_LW: u8 = 51;
    pub const SUPER_LUI_ADDI: u8 = 52;
    pub const SUPER_SW_SW: u8 = 53;
}

/// Classify a raw instruction into a handler index.
fn classify(raw: u32) -> u8 {
    let opcode = raw & 0x7F;
    let funct3 = (raw >> 12) & 0x7;
    let funct7 = (raw >> 25) & 0x7F;

    match opcode {
        0b0110111 => handlers::LUI,
        0b0010111 => handlers::AUIPC,
        0b1101111 => handlers::JAL,
        0b1100111 => handlers::JALR,
        0b1100011 => match funct3 {
            0b000 => handlers::BEQ,
            0b001 => handlers::BNE,
            0b100 => handlers::BLT,
            0b101 => handlers::BGE,
            0b110 => handlers::BLTU,
            0b111 => handlers::BGEU,
            _ => handlers::ILLEGAL,
        },
        0b0000011 => match funct3 {
            0b000 => handlers::LB,
            0b001 => handlers::LH,
            0b010 => handlers::LW,
            0b100 => handlers::LBU,
            0b101 => handlers::LHU,
            _ => handlers::ILLEGAL,
        },
        0b0100011 => match funct3 {
            0b000 => handlers::SB,
            0b001 => handlers::SH,
            0b010 => handlers::SW,
            _ => handlers::ILLEGAL,
        },
        0b0010011 => match funct3 {
            0b000 => handlers::ADDI,
            0b010 => handlers::SLTI,
            0b011 => handlers::SLTIU,
            0b100 => handlers::XORI,
            0b110 => handlers::ORI,
            0b111 => handlers::ANDI,
            0b001 => handlers::SLLI,
            0b101 => if funct7 & 0x20 != 0 { handlers::SRAI } else { handlers::SRLI },
            _ => handlers::ILLEGAL,
        },
        0b0110011 => {
            if funct7 == 0x01 {
                match funct3 {
                    0b000 => handlers::MUL,
                    0b001 => handlers::MULH,
                    0b010 => handlers::MULHSU,
                    0b011 => handlers::MULHU,
                    0b100 => handlers::DIV,
                    0b101 => handlers::DIVU,
                    0b110 => handlers::REM,
                    0b111 => handlers::REMU,
                    _ => handlers::ILLEGAL,
                }
            } else {
                match funct3 {
                    0b000 => if funct7 == 0x20 { handlers::SUB } else { handlers::ADD },
                    0b001 => handlers::SLL,
                    0b010 => handlers::SLT,
                    0b011 => handlers::SLTU,
                    0b100 => handlers::XOR,
                    0b101 => if funct7 == 0x20 { handlers::SRA } else { handlers::SRL },
                    0b110 => handlers::OR,
                    0b111 => handlers::AND,
                    _ => handlers::ILLEGAL,
                }
            }
        },
        0b0001111 => handlers::FENCE,
        0b1110011 => {
            if funct3 == 0 {
                let funct12 = (raw >> 20) & 0xFFF;
                if funct12 == 1 { handlers::EBREAK } else { handlers::ECALL }
            } else {
                handlers::CSR_NOP
            }
        },
        _ => handlers::ILLEGAL,
    }
}

/// Pre-decode an instruction from its raw u32.
fn predecode(raw: u32) -> DecodedOp {
    let inst = Instruction::decode(raw);
    DecodedOp {
        handler: classify(raw),
        rd: inst.rd as u8,
        rs1: inst.rs1 as u8,
        rs2: inst.rs2 as u8,
        imm: inst.imm,
        raw,
    }
}

/// Instruction cache — pre-decoded text section.
pub struct InstructionCache {
    ops: Vec<DecodedOp>,
    text_base: u32,
    text_end: u32,
}

impl InstructionCache {
    /// Build instruction cache from a memory region.
    /// Call after ELF is loaded into guest memory.
    pub fn build(memory: &GuestMemory, text_base: u32, text_size: u32) -> Self {
        let num_instructions = (text_size / 4) as usize;
        let mut ops = Vec::with_capacity(num_instructions);
        for i in 0..num_instructions {
            let addr = text_base + (i as u32) * 4;
            let raw = memory.read_u32(addr).unwrap_or(0);
            ops.push(predecode(raw));
        }
        // Phase 5: Superinstruction fusion — scan for common pairs and
        // replace the first instruction's handler with a fused handler.
        // The fused handler executes both instructions in one dispatch cycle.
        // The second instruction is left as-is (skipped by pc += 8 in the
        // fused handler). This is safe because the second instruction is
        // only reached via the fused handler's pc advance, never directly
        // (branches always target the first instruction of a pair).
        // Phase 5: Superinstruction fusion — only fuse pairs where the
        // second instruction does NOT depend on the first instruction's rd
        // (to avoid read-after-write hazards in the fused execution).
        let len = ops.len();
        for i in 0..len.saturating_sub(1) {
            let h0 = ops[i].handler;
            let h1 = ops[i + 1].handler;
            let rd0 = ops[i].rd;
            let rs1_1 = ops[i + 1].rs1;
            let rs2_1 = ops[i + 1].rs2;
            // Skip fusion if op2 reads what op1 writes (RAW hazard)
            let has_hazard = rd0 != 0 && (rd0 == rs1_1 || rd0 == rs2_1);
            if has_hazard {
                // Exception: LUI+ADDI is specifically designed as a pair
                // where ADDI reads LUI's rd (load-immediate pattern).
                if h0 != handlers::LUI || h1 != handlers::ADDI {
                    continue;
                }
            }
            match (h0, h1) {
                (handlers::ADDI, handlers::ADDI) => ops[i].handler = handlers::SUPER_ADDI_ADDI,
                (handlers::LW, handlers::LW) => ops[i].handler = handlers::SUPER_LW_LW,
                (handlers::LUI, handlers::ADDI) => ops[i].handler = handlers::SUPER_LUI_ADDI,
                (handlers::SW, handlers::SW) => ops[i].handler = handlers::SUPER_SW_SW,
                _ => {}
            }
        }

        InstructionCache {
            ops,
            text_base,
            text_end: text_base + text_size,
        }
    }

    /// Get pre-decoded instruction at PC. Returns None if PC is outside
    /// the cached text section (self-modifying code or data execution).
    #[inline(always)]
    fn get(&self, pc: u32) -> Option<&DecodedOp> {
        if pc >= self.text_base && pc < self.text_end {
            let idx = ((pc - self.text_base) >> 2) as usize;
            self.ops.get(idx)
        } else {
            None
        }
    }
}

/// Fast CPU — uses pre-decoded instruction cache + inlined dispatch.
/// With `cranelift-jit-backend` feature, also tries compiled native blocks first.
pub struct FastCpu {
    pub regs: [u32; 32],
    pub pc: u32,
    pub memory: GuestMemory,
    pub instruction_count: u64,
    host: HostFunctions,
    input_buffer: Vec<u8>,
    output_buffer: Vec<u8>,
    output_written: bool,
    icache: Option<InstructionCache>,
    #[cfg(feature = "cranelift-jit-backend")]
    jit: Option<alloc::sync::Arc<super::jit::JitEngine>>,
    #[cfg(feature = "cranelift-jit-backend")]
    jit_insts: u64,
}

impl FastCpu {
    pub fn new(memory: GuestMemory, entry_point: u32, input: Vec<u8>, host: HostFunctions) -> Self {
        let regs = [0u32; 32];
        FastCpu {
            regs,
            pc: entry_point,
            memory,
            instruction_count: 0,
            host,
            input_buffer: input,
            output_buffer: Vec::new(),
            output_written: false,
            icache: None,
            #[cfg(feature = "cranelift-jit-backend")]
            jit: None,
            #[cfg(feature = "cranelift-jit-backend")]
            jit_insts: 0,
        }
    }

    /// Set the instruction cache (call after ELF load).
    pub fn set_icache(&mut self, icache: InstructionCache) {
        self.icache = Some(icache);
    }

    /// Set the JIT engine (call after ELF load + text section translation).
    #[cfg(feature = "cranelift-jit-backend")]
    pub fn set_jit(&mut self, jit: alloc::sync::Arc<super::jit::JitEngine>) {
        self.jit = Some(jit);
    }

    pub fn output(&self) -> &[u8] { &self.output_buffer }
    pub fn has_output(&self) -> bool { self.output_written }

    pub fn snapshot(&mut self) -> CpuState {
        let register_hash = {
            let mut hasher = blake3::Hasher::new();
            for &r in &self.regs {
                hasher.update(&r.to_le_bytes());
            }
            *hasher.finalize().as_bytes()
        };
        CpuState {
            pc: self.pc,
            instruction_count: self.instruction_count,
            memory_root: self.memory.memory_root(),
            register_hash,
        }
    }

    #[cfg(feature = "cranelift-jit-backend")]
    fn log_jit_stats(&self) {
        #[cfg(feature = "std")]
        if self.jit.is_some() {
            let total = self.instruction_count;
            let jit = self.jit_insts;
            let interp = total.saturating_sub(jit);
            let pct = if total > 0 { (jit as f64 / total as f64) * 100.0 } else { 0.0 };
            eprintln!("[JIT-STATS] total={} jit={} interp={} coverage={:.1}%", total, jit, interp, pct);
        }
    }

    pub fn run(&mut self) -> ExitReason {
        self.run_with_checkpoints(&[], None, &mut Vec::new())
    }

    pub fn run_with_checkpoints(
        &mut self,
        specific_indices: &[u64],
        checkpoint_interval: Option<u64>,
        checkpoints_out: &mut Vec<CpuState>,
    ) -> ExitReason {
        let mut specific_set: Vec<u64> = specific_indices.to_vec();
        specific_set.sort();
        // Next instruction_count at which to take an interior checkpoint. Monotonic
        // threshold, NOT exact-multiple: the JIT advances instruction_count in block
        // jumps (+= block_insts) and the interpreter's fused pairs advance by 2, so an
        // `is_multiple_of(interval)` test almost never lands on a boundary. u64::MAX
        // when no interval is requested ⇒ the checkpoint branch never fires.
        let mut next_checkpoint_at: u64 = checkpoint_interval.unwrap_or(u64::MAX);
        // Effective (mutable) interval: doubles whenever the collected set hits
        // MAX_COLLECTED_CHECKPOINTS so a huge run coarsens instead of collecting
        // unboundedly (KI#39 perf — see crate::dmap::MAX_COLLECTED_CHECKPOINTS).
        let mut cur_interval: u64 = checkpoint_interval.unwrap_or(0);

        #[cfg(feature = "cranelift-jit-backend")]
        let mut jit_skip_pc: Option<u32> = None;

        // Phase 4: Register caching — keep hot RISC-V registers in local
        // variables. The Rust compiler maps locals to native CPU registers,
        // eliminating the self.regs[n] array index + pointer deref per access.
        // Sync back to self.regs on ecall/checkpoint/exit.
        let mut r_sp  = self.regs[2];   // x2  — stack pointer
        let mut r_ra  = self.regs[1];   // x1  — return address
        let mut r_a0  = self.regs[10];  // x10 — arg0 / return value
        let mut r_a1  = self.regs[11];  // x11 — arg1
        let mut r_a2  = self.regs[12];  // x12 — arg2
        let mut r_a3  = self.regs[13];  // x13 — arg3
        let mut r_a4  = self.regs[14];  // x14 — arg4
        let mut r_a5  = self.regs[15];  // x15 — arg5
        let mut r_a7  = self.regs[17];  // x17 — syscall number

        // Macro: read register value from cache or array
        macro_rules! reg {
            (0) => { 0u32 };
            ($idx:expr) => {
                match $idx {
                    0 => 0,
                    1 => r_ra,
                    2 => r_sp,
                    10 => r_a0, 11 => r_a1, 12 => r_a2, 13 => r_a3,
                    14 => r_a4, 15 => r_a5, 17 => r_a7,
                    n => self.regs[n as usize],
                }
            };
        }

        // Macro: write register value to cache and array
        macro_rules! set_reg {
            ($idx:expr, $val:expr) => {
                if $idx != 0 {
                    let v = $val;
                    match $idx {
                        1 => r_ra = v,
                        2 => r_sp = v,
                        10 => r_a0 = v, 11 => r_a1 = v, 12 => r_a2 = v,
                        13 => r_a3 = v, 14 => r_a4 = v, 15 => r_a5 = v,
                        17 => r_a7 = v,
                        _ => {}
                    }
                    self.regs[$idx as usize] = v;
                }
            };
        }

        // Macro: sync cached registers back to self.regs (for ecall/checkpoint)
        macro_rules! sync_regs {
            () => {
                self.regs[1] = r_ra;
                self.regs[2] = r_sp;
                self.regs[10] = r_a0; self.regs[11] = r_a1;
                self.regs[12] = r_a2; self.regs[13] = r_a3;
                self.regs[14] = r_a4; self.regs[15] = r_a5;
                self.regs[17] = r_a7;
            };
        }

        // Macro: reload cached registers from self.regs (after ecall modifies them)
        macro_rules! reload_regs {
            () => {
                r_ra = self.regs[1]; r_sp = self.regs[2];
                r_a0 = self.regs[10]; r_a1 = self.regs[11];
                r_a2 = self.regs[12]; r_a3 = self.regs[13];
                r_a4 = self.regs[14]; r_a5 = self.regs[15];
                r_a7 = self.regs[17];
            };
        }

        loop {
            if self.instruction_count >= MAX_INSTRUCTIONS {
                sync_regs!();
                #[cfg(feature = "cranelift-jit-backend")]
                self.log_jit_stats();
                return ExitReason::InstructionLimit;
            }

            if cur_interval > 0 && self.instruction_count >= next_checkpoint_at {
                sync_regs!();
                checkpoints_out.push(self.snapshot());
                self.memory.clear_dirty();
                // Bounded collection (KI#39): once the set hits the cap, keep
                // every other checkpoint (in-stream power-of-two decimation) and
                // double the interval. The retained set stays a uniform sample
                // spanning the run at 2× spacing; going forward we collect at the
                // doubled interval. Reveals + verification use each checkpoint's
                // exact instruction_count, so this is transparent to detection.
                if checkpoints_out.len() >= crate::dmap::MAX_COLLECTED_CHECKPOINTS {
                    cur_interval = decimate_reservoir(checkpoints_out, cur_interval);
                }
                next_checkpoint_at += cur_interval;
                // If a JIT block or fused pair jumped past more than one interval
                // boundary, skip forward so we take exactly one checkpoint per
                // window (block granularity — "at least every interval + one block").
                if next_checkpoint_at <= self.instruction_count {
                    next_checkpoint_at = (self.instruction_count / cur_interval + 1) * cur_interval;
                }
            }

            // JIT fast path: tight inner loop with register pinning.
            #[cfg(feature = "cranelift-jit-backend")]
            if let Some(ref jit_arc) = self.jit {
                let jit = jit_arc.clone();
                let skip = jit_skip_pc == Some(self.pc);
                if !skip {
                    if let Some(block) = jit.get_block(self.pc) {
                        sync_regs!();
                        let (new_pc, block_insts) = unsafe {
                            jit.execute_block(block, &mut self.regs, &mut self.memory)
                        };
                        reload_regs!();
                        self.instruction_count += block_insts as u64;
                        self.jit_insts += block_insts as u64;

                        match new_pc {
                            super::jit::ECALL_SENTINEL => {
                                let ecall_pc = block.start_pc + (block_insts - 1) * 4;
                                self.pc = ecall_pc;
                                sync_regs!();
                                match self.handle_ecall() {
                                    Ok(None) => { reload_regs!(); self.pc = ecall_pc.wrapping_add(4); continue; }
                                    Ok(Some(reason)) => return reason,
                                    Err(reason) => return reason,
                                }
                            }
                            super::jit::EBREAK_SENTINEL => {
                                sync_regs!();
                                return ExitReason::Ebreak;
                            }
                            super::jit::ILLEGAL_SENTINEL => {
                                jit_skip_pc = Some(self.pc);
                            }
                            pc => {
                                self.pc = pc;
                                self.regs[0] = 0;
                                jit_skip_pc = None;
                                continue;
                            }
                        }
                    }
                }
            }

            // Interpreter path: decode from icache or memory
            let op = if let Some(ref icache) = self.icache {
                if let Some(cached) = icache.get(self.pc) {
                    *cached
                } else {
                    match self.memory.read_u32(self.pc) {
                        Ok(raw) => predecode(raw),
                        Err(e) => { sync_regs!(); return ExitReason::MemoryFault(self.pc, format!("Fetch: {}", e)); }
                    }
                }
            } else {
                match self.memory.read_u32(self.pc) {
                    Ok(raw) => predecode(raw),
                    Err(e) => { sync_regs!(); return ExitReason::MemoryFault(self.pc, format!("Fetch: {}", e)); }
                }
            };

            self.instruction_count += 1;
            let rd = op.rd as usize;
            let rs1v = reg!(op.rs1 as usize);
            let imm = op.imm as u32;

            match op.handler {
                handlers::LUI => {
                    set_reg!(rd, imm);
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::AUIPC => {
                    set_reg!(rd, self.pc.wrapping_add(imm));
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::JAL => {
                    set_reg!(rd, self.pc.wrapping_add(4));
                    self.pc = self.pc.wrapping_add(imm);
                }
                handlers::JALR => {
                    let target = rs1v.wrapping_add(imm) & !1;
                    set_reg!(rd, self.pc.wrapping_add(4));
                    self.pc = target;
                }
                // Branches — inlined, no nested match
                handlers::BEQ => {
                    let rs2v = reg!(op.rs2 as usize);
                    self.pc = if rs1v == rs2v { self.pc.wrapping_add(imm) } else { self.pc.wrapping_add(4) };
                }
                handlers::BNE => {
                    let rs2v = reg!(op.rs2 as usize);
                    self.pc = if rs1v != rs2v { self.pc.wrapping_add(imm) } else { self.pc.wrapping_add(4) };
                }
                handlers::BLT => {
                    let rs2v = reg!(op.rs2 as usize);
                    self.pc = if (rs1v as i32) < (rs2v as i32) { self.pc.wrapping_add(imm) } else { self.pc.wrapping_add(4) };
                }
                handlers::BGE => {
                    let rs2v = reg!(op.rs2 as usize);
                    self.pc = if (rs1v as i32) >= (rs2v as i32) { self.pc.wrapping_add(imm) } else { self.pc.wrapping_add(4) };
                }
                handlers::BLTU => {
                    let rs2v = reg!(op.rs2 as usize);
                    self.pc = if rs1v < rs2v { self.pc.wrapping_add(imm) } else { self.pc.wrapping_add(4) };
                }
                handlers::BGEU => {
                    let rs2v = reg!(op.rs2 as usize);
                    self.pc = if rs1v >= rs2v { self.pc.wrapping_add(imm) } else { self.pc.wrapping_add(4) };
                }
                // Loads — inlined
                handlers::LB => {
                    let addr = rs1v.wrapping_add(imm);
                    match self.memory.read_u8(addr) {
                        Ok(b) => { set_reg!(rd, (b as i8) as i32 as u32); }
                        Err(e) => return ExitReason::MemoryFault(self.pc, format!("LB: {}", e)),
                    }
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::LH => {
                    let addr = rs1v.wrapping_add(imm);
                    match self.memory.read_u16(addr) {
                        Ok(h) => { set_reg!(rd, (h as i16) as i32 as u32); }
                        Err(e) => return ExitReason::MemoryFault(self.pc, format!("LH: {}", e)),
                    }
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::LW => {
                    let addr = rs1v.wrapping_add(imm);
                    match self.memory.read_u32(addr) {
                        Ok(w) => { set_reg!(rd, w); }
                        Err(e) => return ExitReason::MemoryFault(self.pc, format!("LW: {}", e)),
                    }
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::LBU => {
                    let addr = rs1v.wrapping_add(imm);
                    match self.memory.read_u8(addr) {
                        Ok(b) => { set_reg!(rd, b as u32); }
                        Err(e) => return ExitReason::MemoryFault(self.pc, format!("LBU: {}", e)),
                    }
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::LHU => {
                    let addr = rs1v.wrapping_add(imm);
                    match self.memory.read_u16(addr) {
                        Ok(h) => { set_reg!(rd, h as u32); }
                        Err(e) => return ExitReason::MemoryFault(self.pc, format!("LHU: {}", e)),
                    }
                    self.pc = self.pc.wrapping_add(4);
                }
                // Stores
                handlers::SB => {
                    let addr = rs1v.wrapping_add(imm);
                    let val = reg!(op.rs2 as usize);
                    if let Err(e) = self.memory.write_u8(addr, val as u8) {
                        return ExitReason::MemoryFault(self.pc, format!("SB: {}", e));
                    }
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::SH => {
                    let addr = rs1v.wrapping_add(imm);
                    let val = reg!(op.rs2 as usize);
                    if let Err(e) = self.memory.write_u16(addr, val as u16) {
                        return ExitReason::MemoryFault(self.pc, format!("SH: {}", e));
                    }
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::SW => {
                    let addr = rs1v.wrapping_add(imm);
                    let val = reg!(op.rs2 as usize);
                    if let Err(e) = self.memory.write_u32(addr, val) {
                        return ExitReason::MemoryFault(self.pc, format!("SW: {}", e));
                    }
                    self.pc = self.pc.wrapping_add(4);
                }
                // ALU immediate — each is a direct operation, no nested match
                handlers::ADDI => {
                    set_reg!(rd, rs1v.wrapping_add(imm));
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::SLTI => {
                    set_reg!(rd, if (rs1v as i32) < (imm as i32) { 1 } else { 0 });
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::SLTIU => {
                    set_reg!(rd, if rs1v < imm { 1 } else { 0 });
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::XORI => {
                    set_reg!(rd, rs1v ^ imm);
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::ORI => {
                    set_reg!(rd, rs1v | imm);
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::ANDI => {
                    set_reg!(rd, rs1v & imm);
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::SLLI => {
                    set_reg!(rd, rs1v << (imm & 0x1F));
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::SRLI => {
                    set_reg!(rd, rs1v >> (imm & 0x1F));
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::SRAI => {
                    set_reg!(rd, ((rs1v as i32) >> (imm & 0x1F)) as u32);
                    self.pc = self.pc.wrapping_add(4);
                }
                // ALU register — each fully inlined
                handlers::ADD => {
                    let rs2v = reg!(op.rs2 as usize);
                    set_reg!(rd, rs1v.wrapping_add(rs2v));
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::SUB => {
                    let rs2v = reg!(op.rs2 as usize);
                    set_reg!(rd, rs1v.wrapping_sub(rs2v));
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::SLL => {
                    let rs2v = reg!(op.rs2 as usize);
                    set_reg!(rd, rs1v << (rs2v & 0x1F));
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::SLT => {
                    let rs2v = reg!(op.rs2 as usize);
                    set_reg!(rd, if (rs1v as i32) < (rs2v as i32) { 1 } else { 0 });
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::SLTU => {
                    let rs2v = reg!(op.rs2 as usize);
                    set_reg!(rd, if rs1v < rs2v { 1 } else { 0 });
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::XOR => {
                    let rs2v = reg!(op.rs2 as usize);
                    set_reg!(rd, rs1v ^ rs2v);
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::SRL => {
                    let rs2v = reg!(op.rs2 as usize);
                    set_reg!(rd, rs1v >> (rs2v & 0x1F));
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::SRA => {
                    let rs2v = reg!(op.rs2 as usize);
                    set_reg!(rd, ((rs1v as i32) >> (rs2v & 0x1F)) as u32);
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::OR => {
                    let rs2v = reg!(op.rs2 as usize);
                    set_reg!(rd, rs1v | rs2v);
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::AND => {
                    let rs2v = reg!(op.rs2 as usize);
                    set_reg!(rd, rs1v & rs2v);
                    self.pc = self.pc.wrapping_add(4);
                }
                // M extension — inlined
                handlers::MUL => {
                    let rs2v = reg!(op.rs2 as usize);
                    set_reg!(rd, rs1v.wrapping_mul(rs2v));
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::MULH => {
                    let rs2v = reg!(op.rs2 as usize);
                    let result = (rs1v as i32 as i64).wrapping_mul(rs2v as i32 as i64);
                    set_reg!(rd, (result >> 32) as u32);
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::MULHSU => {
                    let rs2v = reg!(op.rs2 as usize);
                    let result = (rs1v as i32 as i64).wrapping_mul(rs2v as u64 as i64);
                    set_reg!(rd, (result >> 32) as u32);
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::MULHU => {
                    let rs2v = reg!(op.rs2 as usize);
                    let result = (rs1v as u64).wrapping_mul(rs2v as u64);
                    set_reg!(rd, (result >> 32) as u32);
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::DIV => {
                    let rs2v = reg!(op.rs2 as usize);
                    let result = if rs2v == 0 { u32::MAX }
                        else if rs1v as i32 == i32::MIN && rs2v as i32 == -1 { rs1v }
                        else { ((rs1v as i32).wrapping_div(rs2v as i32)) as u32 };
                    set_reg!(rd, result);
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::DIVU => {
                    let rs2v = reg!(op.rs2 as usize);
                    let result = if rs2v == 0 { u32::MAX } else { rs1v / rs2v };
                    set_reg!(rd, result);
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::REM => {
                    let rs2v = reg!(op.rs2 as usize);
                    let result = if rs2v == 0 { rs1v }
                        else if rs1v as i32 == i32::MIN && rs2v as i32 == -1 { 0 }
                        else { ((rs1v as i32).wrapping_rem(rs2v as i32)) as u32 };
                    set_reg!(rd, result);
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::REMU => {
                    let rs2v = reg!(op.rs2 as usize);
                    let result = if rs2v == 0 { rs1v } else { rs1v % rs2v };
                    set_reg!(rd, result);
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::FENCE => {
                    self.pc = self.pc.wrapping_add(4);
                }
                handlers::ECALL => {
                    sync_regs!();
                    match self.handle_ecall() {
                        Ok(None) => {
                            reload_regs!();
                            self.pc = self.pc.wrapping_add(4);
                        }
                        Ok(Some(reason)) => return reason,
                        Err(reason) => return reason,
                    }
                }
                handlers::EBREAK => {
                    sync_regs!();
                    return ExitReason::Ebreak;
                }
                handlers::CSR_NOP => {
                    self.pc = self.pc.wrapping_add(4);
                }
                // Phase 5: Superinstructions — fused pairs, one dispatch cycle
                handlers::SUPER_ADDI_ADDI => {
                    // Execute ADDI #1
                    set_reg!(rd, rs1v.wrapping_add(imm));
                    // Execute ADDI #2 (next instruction in cache)
                    if let Some(ref icache) = self.icache {
                        if let Some(op2) = icache.get(self.pc.wrapping_add(4)) {
                            let rs1v2 = reg!(op2.rs1 as usize);
                            set_reg!(op2.rd as usize, rs1v2.wrapping_add(op2.imm as u32));
                        }
                    }
                    self.instruction_count += 1;
                    self.pc = self.pc.wrapping_add(8);
                }
                handlers::SUPER_LW_LW => {
                    // LW #1
                    let addr1 = rs1v.wrapping_add(imm);
                    match self.memory.read_u32(addr1) {
                        Ok(w) => { set_reg!(rd, w); }
                        Err(e) => { sync_regs!(); return ExitReason::MemoryFault(self.pc, format!("LW: {}", e)); }
                    }
                    // LW #2
                    if let Some(ref icache) = self.icache {
                        if let Some(op2) = icache.get(self.pc.wrapping_add(4)) {
                            let rs1v2 = reg!(op2.rs1 as usize);
                            let addr2 = rs1v2.wrapping_add(op2.imm as u32);
                            match self.memory.read_u32(addr2) {
                                Ok(w) => { set_reg!(op2.rd as usize, w); }
                                Err(e) => { sync_regs!(); return ExitReason::MemoryFault(self.pc.wrapping_add(4), format!("LW: {}", e)); }
                            }
                        }
                    }
                    self.instruction_count += 1;
                    self.pc = self.pc.wrapping_add(8);
                }
                handlers::SUPER_LUI_ADDI => {
                    // LUI loads upper 20 bits into rd
                    set_reg!(rd, imm);
                    // ADDI adds lower 12 bits — must read the UPDATED rd from LUI
                    if let Some(ref icache) = self.icache {
                        if let Some(op2) = icache.get(self.pc.wrapping_add(4)) {
                            let rs1v2 = reg!(op2.rs1 as usize); // reads LUI's rd value
                            set_reg!(op2.rd as usize, rs1v2.wrapping_add(op2.imm as u32));
                        }
                    }
                    self.instruction_count += 1;
                    self.pc = self.pc.wrapping_add(8);
                }
                handlers::SUPER_SW_SW => {
                    // SW #1
                    let addr1 = rs1v.wrapping_add(imm);
                    let val1 = reg!(op.rs2 as usize);
                    if let Err(e) = self.memory.write_u32(addr1, val1) {
                        sync_regs!(); return ExitReason::MemoryFault(self.pc, format!("SW: {}", e));
                    }
                    // SW #2
                    if let Some(ref icache) = self.icache {
                        if let Some(op2) = icache.get(self.pc.wrapping_add(4)) {
                            let rs1v2 = reg!(op2.rs1 as usize);
                            let addr2 = rs1v2.wrapping_add(op2.imm as u32);
                            let val2 = reg!(op2.rs2 as usize);
                            if let Err(e) = self.memory.write_u32(addr2, val2) {
                                sync_regs!(); return ExitReason::MemoryFault(self.pc.wrapping_add(4), format!("SW: {}", e));
                            }
                        }
                    }
                    self.instruction_count += 1;
                    self.pc = self.pc.wrapping_add(8);
                }
                _ => {
                    sync_regs!();
                    return ExitReason::IllegalInstruction(self.pc, op.raw);
                }
            }

            self.regs[0] = 0;

            #[cfg(feature = "cranelift-jit-backend")]
            if jit_skip_pc.is_some() {
                jit_skip_pc = None;
            }
        }
    }

    pub fn run_collecting_checkpoints(
        &mut self,
        interval: u64,
    ) -> (ExitReason, Vec<CpuState>) {
        // Use the same main loop as run_with_checkpoints but collect checkpoints
        let mut checkpoints: Vec<CpuState> = Vec::new();
        let reason = self.run_with_checkpoints(&[], Some(interval), &mut checkpoints);
        // Final checkpoint at exit (Improvement D: guarantees ≥1 checkpoint even for
        // a run shorter than one interval).
        checkpoints.push(self.snapshot());
        (reason, checkpoints)
    }

    fn handle_ecall(&mut self) -> Result<Option<ExitReason>, ExitReason> {
        let syscall_num = self.regs[17]; // a7
        match syscall_num {
            syscall::READ_INPUTS => {
                let buf_ptr = self.regs[10];
                let buf_len = self.regs[11];
                let to_copy = core::cmp::min(buf_len as usize, self.input_buffer.len());
                let data: Vec<u8> = self.input_buffer[..to_copy].to_vec();
                self.memory.write_bytes(buf_ptr, &data)
                    .map_err(|e| ExitReason::MemoryFault(self.pc, format!("read_inputs: {}", e)))?;
                self.regs[10] = to_copy as u32;
                Ok(None)
            }
            syscall::WRITE_OUTPUTS => {
                let buf_ptr = self.regs[10];
                let buf_len = self.regs[11];
                let data = self.memory.read_bytes(buf_ptr, buf_len)
                    .map_err(|e| ExitReason::MemoryFault(self.pc, format!("write_outputs: {}", e)))?;
                self.output_buffer = data;
                self.output_written = true;
                self.regs[10] = 0;
                Ok(None)
            }
            syscall::HOST_CALL => {
                let func_id = self.regs[10] as u64;
                let in_ptr = self.regs[11];
                let in_len = self.regs[12];
                let out_ptr = self.regs[13];
                let input = self.memory.read_bytes(in_ptr, in_len)
                    .map_err(|e| ExitReason::MemoryFault(self.pc, format!("host_call input: {}", e)))?;
                match self.host.call(func_id, &input) {
                    Ok(output) => {
                        self.memory.write_bytes(out_ptr, &output)
                            .map_err(|e| ExitReason::MemoryFault(self.pc, format!("host_call output: {}", e)))?;
                        self.regs[10] = output.len() as u32;
                    }
                    Err(_) => { self.regs[10] = u32::MAX; }
                }
                Ok(None)
            }
            syscall::EXIT => {
                #[cfg(feature = "cranelift-jit-backend")]
                self.log_jit_stats();
                let exit_code = self.regs[10];
                Ok(Some(ExitReason::Exit(exit_code)))
            }
            _ => Err(ExitReason::UnknownSyscall(syscall_num)),
        }
    }
}
