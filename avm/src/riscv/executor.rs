//! RV32IM CPU Executor
//!
//! Implements the RISC-V RV32IM instruction set: 32-bit base integer
//! plus multiply/divide extension. ~50 instructions total.
//!
//! The executor is deterministic: same initial state + same memory
//! always produces the same final state on any platform.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use super::decoder::{Instruction, opcodes, branch, load, store, alu_imm, alu_reg, system};
use super::memory::GuestMemory;
use crate::host_functions::HostFunctions;

/// Syscall numbers for AVM guest I/O (ecall convention)
pub mod syscall {
    /// Read PublicInputs from host into guest memory
    /// a0 = buffer pointer, a1 = buffer length → a0 = bytes read
    pub const READ_INPUTS: u32 = 0x01;
    /// Write PublicOutputs from guest memory to host
    /// a0 = buffer pointer, a1 = buffer length → a0 = 0 on success
    pub const WRITE_OUTPUTS: u32 = 0x02;
    /// Call a host function (crypto, time, etc.)
    /// a0 = function_id, a1 = input pointer, a2 = input length, a3 = output pointer → a0 = output length
    pub const HOST_CALL: u32 = 0x10;
    /// Exit guest execution
    /// a0 = exit code (0 = success)
    pub const EXIT: u32 = 0x5D;
}

/// Maximum instructions before forced halt (prevent infinite loops).
/// CBOR deserialization of full PublicInputs with post-quantum VBC bundles
/// (SPHINCS+ 7856B sigs, Dilithium 1952B PKs) dominates instruction count.
/// Core validation itself uses ~10-30M; the rest is serde overhead.
/// CL5 redeem with k=3 cheques: ~600-800M (deserialization alone).
/// CL5 redeem with k=5 cheques + 6-link FACT chains: ~1.5-2.5B.
/// AUDIT-FIX v2.11.13: Increased from 500M — CL5 k=3 was hitting limit.
/// AUDIT-FIX v2.11.16: Increased from 1B — CL5 k=5 with deep FACT chains
/// exceeded 1B (wallets 042/062 in 72h soak). 4B provides headroom.
pub const MAX_INSTRUCTIONS: u64 = 4_000_000_000; // 4B

/// CPU state
pub struct Cpu {
    /// 32 general-purpose registers (x0 is always 0)
    pub regs: [u32; 32],
    /// Program counter
    pub pc: u32,
    /// Guest memory
    pub memory: GuestMemory,
    /// Instruction count (for DMAP checkpoints)
    pub instruction_count: u64,
    /// Host functions (ecall handler)
    host: HostFunctions,
    /// Input buffer (serialized PublicInputs, provided by host)
    input_buffer: Vec<u8>,
    /// Output buffer (serialized PublicOutputs, written by guest)
    output_buffer: Vec<u8>,
    /// Whether the guest has written outputs
    output_written: bool,
}

/// Exit reason when CPU stops
#[derive(Debug)]
pub enum ExitReason {
    /// Guest called exit syscall with code
    Exit(u32),
    /// Hit instruction limit
    InstructionLimit,
    /// EBREAK instruction
    Ebreak,
    /// Illegal instruction
    IllegalInstruction(u32, u32), // (pc, raw_instruction)
    /// Memory fault
    MemoryFault(u32, String), // (pc, description)
    /// Unknown syscall
    UnknownSyscall(u32), // syscall number
}

/// CPU state snapshot for DMAP checkpoints
#[derive(Debug, Clone)]
pub struct CpuState {
    pub pc: u32,
    pub instruction_count: u64,
    pub memory_root: [u8; 32],
    /// BLAKE3 hash of all 32 RISC-V registers (Improvement A: register-level divergence detection)
    pub register_hash: [u8; 32],
}

/// KI#39 reservoir decimation. When the collected checkpoint set reaches
/// [`crate::dmap::MAX_COLLECTED_CHECKPOINTS`], keep every other entry (a uniform
/// 2× down-sample that still spans the whole run) and return the doubled
/// interval. Both executors call this so a huge run coarsens its checkpoint
/// spacing instead of collecting — and re-hashing memory — unboundedly.
/// Transparent to detection: reveals sample K from the committed set and the
/// verifier re-executes to each revealed checkpoint's exact instruction_count.
#[inline]
pub(crate) fn decimate_reservoir(checkpoints: &mut Vec<CpuState>, interval: u64) -> u64 {
    let mut keep = false;
    checkpoints.retain(|_| {
        keep = !keep;
        keep
    });
    interval.saturating_mul(2)
}

impl Cpu {
    /// Create a new CPU with the given host functions and input data
    pub fn new(host: HostFunctions, input_data: Vec<u8>) -> Self {
        Cpu {
            regs: [0u32; 32],
            pc: 0,
            memory: GuestMemory::new(),
            instruction_count: 0,
            host,
            input_buffer: input_data,
            output_buffer: Vec::new(),
            output_written: false,
        }
    }

    /// Set the program counter (typically to ELF entry point)
    pub fn set_pc(&mut self, pc: u32) {
        self.pc = pc;
    }

    /// Set the stack pointer (register x2/sp)
    pub fn set_sp(&mut self, sp: u32) {
        self.regs[2] = sp;
    }

    /// Get the output buffer (after guest writes outputs)
    pub fn output(&self) -> &[u8] {
        &self.output_buffer
    }

    /// Whether the guest has written output
    pub fn has_output(&self) -> bool {
        self.output_written
    }

    /// Take a DMAP state snapshot (includes register hash for divergence detection)
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

    /// Run until exit or instruction limit
    pub fn run(&mut self) -> ExitReason {
        self.run_with_checkpoints(&[], None)
    }

    /// Run with optional DMAP checkpoint collection
    ///
    /// If `checkpoint_interval` is Some(N), collects a CpuState snapshot
    /// every N instructions and pushes it to `checkpoints_out`.
    ///
    /// If `specific_indices` is non-empty, only collects at those
    /// instruction-count checkpoints (for verification re-execution).
    pub fn run_with_checkpoints(
        &mut self,
        specific_indices: &[u64],
        checkpoint_interval: Option<u64>,
    ) -> ExitReason {
        let mut checkpoints: Vec<CpuState> = Vec::new();
        let _next_checkpoint = checkpoint_interval.unwrap_or(u64::MAX);
        let mut specific_set: Vec<u64> = specific_indices.to_vec();
        specific_set.sort();

        loop {
            if self.instruction_count >= MAX_INSTRUCTIONS {
                return ExitReason::InstructionLimit;
            }

            // Check if we need a checkpoint
            if let Some(interval) = checkpoint_interval {
                if self.instruction_count > 0 && self.instruction_count.is_multiple_of(interval) {
                    checkpoints.push(self.snapshot());
                    self.memory.clear_dirty();
                }
            }

            // Execute one instruction
            match self.step() {
                Ok(None) => continue,
                Ok(Some(reason)) => return reason,
                Err(reason) => return reason,
            }
        }
    }

    /// Collect all checkpoints from execution with given interval
    pub fn run_collecting_checkpoints(
        &mut self,
        interval: u64,
    ) -> (ExitReason, Vec<CpuState>) {
        let mut checkpoints: Vec<CpuState> = Vec::new();
        // Bounded collection mirroring FastCpu (KI#39): threshold-based (not
        // is_multiple_of) so the interval can double cleanly once the collected
        // set hits crate::dmap::MAX_COLLECTED_CHECKPOINTS.
        let mut cur_interval = interval.max(1);
        let mut next_checkpoint_at = cur_interval;

        loop {
            if self.instruction_count >= MAX_INSTRUCTIONS {
                // Final checkpoint at execution end (Improvement D)
                checkpoints.push(self.snapshot());
                return (ExitReason::InstructionLimit, checkpoints);
            }

            // Collect checkpoint at the (doubling) interval, capped set size.
            if self.instruction_count >= next_checkpoint_at {
                checkpoints.push(self.snapshot());
                self.memory.clear_dirty();
                if checkpoints.len() >= crate::dmap::MAX_COLLECTED_CHECKPOINTS {
                    cur_interval = decimate_reservoir(&mut checkpoints, cur_interval);
                }
                next_checkpoint_at += cur_interval;
                if next_checkpoint_at <= self.instruction_count {
                    next_checkpoint_at = (self.instruction_count / cur_interval + 1) * cur_interval;
                }
            }

            match self.step() {
                Ok(None) => continue,
                Ok(Some(reason)) => {
                    // Final checkpoint at program exit (Improvement D: guarantees D ≥ 1)
                    checkpoints.push(self.snapshot());
                    return (reason, checkpoints);
                }
                Err(reason) => {
                    checkpoints.push(self.snapshot());
                    return (reason, checkpoints);
                }
            }
        }
    }

    /// Execute a single instruction. Returns:
    /// - Ok(None) — continue execution
    /// - Ok(Some(reason)) — clean exit
    /// - Err(reason) — error exit
    fn step(&mut self) -> Result<Option<ExitReason>, ExitReason> {
        let raw = self.memory.read_u32(self.pc)
            .map_err(|e| ExitReason::MemoryFault(self.pc, format!("Fetch: {}", e)))?;

        let inst = Instruction::decode(raw);
        self.instruction_count += 1;

        match inst.opcode {
            opcodes::LUI => {
                self.set_rd(inst.rd, inst.imm as u32);
                self.pc = self.pc.wrapping_add(4);
            }
            opcodes::AUIPC => {
                self.set_rd(inst.rd, self.pc.wrapping_add(inst.imm as u32));
                self.pc = self.pc.wrapping_add(4);
            }
            opcodes::JAL => {
                self.set_rd(inst.rd, self.pc.wrapping_add(4));
                self.pc = self.pc.wrapping_add(inst.imm as u32);
            }
            opcodes::JALR => {
                let target = (self.reg(inst.rs1).wrapping_add(inst.imm as u32)) & !1;
                self.set_rd(inst.rd, self.pc.wrapping_add(4));
                self.pc = target;
            }
            opcodes::BRANCH => {
                let rs1 = self.reg(inst.rs1);
                let rs2 = self.reg(inst.rs2);
                let taken = match inst.funct3 {
                    branch::BEQ => rs1 == rs2,
                    branch::BNE => rs1 != rs2,
                    branch::BLT => (rs1 as i32) < (rs2 as i32),
                    branch::BGE => (rs1 as i32) >= (rs2 as i32),
                    branch::BLTU => rs1 < rs2,
                    branch::BGEU => rs1 >= rs2,
                    _ => return Err(ExitReason::IllegalInstruction(self.pc, raw)),
                };
                if taken {
                    self.pc = self.pc.wrapping_add(inst.imm as u32);
                } else {
                    self.pc = self.pc.wrapping_add(4);
                }
            }
            opcodes::LOAD => {
                let addr = self.reg(inst.rs1).wrapping_add(inst.imm as u32);
                let val = match inst.funct3 {
                    load::LB => {
                        let b = self.mem_read_u8(addr)?;
                        (b as i8) as i32 as u32 // sign-extend
                    }
                    load::LH => {
                        let h = self.mem_read_u16(addr)?;
                        (h as i16) as i32 as u32 // sign-extend
                    }
                    load::LW => self.mem_read_u32(addr)?,
                    load::LBU => self.mem_read_u8(addr)? as u32,
                    load::LHU => self.mem_read_u16(addr)? as u32,
                    _ => return Err(ExitReason::IllegalInstruction(self.pc, raw)),
                };
                self.set_rd(inst.rd, val);
                self.pc = self.pc.wrapping_add(4);
            }
            opcodes::STORE => {
                let addr = self.reg(inst.rs1).wrapping_add(inst.imm as u32);
                let val = self.reg(inst.rs2);
                match inst.funct3 {
                    store::SB => self.mem_write_u8(addr, val as u8)?,
                    store::SH => self.mem_write_u16(addr, val as u16)?,
                    store::SW => self.mem_write_u32(addr, val)?,
                    _ => return Err(ExitReason::IllegalInstruction(self.pc, raw)),
                }
                self.pc = self.pc.wrapping_add(4);
            }
            opcodes::OP_IMM => {
                let rs1 = self.reg(inst.rs1);
                let imm = inst.imm as u32;
                let result = match inst.funct3 {
                    alu_imm::ADDI => rs1.wrapping_add(imm),
                    alu_imm::SLTI => if (rs1 as i32) < (imm as i32) { 1 } else { 0 },
                    alu_imm::SLTIU => if rs1 < imm { 1 } else { 0 },
                    alu_imm::XORI => rs1 ^ imm,
                    alu_imm::ORI => rs1 | imm,
                    alu_imm::ANDI => rs1 & imm,
                    alu_imm::SLLI => rs1 << (imm & 0x1F),
                    alu_imm::SRLI_SRAI => {
                        let shamt = imm & 0x1F;
                        if inst.funct7 & 0x20 != 0 {
                            // SRAI — arithmetic right shift
                            ((rs1 as i32) >> shamt) as u32
                        } else {
                            // SRLI — logical right shift
                            rs1 >> shamt
                        }
                    }
                    _ => return Err(ExitReason::IllegalInstruction(self.pc, raw)),
                };
                self.set_rd(inst.rd, result);
                self.pc = self.pc.wrapping_add(4);
            }
            opcodes::OP => {
                let rs1 = self.reg(inst.rs1);
                let rs2 = self.reg(inst.rs2);

                let result = if inst.funct7 == 0x01 {
                    // M extension (multiply/divide)
                    self.execute_m_extension(inst.funct3, rs1, rs2)?
                } else {
                    // Base integer
                    match inst.funct3 {
                        alu_reg::ADD_SUB_MUL => {
                            if inst.funct7 == 0x20 {
                                rs1.wrapping_sub(rs2) // SUB
                            } else {
                                rs1.wrapping_add(rs2) // ADD
                            }
                        }
                        alu_reg::SLL_MULH => rs1 << (rs2 & 0x1F),
                        alu_reg::SLT_MULHSU => {
                            if (rs1 as i32) < (rs2 as i32) { 1 } else { 0 }
                        }
                        alu_reg::SLTU_MULHU => {
                            if rs1 < rs2 { 1 } else { 0 }
                        }
                        alu_reg::XOR_DIV => rs1 ^ rs2,
                        alu_reg::SRL_SRA_DIVU => {
                            let shamt = rs2 & 0x1F;
                            if inst.funct7 == 0x20 {
                                ((rs1 as i32) >> shamt) as u32 // SRA
                            } else {
                                rs1 >> shamt // SRL
                            }
                        }
                        alu_reg::OR_REM => rs1 | rs2,
                        alu_reg::AND_REMU => rs1 & rs2,
                        _ => return Err(ExitReason::IllegalInstruction(self.pc, raw)),
                    }
                };
                self.set_rd(inst.rd, result);
                self.pc = self.pc.wrapping_add(4);
            }
            opcodes::FENCE => {
                // FENCE is a NOP for single-threaded deterministic execution
                self.pc = self.pc.wrapping_add(4);
            }
            opcodes::SYSTEM => {
                match inst.funct3 {
                    system::ECALL_EBREAK => {
                        let funct12 = (raw >> 20) & 0xFFF;
                        if funct12 == system::EBREAK_FUNCT12 {
                            return Ok(Some(ExitReason::Ebreak));
                        }
                        // ECALL — handle syscall
                        if let Some(reason) = self.handle_ecall()? {
                            return Ok(Some(reason));
                        }
                        self.pc = self.pc.wrapping_add(4);
                    }
                    _ => {
                        // CSR instructions — treat as NOP for now
                        // (Core doesn't use CSRs)
                        self.pc = self.pc.wrapping_add(4);
                    }
                }
            }
            _ => return Err(ExitReason::IllegalInstruction(self.pc, raw)),
        }

        // x0 is always 0
        self.regs[0] = 0;

        Ok(None)
    }

    /// Execute M extension instructions (multiply/divide)
    fn execute_m_extension(&self, funct3: u32, rs1: u32, rs2: u32) -> Result<u32, ExitReason> {
        Ok(match funct3 {
            0b000 => {
                // MUL — lower 32 bits of rs1 × rs2
                rs1.wrapping_mul(rs2)
            }
            0b001 => {
                // MULH — upper 32 bits of signed × signed
                let result = (rs1 as i32 as i64).wrapping_mul(rs2 as i32 as i64);
                (result >> 32) as u32
            }
            0b010 => {
                // MULHSU — upper 32 bits of signed × unsigned
                let result = (rs1 as i32 as i64).wrapping_mul(rs2 as u64 as i64);
                (result >> 32) as u32
            }
            0b011 => {
                // MULHU — upper 32 bits of unsigned × unsigned
                let result = (rs1 as u64).wrapping_mul(rs2 as u64);
                (result >> 32) as u32
            }
            0b100 => {
                // DIV — signed division
                if rs2 == 0 {
                    u32::MAX // Division by zero → -1
                } else if rs1 as i32 == i32::MIN && rs2 as i32 == -1 {
                    rs1 // Overflow → dividend
                } else {
                    ((rs1 as i32).wrapping_div(rs2 as i32)) as u32
                }
            }
            0b101 => {
                // DIVU — unsigned division
                if rs2 == 0 {
                    u32::MAX // Division by zero → all 1s
                } else {
                    rs1 / rs2
                }
            }
            0b110 => {
                // REM — signed remainder
                if rs2 == 0 {
                    rs1 // Division by zero → dividend
                } else if rs1 as i32 == i32::MIN && rs2 as i32 == -1 {
                    0 // Overflow → 0
                } else {
                    ((rs1 as i32).wrapping_rem(rs2 as i32)) as u32
                }
            }
            0b111 => {
                // REMU — unsigned remainder
                if rs2 == 0 {
                    rs1 // Division by zero → dividend
                } else {
                    rs1 % rs2
                }
            }
            _ => unreachable!(),
        })
    }

    /// Handle an ECALL (syscall)
    fn handle_ecall(&mut self) -> Result<Option<ExitReason>, ExitReason> {
        let syscall_num = self.regs[17]; // a7

        match syscall_num {
            syscall::READ_INPUTS => {
                let buf_ptr = self.regs[10]; // a0
                let buf_len = self.regs[11]; // a1
                let to_copy = core::cmp::min(buf_len as usize, self.input_buffer.len());
                let data: Vec<u8> = self.input_buffer[..to_copy].to_vec();
                self.memory.write_bytes(buf_ptr, &data)
                    .map_err(|e| ExitReason::MemoryFault(self.pc, format!("read_inputs: {}", e)))?;
                self.regs[10] = to_copy as u32; // return bytes read
                Ok(None)
            }
            syscall::WRITE_OUTPUTS => {
                let buf_ptr = self.regs[10]; // a0
                let buf_len = self.regs[11]; // a1
                let data = self.memory.read_bytes(buf_ptr, buf_len)
                    .map_err(|e| ExitReason::MemoryFault(self.pc, format!("write_outputs: {}", e)))?;
                self.output_buffer = data;
                self.output_written = true;
                self.regs[10] = 0; // success
                Ok(None)
            }
            syscall::HOST_CALL => {
                let func_id = self.regs[10] as u64; // a0
                let in_ptr = self.regs[11]; // a1
                let in_len = self.regs[12]; // a2
                let out_ptr = self.regs[13]; // a3

                // Read input data from guest memory
                let input = self.memory.read_bytes(in_ptr, in_len)
                    .map_err(|e| ExitReason::MemoryFault(self.pc, format!("host_call input: {}", e)))?;

                // Call host function
                match self.host.call(func_id, &input) {
                    Ok(output) => {
                        // Write output to guest memory
                        self.memory.write_bytes(out_ptr, &output)
                            .map_err(|e| ExitReason::MemoryFault(self.pc, format!("host_call output: {}", e)))?;
                        self.regs[10] = output.len() as u32; // return output length
                    }
                    Err(_e) => {
                        // Host function error — set return value to max
                        self.regs[10] = u32::MAX;
                    }
                }
                Ok(None)
            }
            syscall::EXIT => {
                let exit_code = self.regs[10]; // a0
                Ok(Some(ExitReason::Exit(exit_code)))
            }
            _ => Err(ExitReason::UnknownSyscall(syscall_num)),
        }
    }

    /// Read register value (x0 always returns 0)
    #[inline]
    fn reg(&self, idx: u32) -> u32 {
        if idx == 0 { 0 } else { self.regs[idx as usize] }
    }

    /// Set register value (writes to x0 are discarded)
    #[inline]
    fn set_rd(&mut self, rd: u32, val: u32) {
        if rd != 0 {
            self.regs[rd as usize] = val;
        }
    }

    // Memory access wrappers that convert errors
    fn mem_read_u8(&self, addr: u32) -> Result<u8, ExitReason> {
        self.memory.read_u8(addr)
            .map_err(|e| ExitReason::MemoryFault(self.pc, format!("load: {}", e)))
    }
    fn mem_read_u16(&self, addr: u32) -> Result<u16, ExitReason> {
        self.memory.read_u16(addr)
            .map_err(|e| ExitReason::MemoryFault(self.pc, format!("load: {}", e)))
    }
    fn mem_read_u32(&self, addr: u32) -> Result<u32, ExitReason> {
        self.memory.read_u32(addr)
            .map_err(|e| ExitReason::MemoryFault(self.pc, format!("load: {}", e)))
    }
    fn mem_write_u8(&mut self, addr: u32, val: u8) -> Result<(), ExitReason> {
        self.memory.write_u8(addr, val)
            .map_err(|e| ExitReason::MemoryFault(self.pc, format!("store: {}", e)))
    }
    fn mem_write_u16(&mut self, addr: u32, val: u16) -> Result<(), ExitReason> {
        self.memory.write_u16(addr, val)
            .map_err(|e| ExitReason::MemoryFault(self.pc, format!("store: {}", e)))
    }
    fn mem_write_u32(&mut self, addr: u32, val: u32) -> Result<(), ExitReason> {
        self.memory.write_u32(addr, val)
            .map_err(|e| ExitReason::MemoryFault(self.pc, format!("store: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_functions::HostFunctions;

    /// KI#39: the interior-checkpoint collector must stay bounded even on a
    /// CL5-redeem-scale run (~600M+ instructions), or per-checkpoint memory_root
    /// cost collapses AVM throughput and redeems blow the SDK poll window. This
    /// drives the exact cap+decimate logic the executors use over a huge run and
    /// asserts the reservoir never exceeds MAX_COLLECTED_CHECKPOINTS while still
    /// keeping a uniform sample (monotonic instruction_counts spanning the run,
    /// enough to reveal K).
    #[test]
    fn test_checkpoint_reservoir_stays_bounded_on_huge_run() {
        let cap = crate::dmap::MAX_COLLECTED_CHECKPOINTS;
        let mut cps: Vec<CpuState> = Vec::new();
        let mut cur_interval = crate::dmap::DMAP_CHECKPOINT_INTERVAL;
        let mut next_checkpoint_at = cur_interval;
        let run_len: u64 = 700_000_000; // CL5-redeem scale
        let step: u64 = 137; // arbitrary block-jump granularity (not a multiple of interval)
        let mut ic: u64 = 0;
        while ic < run_len {
            ic += step;
            if ic >= next_checkpoint_at {
                cps.push(CpuState {
                    pc: 0,
                    instruction_count: ic,
                    memory_root: [0u8; 32],
                    register_hash: [0u8; 32],
                });
                if cps.len() >= cap {
                    cur_interval = decimate_reservoir(&mut cps, cur_interval);
                }
                next_checkpoint_at += cur_interval;
                if next_checkpoint_at <= ic {
                    next_checkpoint_at = (ic / cur_interval + 1) * cur_interval;
                }
            }
        }
        assert!(cps.len() <= cap,
            "reservoir exceeded cap: {} > {}", cps.len(), cap);
        assert!(cps.len() as u64 > crate::dmap::DMAP_NUM_CHALLENGES,
            "too few checkpoints to reveal K={}: got {}", crate::dmap::DMAP_NUM_CHALLENGES, cps.len());
        // Uniform sample: instruction_counts strictly increasing.
        for w in cps.windows(2) {
            assert!(w[1].instruction_count > w[0].instruction_count,
                "checkpoints must be strictly increasing");
        }
        // Sample spans the run: the last checkpoint is within one (coarsened)
        // interval of the end.
        assert!(cps.last().unwrap().instruction_count > run_len - cur_interval,
            "reservoir must span to the end of the run");
    }

    fn make_cpu() -> Cpu {
        let host = HostFunctions::new(0, [0u8; 32]);
        Cpu::new(host, Vec::new())
    }

    /// Helper: write instructions to memory and run from given PC
    fn run_instructions(cpu: &mut Cpu, addr: u32, instructions: &[u32]) -> ExitReason {
        for (i, &inst) in instructions.iter().enumerate() {
            cpu.memory.write_u32(addr + (i as u32) * 4, inst).unwrap();
        }
        cpu.set_pc(addr);
        cpu.run()
    }

    #[test]
    fn test_addi() {
        let mut cpu = make_cpu();
        // addi x1, x0, 42 → 0x02A00093
        // exit syscall: addi a7, x0, 93; ecall
        let code = [
            0x02A00093u32, // addi x1, x0, 42
            0x05D00893,    // addi a7, x0, 93 (EXIT syscall)
            0x00000073,    // ecall
        ];
        let reason = run_instructions(&mut cpu, 0x1000, &code);
        assert_eq!(cpu.regs[1], 42);
        assert!(matches!(reason, ExitReason::Exit(0)));
    }

    #[test]
    fn test_add_sub() {
        let mut cpu = make_cpu();
        let code = [
            0x00A00093u32, // addi x1, x0, 10
            0x01400113,    // addi x2, x0, 20
            0x002081B3,    // add x3, x1, x2  → 30
            0x40208233,    // sub x4, x1, x2  → -10 (0xFFFFFFF6)
            0x05D00893,    // addi a7, x0, 93
            0x00000073,    // ecall
        ];
        let _reason = run_instructions(&mut cpu, 0x1000, &code);
        assert_eq!(cpu.regs[3], 30);
        assert_eq!(cpu.regs[4], 0xFFFFFFF6); // -10 as u32
    }

    #[test]
    fn test_lui_auipc() {
        let mut cpu = make_cpu();
        let code = [
            0x123450B7u32, // lui x1, 0x12345
            0x00000117,    // auipc x2, 0 → x2 = PC (0x1004)
            0x05D00893,    // addi a7, x0, 93
            0x00000073,    // ecall
        ];
        let _reason = run_instructions(&mut cpu, 0x1000, &code);
        assert_eq!(cpu.regs[1], 0x12345000);
        assert_eq!(cpu.regs[2], 0x1004); // PC at auipc
    }

    #[test]
    fn test_store_load() {
        let mut cpu = make_cpu();
        let code = [
            0x0FF00093u32, // addi x1, x0, 255
            0x00102023,    // sw x1, 0(x0) → store 255 at addr 0
            0x00002103,    // lw x2, 0(x0) → load from addr 0
            0x05D00893,    // addi a7, x0, 93
            0x00000073,    // ecall
        ];
        // Write code at 0x1000 to avoid overwriting addr 0
        let _reason = run_instructions(&mut cpu, 0x1000, &code);
        assert_eq!(cpu.regs[2], 255);
    }

    #[test]
    fn test_branch_taken() {
        let mut cpu = make_cpu();
        let code = [
            0x00A00093u32, // addi x1, x0, 10
            0x00A00113,    // addi x2, x0, 10
            0x00208463,    // beq x1, x2, +8  → skip next instruction
            0x06400093,    // addi x1, x0, 100 (should be skipped)
            0x05D00893,    // addi a7, x0, 93
            0x00000073,    // ecall
        ];
        let _reason = run_instructions(&mut cpu, 0x1000, &code);
        assert_eq!(cpu.regs[1], 10); // Not overwritten to 100
    }

    #[test]
    fn test_jal() {
        let mut cpu = make_cpu();
        let code = [
            0x008000EF, // jal x1, +8 → jump to PC+8, save return in x1
            0x00000013, // nop (skipped)
            0x05D00893, // addi a7, x0, 93
            0x00000073, // ecall
        ];
        let _reason = run_instructions(&mut cpu, 0x1000, &code);
        assert_eq!(cpu.regs[1], 0x1004); // Return address
    }

    #[test]
    fn test_mul() {
        let mut cpu = make_cpu();
        let code = [
            0x00700093u32, // addi x1, x0, 7
            0x00600113,    // addi x2, x0, 6
            0x022081B3,    // mul x3, x1, x2 → 42
            0x05D00893,    // addi a7, x0, 93
            0x00000073,    // ecall
        ];
        let _reason = run_instructions(&mut cpu, 0x1000, &code);
        assert_eq!(cpu.regs[3], 42);
    }

    #[test]
    fn test_div_by_zero() {
        let mut cpu = make_cpu();
        let code = [
            0x00A00093u32, // addi x1, x0, 10
            0x00000113,    // addi x2, x0, 0
            0x022041B3,    // div x3, x1, x2 → -1 (div by zero)
            0x022051B3,    // divu x3, x1, x2 → 0xFFFFFFFF (div by zero)
            0x05D00893,    // addi a7, x0, 93
            0x00000073,    // ecall
        ];
        let _reason = run_instructions(&mut cpu, 0x1000, &code);
        assert_eq!(cpu.regs[3], u32::MAX);
    }

    #[test]
    fn test_x0_always_zero() {
        let mut cpu = make_cpu();
        let code = [
            0x02A00013u32, // addi x0, x0, 42 → write to x0 (discarded)
            0x05D00893,    // addi a7, x0, 93
            0x00000073,    // ecall
        ];
        let _reason = run_instructions(&mut cpu, 0x1000, &code);
        assert_eq!(cpu.regs[0], 0); // x0 is still 0
    }

    #[test]
    fn test_checkpoint_collection() {
        let mut cpu = make_cpu();
        // 10 nops then exit
        let mut code = Vec::new();
        for _ in 0..10 {
            code.push(0x00000013u32); // nop
        }
        code.push(0x05D00893); // addi a7, x0, 93
        code.push(0x00000073); // ecall
        for (i, &inst) in code.iter().enumerate() {
            cpu.memory.write_u32(0x1000 + (i as u32) * 4, inst).unwrap();
        }
        cpu.set_pc(0x1000);

        let (reason, checkpoints) = cpu.run_collecting_checkpoints(5);
        assert!(matches!(reason, ExitReason::Exit(0)));
        // 12 instructions total, checkpoints at 5, 10, and final exit (Improvement D)
        assert_eq!(checkpoints.len(), 3);
        assert_eq!(checkpoints[0].instruction_count, 5);
        assert_eq!(checkpoints[1].instruction_count, 10);
        assert_eq!(checkpoints[2].instruction_count, 12); // final checkpoint
        // All checkpoints include register_hash
        assert_ne!(checkpoints[0].register_hash, [0u8; 32]);
    }
}
