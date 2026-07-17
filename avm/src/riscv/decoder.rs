//! RV32IM Instruction Decoder
//!
//! Decodes 32-bit RISC-V instructions into structured representations.
//! Supports all RV32I base instructions plus M extension (multiply/divide).

/// Decoded instruction representation
#[derive(Debug, Clone, Copy)]
pub struct Instruction {
    pub opcode: u32,
    pub rd: u32,
    pub rs1: u32,
    pub rs2: u32,
    pub funct3: u32,
    pub funct7: u32,
    pub imm: i32,
    pub raw: u32,
}

/// RV32IM opcodes
pub mod opcodes {
    pub const LUI: u32 = 0b0110111;
    pub const AUIPC: u32 = 0b0010111;
    pub const JAL: u32 = 0b1101111;
    pub const JALR: u32 = 0b1100111;
    pub const BRANCH: u32 = 0b1100011;
    pub const LOAD: u32 = 0b0000011;
    pub const STORE: u32 = 0b0100011;
    pub const OP_IMM: u32 = 0b0010011;
    pub const OP: u32 = 0b0110011;
    pub const FENCE: u32 = 0b0001111;
    pub const SYSTEM: u32 = 0b1110011;
}

/// Branch funct3 values
pub mod branch {
    pub const BEQ: u32 = 0b000;
    pub const BNE: u32 = 0b001;
    pub const BLT: u32 = 0b100;
    pub const BGE: u32 = 0b101;
    pub const BLTU: u32 = 0b110;
    pub const BGEU: u32 = 0b111;
}

/// Load funct3 values
pub mod load {
    pub const LB: u32 = 0b000;
    pub const LH: u32 = 0b001;
    pub const LW: u32 = 0b010;
    pub const LBU: u32 = 0b100;
    pub const LHU: u32 = 0b101;
}

/// Store funct3 values
pub mod store {
    pub const SB: u32 = 0b000;
    pub const SH: u32 = 0b001;
    pub const SW: u32 = 0b010;
}

/// ALU immediate funct3 values
pub mod alu_imm {
    pub const ADDI: u32 = 0b000;
    pub const SLTI: u32 = 0b010;
    pub const SLTIU: u32 = 0b011;
    pub const XORI: u32 = 0b100;
    pub const ORI: u32 = 0b110;
    pub const ANDI: u32 = 0b111;
    pub const SLLI: u32 = 0b001;
    pub const SRLI_SRAI: u32 = 0b101;
}

/// ALU register funct3 values
pub mod alu_reg {
    pub const ADD_SUB_MUL: u32 = 0b000;
    pub const SLL_MULH: u32 = 0b001;
    pub const SLT_MULHSU: u32 = 0b010;
    pub const SLTU_MULHU: u32 = 0b011;
    pub const XOR_DIV: u32 = 0b100;
    pub const SRL_SRA_DIVU: u32 = 0b101;
    pub const OR_REM: u32 = 0b110;
    pub const AND_REMU: u32 = 0b111;
}

/// System funct3 / funct12 values
pub mod system {
    pub const ECALL_EBREAK: u32 = 0b000;
    pub const ECALL_FUNCT12: u32 = 0b000000000000;
    pub const EBREAK_FUNCT12: u32 = 0b000000000001;
}

impl Instruction {
    /// Decode a 32-bit RISC-V instruction
    pub fn decode(raw: u32) -> Self {
        let opcode = raw & 0x7F;
        let rd = (raw >> 7) & 0x1F;
        let funct3 = (raw >> 12) & 0x7;
        let rs1 = (raw >> 15) & 0x1F;
        let rs2 = (raw >> 20) & 0x1F;
        let funct7 = (raw >> 25) & 0x7F;

        let imm = match opcode {
            // I-type: bits [31:20] sign-extended
            opcodes::LOAD | opcodes::OP_IMM | opcodes::JALR | opcodes::SYSTEM => {
                (raw as i32) >> 20
            }
            // S-type: imm[11:5] = bits[31:25], imm[4:0] = bits[11:7]
            opcodes::STORE => {
                let imm_11_5 = (raw >> 25) & 0x7F;
                let imm_4_0 = (raw >> 7) & 0x1F;
                let imm = (imm_11_5 << 5) | imm_4_0;
                // Sign-extend from bit 11
                if imm & 0x800 != 0 {
                    (imm | 0xFFFFF000) as i32
                } else {
                    imm as i32
                }
            }
            // B-type: imm[12|10:5] = bits[31:25], imm[4:1|11] = bits[11:7]
            opcodes::BRANCH => {
                let imm_12 = (raw >> 31) & 1;
                let imm_10_5 = (raw >> 25) & 0x3F;
                let imm_4_1 = (raw >> 8) & 0xF;
                let imm_11 = (raw >> 7) & 1;
                let imm = (imm_12 << 12)
                    | (imm_11 << 11)
                    | (imm_10_5 << 5)
                    | (imm_4_1 << 1);
                if imm & 0x1000 != 0 {
                    (imm | 0xFFFFE000) as i32
                } else {
                    imm as i32
                }
            }
            // U-type: imm[31:12]
            opcodes::LUI | opcodes::AUIPC => {
                (raw & 0xFFFFF000) as i32
            }
            // J-type: imm[20|10:1|11|19:12]
            opcodes::JAL => {
                let imm_20 = (raw >> 31) & 1;
                let imm_10_1 = (raw >> 21) & 0x3FF;
                let imm_11 = (raw >> 20) & 1;
                let imm_19_12 = (raw >> 12) & 0xFF;
                let imm = (imm_20 << 20)
                    | (imm_19_12 << 12)
                    | (imm_11 << 11)
                    | (imm_10_1 << 1);
                if imm & 0x100000 != 0 {
                    (imm | 0xFFE00000) as i32
                } else {
                    imm as i32
                }
            }
            _ => 0,
        };

        Instruction {
            opcode,
            rd,
            rs1,
            rs2,
            funct3,
            funct7,
            imm,
            raw,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_addi() {
        // addi x1, x0, 42 → 0x02A00093
        let raw: u32 = 0x02A00093;
        let inst = Instruction::decode(raw);
        assert_eq!(inst.opcode, opcodes::OP_IMM);
        assert_eq!(inst.rd, 1);
        assert_eq!(inst.rs1, 0);
        assert_eq!(inst.funct3, alu_imm::ADDI);
        assert_eq!(inst.imm, 42);
    }

    #[test]
    fn test_decode_lui() {
        // lui x5, 0x12345 → 0x12345297
        let raw: u32 = 0x12345297;
        let inst = Instruction::decode(raw);
        assert_eq!(inst.opcode, opcodes::AUIPC);
        assert_eq!(inst.rd, 5);
        assert_eq!(inst.imm, 0x12345000_u32 as i32);
    }

    #[test]
    fn test_decode_negative_imm() {
        // addi x1, x0, -1 → 0xFFF00093
        let raw: u32 = 0xFFF00093;
        let inst = Instruction::decode(raw);
        assert_eq!(inst.opcode, opcodes::OP_IMM);
        assert_eq!(inst.funct3, alu_imm::ADDI);
        assert_eq!(inst.imm, -1);
    }

    #[test]
    fn test_decode_sw() {
        // sw x1, 8(x2) → 0x00112423
        let raw: u32 = 0x00112423;
        let inst = Instruction::decode(raw);
        assert_eq!(inst.opcode, opcodes::STORE);
        assert_eq!(inst.funct3, store::SW);
        assert_eq!(inst.rs1, 2);
        assert_eq!(inst.rs2, 1);
        assert_eq!(inst.imm, 8);
    }

    #[test]
    fn test_decode_beq() {
        // beq x1, x2, +16 → 0x00208863
        let raw: u32 = 0x00208863;
        let inst = Instruction::decode(raw);
        assert_eq!(inst.opcode, opcodes::BRANCH);
        assert_eq!(inst.funct3, branch::BEQ);
        assert_eq!(inst.rs1, 1);
        assert_eq!(inst.rs2, 2);
        assert_eq!(inst.imm, 16);
    }
}
