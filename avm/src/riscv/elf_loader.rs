//! Minimal ELF Loader for RISC-V Binaries
//!
//! Parses ELF32 headers and loads PT_LOAD segments into guest memory.
//! Extracts the entry point for the CPU to start execution.
//!
//! No external dependencies — ELF is a stable, well-documented format.
//! This ensures 100-year portability (YP §31).

use super::memory::GuestMemory;

/// ELF magic number
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// ELF class: 32-bit
const ELFCLASS32: u8 = 1;

/// ELF data encoding: little-endian
const ELFDATA2LSB: u8 = 1;

/// ELF machine type: RISC-V
const EM_RISCV: u16 = 243;

/// Program header type: loadable segment
const PT_LOAD: u32 = 1;

/// Result of loading an ELF
pub struct ElfInfo {
    /// Entry point address (where PC starts)
    pub entry_point: u32,
    /// Total bytes loaded into memory
    pub loaded_bytes: usize,
    /// Number of segments loaded
    pub num_segments: usize,
}

/// Load a RISC-V ELF32 binary into guest memory
///
/// Returns the entry point address and load statistics.
pub fn load_elf(elf_bytes: &[u8], memory: &mut GuestMemory) -> Result<ElfInfo, ElfError> {
    // Minimum ELF header size
    if elf_bytes.len() < 52 {
        return Err(ElfError::TooSmall);
    }

    // Verify magic
    if elf_bytes[0..4] != ELF_MAGIC {
        return Err(ElfError::BadMagic);
    }

    // Verify class (32-bit)
    if elf_bytes[4] != ELFCLASS32 {
        return Err(ElfError::Not32Bit);
    }

    // Verify endianness (little-endian)
    if elf_bytes[5] != ELFDATA2LSB {
        return Err(ElfError::NotLittleEndian);
    }

    // Read ELF header fields
    let e_machine = read_u16(elf_bytes, 18);
    if e_machine != EM_RISCV {
        return Err(ElfError::NotRiscV(e_machine));
    }

    let e_entry = read_u32(elf_bytes, 24);
    let e_phoff = read_u32(elf_bytes, 28) as usize;
    let e_phentsize = read_u16(elf_bytes, 42) as usize;
    let e_phnum = read_u16(elf_bytes, 44) as usize;

    if e_phentsize < 32 {
        return Err(ElfError::BadPhentsize(e_phentsize));
    }

    let mut loaded_bytes = 0usize;
    let mut num_segments = 0usize;

    // Load PT_LOAD segments
    for i in 0..e_phnum {
        let ph_offset = e_phoff + i * e_phentsize;
        if ph_offset + e_phentsize > elf_bytes.len() {
            return Err(ElfError::TruncatedProgramHeader(i));
        }

        let p_type = read_u32(elf_bytes, ph_offset);
        if p_type != PT_LOAD {
            continue;
        }

        let p_offset = read_u32(elf_bytes, ph_offset + 4) as usize;
        let p_vaddr = read_u32(elf_bytes, ph_offset + 8);
        let p_filesz = read_u32(elf_bytes, ph_offset + 16) as usize;
        let p_memsz = read_u32(elf_bytes, ph_offset + 20) as usize;

        // Load file data into memory at virtual address
        if p_filesz > 0 {
            if p_offset + p_filesz > elf_bytes.len() {
                return Err(ElfError::TruncatedSegment(i));
            }
            let data = &elf_bytes[p_offset..p_offset + p_filesz];
            memory.write_bytes(p_vaddr, data)
                .map_err(|_| ElfError::SegmentOutOfBounds(i, p_vaddr, p_filesz))?;
        }

        // Zero-fill BSS (p_memsz > p_filesz)
        if p_memsz > p_filesz {
            let bss_start = p_vaddr.wrapping_add(p_filesz as u32);
            let bss_len = p_memsz - p_filesz;
            for j in 0..bss_len {
                memory.write_u8(bss_start.wrapping_add(j as u32), 0)
                    .map_err(|_| ElfError::SegmentOutOfBounds(i, bss_start, bss_len))?;
            }
        }

        loaded_bytes += p_memsz;
        num_segments += 1;
    }

    if num_segments == 0 {
        return Err(ElfError::NoLoadableSegments);
    }

    Ok(ElfInfo {
        entry_point: e_entry,
        loaded_bytes,
        num_segments,
    })
}

/// Read a little-endian u16 from a byte slice
fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

/// Read a little-endian u32 from a byte slice
fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// ELF loading errors
#[derive(Debug)]
pub enum ElfError {
    TooSmall,
    BadMagic,
    Not32Bit,
    NotLittleEndian,
    NotRiscV(u16),
    BadPhentsize(usize),
    TruncatedProgramHeader(usize),
    TruncatedSegment(usize),
    SegmentOutOfBounds(usize, u32, usize),
    NoLoadableSegments,
}

impl core::fmt::Display for ElfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ElfError::TooSmall => write!(f, "ELF too small"),
            ElfError::BadMagic => write!(f, "Not an ELF file (bad magic)"),
            ElfError::Not32Bit => write!(f, "Not a 32-bit ELF"),
            ElfError::NotLittleEndian => write!(f, "Not little-endian"),
            ElfError::NotRiscV(m) => write!(f, "Not RISC-V (machine={})", m),
            ElfError::BadPhentsize(s) => write!(f, "Bad program header entry size: {}", s),
            ElfError::TruncatedProgramHeader(i) => write!(f, "Truncated program header {}", i),
            ElfError::TruncatedSegment(i) => write!(f, "Truncated segment {}", i),
            ElfError::SegmentOutOfBounds(i, addr, sz) => {
                write!(f, "Segment {} out of bounds: addr=0x{:08X} size={}", i, addr, sz)
            }
            ElfError::NoLoadableSegments => write!(f, "No loadable segments found"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid ELF32 RISC-V binary with one PT_LOAD segment
    fn make_test_elf(entry: u32, vaddr: u32, code: &[u8]) -> Vec<u8> {
        let mut elf = vec![0u8; 52 + 32]; // ELF header + 1 program header

        // ELF header
        elf[0..4].copy_from_slice(&ELF_MAGIC);
        elf[4] = ELFCLASS32; // 32-bit
        elf[5] = ELFDATA2LSB; // little-endian
        elf[6] = 1; // ELF version
        // e_type = ET_EXEC (2)
        elf[16] = 2;
        // e_machine = EM_RISCV
        elf[18..20].copy_from_slice(&EM_RISCV.to_le_bytes());
        // e_version
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        // e_entry
        elf[24..28].copy_from_slice(&entry.to_le_bytes());
        // e_phoff = 52 (right after header)
        elf[28..32].copy_from_slice(&52u32.to_le_bytes());
        // e_phentsize = 32
        elf[42..44].copy_from_slice(&32u16.to_le_bytes());
        // e_phnum = 1
        elf[44..46].copy_from_slice(&1u16.to_le_bytes());

        // Program header (PT_LOAD)
        let ph = 52usize;
        elf[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes()); // p_type
        let data_offset = (52 + 32) as u32; // after headers
        elf[ph + 4..ph + 8].copy_from_slice(&data_offset.to_le_bytes()); // p_offset
        elf[ph + 8..ph + 12].copy_from_slice(&vaddr.to_le_bytes()); // p_vaddr
        elf[ph + 12..ph + 16].copy_from_slice(&vaddr.to_le_bytes()); // p_paddr
        let filesz = code.len() as u32;
        elf[ph + 16..ph + 20].copy_from_slice(&filesz.to_le_bytes()); // p_filesz
        elf[ph + 20..ph + 24].copy_from_slice(&filesz.to_le_bytes()); // p_memsz

        // Append code
        elf.extend_from_slice(code);

        elf
    }

    #[test]
    fn test_load_minimal_elf() {
        let code = [0x13, 0x00, 0x00, 0x00]; // nop (addi x0, x0, 0)
        let elf_bytes = make_test_elf(0x1000, 0x1000, &code);
        let mut mem = GuestMemory::new();
        let info = load_elf(&elf_bytes, &mut mem).unwrap();
        assert_eq!(info.entry_point, 0x1000);
        assert_eq!(info.num_segments, 1);
        // Verify code is in memory
        assert_eq!(mem.read_u32(0x1000).unwrap(), 0x00000013);
    }

    #[test]
    fn test_reject_non_elf() {
        let bad = vec![0u8; 100];
        let mut mem = GuestMemory::new();
        assert!(load_elf(&bad, &mut mem).is_err());
    }

    #[test]
    fn test_reject_non_riscv() {
        let mut elf = vec![0u8; 52 + 32];
        elf[0..4].copy_from_slice(&ELF_MAGIC);
        elf[4] = ELFCLASS32;
        elf[5] = ELFDATA2LSB;
        elf[18..20].copy_from_slice(&0x03u16.to_le_bytes()); // x86, not RISC-V
        elf[28..32].copy_from_slice(&52u32.to_le_bytes());
        elf[42..44].copy_from_slice(&32u16.to_le_bytes());
        elf[44..46].copy_from_slice(&0u16.to_le_bytes()); // no segments
        let mut mem = GuestMemory::new();
        assert!(load_elf(&elf, &mut mem).is_err());
    }
}

