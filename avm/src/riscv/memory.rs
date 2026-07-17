//! Guest Memory with Page-Level Tracking
//!
//! Provides a flat 32-bit address space for the RISC-V guest with page-level
//! dirty tracking for DMAP Merkle attestation.
//!
//! Uses a flat Vec<u8> for O(1) memory access. Page-level dirty bits maintained
//! separately for DMAP checkpoint Merkle tree computation.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

/// Page size for DMAP Merkle tree (4KB)
pub const PAGE_SIZE: u32 = 4096;

/// Maximum guest memory.
///
/// **2026-05-10 (KnownIssue #2 fix):** raised from 16 MB → 32 MB.
/// The 8 MB IO_BUFFER_SIZE in core/avm-guest plus a 5+ MB CBOR
/// PublicInputs (CL5 redeem with 44-link receiver_fact_chain) plus
/// 132 nested Dilithium verifications (44 links × 3 witnesses, each
/// allocating pk 1952B + sig 3309B + internal hash state) saturated
/// the 15 MB usable region (16 MB - 64 KB text base). The bump
/// allocator returned null, the alloc-error path triggered a Rust
/// panic, the panic_handler sent the static `AVM_GUEST_PANIC`
/// marker and exit(1) — surfacing on host as
/// `AvmError::ExecutionError("Guest exited with code 1")`. See
/// docs/AXIOM_REPORT_KnownIssues.md §2 for the soak repro and
/// docs/known_issues_evidence/cl5_panic_chain44_scarred.json for a
/// dump that reproduces it. With 32 MB the headroom is ~24 MB after
/// the IO buffer; production CL5 redeems with k=5 cheques + full
/// VBC chains stay well within budget. link.x in the guest must
/// match (RAM LENGTH = 31M).
pub const MAX_MEMORY: u32 = 32 * 1024 * 1024;

/// Maximum number of pages (MAX_MEMORY / PAGE_SIZE)
pub const MAX_PAGES: u32 = MAX_MEMORY / PAGE_SIZE;

/// Guest memory with page-level tracking for DMAP.
///
/// Flat Vec<u8> for O(1) memory access — eliminates BTreeMap overhead
/// that dominated execution time (~2B lookups per TX at O(log n) each).
///
/// Incremental Merkle: page hashes are cached and only re-computed for
/// dirty pages at each checkpoint. This avoids re-hashing ~2000 unchanged
/// pages 30-50K times per TX (was 50-70% of total execution time).
pub struct GuestMemory {
    /// Flat memory array — direct indexed access
    data: Vec<u8>,
    /// Per-page dirty bit (written since last checkpoint)
    page_dirty: Vec<bool>,
    /// Pages dirtied since last checkpoint clear
    dirty_since_checkpoint: Vec<u32>,
    /// Pages that have ever been written (for sparse Merkle)
    page_allocated: Vec<bool>,
    /// Cached BLAKE3 hash per page (updated incrementally on dirty pages only)
    page_hash_cache: Vec<[u8; 32]>,
    /// Per-page dirty flags written by JIT-compiled code. JIT blocks store into
    /// guest memory through a raw pointer and bypass write_u* (which is what the
    /// page_dirty/dirty_since_checkpoint tracking above keys off), so the JIT is
    /// handed this flat byte array and sets jit_dirty[guest_addr >> PAGE_SHIFT]=1
    /// after every store. memory_root() folds these into the dirty set before
    /// hashing; clear_dirty() zeroes them. One byte per page (not a bitmap) so
    /// Cranelift can emit a single unconditional byte-store with no read-modify-write.
    jit_dirty: Vec<u8>,
}

impl Default for GuestMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl GuestMemory {
    pub fn new() -> Self {
        GuestMemory {
            data: vec![0u8; MAX_MEMORY as usize],
            page_dirty: vec![false; MAX_PAGES as usize],
            dirty_since_checkpoint: Vec::new(),
            page_allocated: vec![false; MAX_PAGES as usize],
            page_hash_cache: vec![ZERO_PAGE_HASH; MAX_PAGES as usize],
            jit_dirty: vec![0u8; MAX_PAGES as usize],
        }
    }

    pub fn clear_for_reuse(&mut self) {
        self.data.fill(0);
        self.page_dirty.fill(false);
        self.dirty_since_checkpoint.clear();
        self.page_allocated.fill(false);
        self.page_hash_cache.fill(ZERO_PAGE_HASH);
        self.jit_dirty.fill(0);
    }

    /// Get raw pointer to memory data (for JIT direct access).
    /// SAFETY: caller must ensure bounds checking before dereferencing.
    #[cfg(feature = "cranelift-jit-backend")]
    #[inline(always)]
    pub fn data_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }

    /// Raw pointer to the per-page JIT dirty bytemap (len MAX_PAGES). JIT-compiled
    /// blocks write 1 to jit_dirty[guest_addr >> PAGE_SHIFT] after each store so
    /// that memory_root() can pick up pages the interpreter dirty path never sees.
    /// Length is exactly MAX_PAGES, so `guest_addr >> PAGE_SHIFT` is always in bounds
    /// for any in-bounds guest address (addr < MAX_MEMORY).
    pub fn jit_dirty_mut_ptr(&mut self) -> *mut u8 {
        self.jit_dirty.as_mut_ptr()
    }

    /// Read a single byte from guest memory
    #[inline(always)]
    pub fn read_u8(&self, addr: u32) -> Result<u8, MemoryError> {
        if addr >= MAX_MEMORY {
            return Err(MemoryError::OutOfBounds(addr));
        }
        Ok(unsafe { *self.data.get_unchecked(addr as usize) })
    }

    /// Read a 16-bit value (little-endian)
    #[inline(always)]
    pub fn read_u16(&self, addr: u32) -> Result<u16, MemoryError> {
        if addr > MAX_MEMORY - 2 {
            return Err(MemoryError::OutOfBounds(addr));
        }
        let a = addr as usize;
        Ok(unsafe {
            *self.data.get_unchecked(a) as u16
                | (*self.data.get_unchecked(a + 1) as u16) << 8
        })
    }

    /// Read a 32-bit value (little-endian)
    #[inline(always)]
    pub fn read_u32(&self, addr: u32) -> Result<u32, MemoryError> {
        if addr > MAX_MEMORY - 4 {
            return Err(MemoryError::OutOfBounds(addr));
        }
        let a = addr as usize;
        Ok(unsafe {
            *self.data.get_unchecked(a) as u32
                | (*self.data.get_unchecked(a + 1) as u32) << 8
                | (*self.data.get_unchecked(a + 2) as u32) << 16
                | (*self.data.get_unchecked(a + 3) as u32) << 24
        })
    }

    /// Write a single byte to guest memory
    #[inline(always)]
    pub fn write_u8(&mut self, addr: u32, val: u8) -> Result<(), MemoryError> {
        if addr >= MAX_MEMORY {
            return Err(MemoryError::OutOfBounds(addr));
        }
        unsafe { *self.data.get_unchecked_mut(addr as usize) = val; }
        let pi = (addr / PAGE_SIZE) as usize;
        if !self.page_dirty[pi] {
            self.page_dirty[pi] = true;
            self.page_allocated[pi] = true;
            self.dirty_since_checkpoint.push(addr / PAGE_SIZE);
        }
        Ok(())
    }

    /// Write a 16-bit value (little-endian)
    #[inline(always)]
    pub fn write_u16(&mut self, addr: u32, val: u16) -> Result<(), MemoryError> {
        self.write_u8(addr, val as u8)?;
        self.write_u8(addr.wrapping_add(1), (val >> 8) as u8)?;
        Ok(())
    }

    /// Write a 32-bit value (little-endian)
    #[inline(always)]
    pub fn write_u32(&mut self, addr: u32, val: u32) -> Result<(), MemoryError> {
        self.write_u8(addr, val as u8)?;
        self.write_u8(addr.wrapping_add(1), (val >> 8) as u8)?;
        self.write_u8(addr.wrapping_add(2), (val >> 16) as u8)?;
        self.write_u8(addr.wrapping_add(3), (val >> 24) as u8)?;
        Ok(())
    }

    /// Write a slice of bytes starting at addr
    pub fn write_bytes(&mut self, addr: u32, data: &[u8]) -> Result<(), MemoryError> {
        // Use u64 to prevent overflow when addr + len > u32::MAX
        let end64 = addr as u64 + data.len() as u64;
        if end64 > MAX_MEMORY as u64 {
            return Err(MemoryError::OutOfBounds(addr));
        }
        let end = end64 as usize;
        self.data[addr as usize..end].copy_from_slice(data);
        // Mark all touched pages dirty
        let first_page = addr / PAGE_SIZE;
        let last_page = (addr + data.len() as u32 - 1) / PAGE_SIZE;
        for p in first_page..=last_page {
            let pi = p as usize;
            if !self.page_dirty[pi] {
                self.page_dirty[pi] = true;
                self.page_allocated[pi] = true;
                self.dirty_since_checkpoint.push(p);
            }
        }
        Ok(())
    }

    /// Read a slice of bytes starting at addr
    pub fn read_bytes(&self, addr: u32, len: u32) -> Result<Vec<u8>, MemoryError> {
        let end64 = addr as u64 + len as u64;
        if end64 > MAX_MEMORY as u64 {
            return Err(MemoryError::OutOfBounds(addr));
        }
        let end = end64 as usize;
        Ok(self.data[addr as usize..end].to_vec())
    }

    /// Compute BLAKE3 hash of a specific page
    pub fn page_hash(&self, page_idx: u32) -> [u8; 32] {
        if !self.page_allocated[page_idx as usize] {
            return ZERO_PAGE_HASH;
        }
        let start = (page_idx * PAGE_SIZE) as usize;
        let end = start + PAGE_SIZE as usize;
        *blake3::hash(&self.data[start..end]).as_bytes()
    }

    /// Compute a Merkle root over all memory pages (incremental).
    ///
    /// Only re-hashes pages that were dirtied since the last call.
    /// Cached page hashes are reused for unchanged pages.
    /// This is the critical optimization: avoids re-hashing ~2000 unchanged
    /// pages at each of 30-50K checkpoints per TX.
    pub fn memory_root(&mut self) -> [u8; 32] {
        // Fold JIT-written pages into the dirty set. JIT-compiled blocks store
        // through the raw data pointer and set jit_dirty[page]=1 (they bypass
        // write_u*, which is what dirty_since_checkpoint keys off), so without
        // this reconciliation memory_root() would omit every JIT-written page.
        // jit_dirty is zeroed by clear_dirty() after the checkpoint is taken.
        for pi in 0..self.jit_dirty.len() {
            if self.jit_dirty[pi] != 0 && !self.page_dirty[pi] {
                self.page_dirty[pi] = true;
                self.page_allocated[pi] = true;
                self.dirty_since_checkpoint.push(pi as u32);
            }
        }

        // Update cache for dirty pages only (~30-50 pages vs ~2000 total)
        for &idx in &self.dirty_since_checkpoint {
            let start = (idx as usize) * PAGE_SIZE as usize;
            let end = start + PAGE_SIZE as usize;
            self.page_hash_cache[idx as usize] = *blake3::hash(&self.data[start..end]).as_bytes();
        }

        // Build Merkle tree from cached hashes using tracked allocated pages
        sparse_merkle_root_from_cache(&self.page_hash_cache, &self.page_allocated, MAX_PAGES)
    }

    /// Compute a full (non-incremental) Merkle root — for verification only.
    /// Hashes every allocated page from scratch. Used by DMAP re-execution
    /// to ensure the incremental result matches.
    pub fn memory_root_full(&self) -> [u8; 32] {
        let mut leaves: BTreeMap<u32, [u8; 32]> = BTreeMap::new();
        for idx in 0..MAX_PAGES {
            if self.page_allocated[idx as usize] {
                let start = (idx * PAGE_SIZE) as usize;
                let end = start + PAGE_SIZE as usize;
                leaves.insert(idx, *blake3::hash(&self.data[start..end]).as_bytes());
            }
        }
        sparse_merkle_root(&leaves, MAX_PAGES)
    }

    /// Clear dirty tracking (call after taking a DMAP checkpoint)
    pub fn clear_dirty(&mut self) {
        for &page_idx in &self.dirty_since_checkpoint {
            self.page_dirty[page_idx as usize] = false;
        }
        self.dirty_since_checkpoint.clear();
        // Reset the JIT dirty bytemap for the next checkpoint window. memory_root()
        // has already folded any set pages into dirty_since_checkpoint above.
        self.jit_dirty.fill(0);
    }

    /// Get indices of pages dirtied since last checkpoint
    pub fn dirty_pages(&self) -> &[u32] {
        &self.dirty_since_checkpoint
    }

    /// Total allocated pages
    pub fn allocated_pages(&self) -> usize {
        self.page_allocated.iter().filter(|&&a| a).count()
    }

    /// Reset all memory (for re-execution)
    pub fn reset(&mut self) {
        self.data.fill(0);
        self.page_dirty.fill(false);
        self.page_allocated.fill(false);
        self.dirty_since_checkpoint.clear();
        self.page_hash_cache.fill(ZERO_PAGE_HASH);
    }
}

/// BLAKE3 hash of an all-zero 4096-byte page (precomputed, verified at test time).
pub const ZERO_PAGE_HASH: [u8; 32] = [
    0xb6, 0xfb, 0x73, 0xfc, 0x46, 0x93, 0x8c, 0x98,
    0x1e, 0x2b, 0x0b, 0x4b, 0x1e, 0xf2, 0x82, 0xad,
    0xcf, 0xc8, 0x98, 0x54, 0xd0, 0x1b, 0xfe, 0x39,
    0x72, 0xfd, 0xc4, 0x78, 0x5b, 0x41, 0xb2, 0xc7,
];

/// Runtime computation of zero page hash (must match ZERO_PAGE_HASH constant).
fn zero_page_hash() -> [u8; 32] {
    ZERO_PAGE_HASH
}

/// Compute a sparse Merkle root from cached page hashes (no BTreeMap allocation).
///
/// Uses pre-cached page hashes and an allocation bitset.
/// Only allocated pages differ from the zero-page default.
fn sparse_merkle_root_from_cache(
    page_hashes: &[[u8; 32]],
    page_allocated: &[bool],
    num_leaves: u32,
) -> [u8; 32] {
    if num_leaves == 0 {
        return [0u8; 32];
    }

    let depth = if num_leaves <= 1 { 0 } else { 32 - (num_leaves - 1).leading_zeros() };
    let tree_size = 1u32 << depth;
    let zph = ZERO_PAGE_HASH;

    // Use Vec-based levels instead of BTreeMap (faster for dense-ish pages)
    // Only store non-default entries
    let mut current: BTreeMap<u32, [u8; 32]> = BTreeMap::new();
    for (idx, &allocated) in page_allocated.iter().enumerate() {
        if allocated {
            let hash = page_hashes[idx];
            if hash != zph {
                current.insert(idx as u32, hash);
            }
        }
    }

    let mut level_size = tree_size;
    let mut default_hash = zph;

    for _ in 0..depth {
        let mut next: BTreeMap<u32, [u8; 32]> = BTreeMap::new();
        let pairs = level_size / 2;

        let next_default = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&default_hash);
            hasher.update(&default_hash);
            *hasher.finalize().as_bytes()
        };

        for i in 0..pairs {
            let left_idx = i * 2;
            let right_idx = i * 2 + 1;
            let left = current.get(&left_idx).unwrap_or(&default_hash);
            let right = current.get(&right_idx).unwrap_or(&default_hash);

            let parent = {
                let mut hasher = blake3::Hasher::new();
                hasher.update(left);
                hasher.update(right);
                *hasher.finalize().as_bytes()
            };

            if parent != next_default {
                next.insert(i, parent);
            }
        }

        current = next;
        level_size = pairs;
        default_hash = next_default;
    }

    *current.get(&0).unwrap_or(&default_hash)
}

/// Compute a sparse Merkle root from a map of (leaf_index → hash)
///
/// Unoccupied leaves use the zero page hash. Tree has `num_leaves` total.
pub fn sparse_merkle_root(leaves: &BTreeMap<u32, [u8; 32]>, num_leaves: u32) -> [u8; 32] {
    if num_leaves == 0 {
        return [0u8; 32];
    }

    // Find the tree depth (round up to power of 2) — integer math, no f64
    let depth = if num_leaves <= 1 { 0 } else { 32 - (num_leaves - 1).leading_zeros() };
    let tree_size = 1u32 << depth;

    let zph = zero_page_hash();

    // Build bottom-up
    let mut current_level: BTreeMap<u32, [u8; 32]> = BTreeMap::new();

    // Initialize leaves
    for (&idx, &hash) in leaves {
        current_level.insert(idx, hash);
    }

    let mut level_size = tree_size;
    let mut default_hash = zph;

    for _ in 0..depth {
        let mut next_level: BTreeMap<u32, [u8; 32]> = BTreeMap::new();
        let pairs = level_size / 2;

        // Compute next level's default hash
        let next_default = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&default_hash);
            hasher.update(&default_hash);
            *hasher.finalize().as_bytes()
        };

        for i in 0..pairs {
            let left_idx = i * 2;
            let right_idx = i * 2 + 1;
            let left = current_level.get(&left_idx).unwrap_or(&default_hash);
            let right = current_level.get(&right_idx).unwrap_or(&default_hash);

            // Only store if different from default
            let parent = {
                let mut hasher = blake3::Hasher::new();
                hasher.update(left);
                hasher.update(right);
                *hasher.finalize().as_bytes()
            };

            if parent != next_default {
                next_level.insert(i, parent);
            }
        }

        current_level = next_level;
        level_size = pairs;
        default_hash = next_default;
    }

    // Root is at index 0 of the final level
    *current_level.get(&0).unwrap_or(&default_hash)
}

/// Memory access error
#[derive(Debug)]
pub enum MemoryError {
    OutOfBounds(u32),
}

impl core::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MemoryError::OutOfBounds(addr) => {
                write!(f, "Memory access out of bounds: 0x{:08X}", addr)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_page_hash_constant_matches_runtime() {
        let zero_page = vec![0u8; PAGE_SIZE as usize];
        let computed = *blake3::hash(&zero_page).as_bytes();
        assert_eq!(ZERO_PAGE_HASH, computed,
            "ZERO_PAGE_HASH constant does not match BLAKE3 of zero page — update the constant!");
    }

    #[test]
    fn test_read_write_u8() {
        let mut mem = GuestMemory::new();
        mem.write_u8(0x100, 0x42).unwrap();
        assert_eq!(mem.read_u8(0x100).unwrap(), 0x42);
    }

    #[test]
    fn test_read_write_u32() {
        let mut mem = GuestMemory::new();
        mem.write_u32(0x200, 0xDEADBEEF).unwrap();
        assert_eq!(mem.read_u32(0x200).unwrap(), 0xDEADBEEF);
    }

    #[test]
    fn test_unallocated_reads_zero() {
        let mem = GuestMemory::new();
        assert_eq!(mem.read_u8(0x500).unwrap(), 0);
        assert_eq!(mem.read_u32(0x500).unwrap(), 0);
    }

    #[test]
    fn test_out_of_bounds() {
        let mut mem = GuestMemory::new();
        assert!(mem.write_u8(MAX_MEMORY, 1).is_err());
        assert!(mem.read_u8(MAX_MEMORY).is_err());
    }

    #[test]
    fn test_dirty_tracking() {
        let mut mem = GuestMemory::new();
        assert!(mem.dirty_pages().is_empty());
        mem.write_u8(0x100, 1).unwrap();
        assert_eq!(mem.dirty_pages().len(), 1);
        // Write to same page — no duplicate
        mem.write_u8(0x101, 2).unwrap();
        assert_eq!(mem.dirty_pages().len(), 1);
        // Write to different page
        mem.write_u8(PAGE_SIZE + 0x100, 3).unwrap();
        assert_eq!(mem.dirty_pages().len(), 2);
        mem.clear_dirty();
        assert!(mem.dirty_pages().is_empty());
    }

    #[test]
    fn test_memory_root_deterministic() {
        let mut mem = GuestMemory::new();
        mem.write_u32(0x100, 0x12345678).unwrap();
        let root1 = mem.memory_root();
        let root2 = mem.memory_root();
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_memory_root_changes_on_write() {
        let mut mem = GuestMemory::new();
        let root1 = mem.memory_root();
        mem.write_u8(0x100, 1).unwrap();
        let root2 = mem.memory_root();
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_incremental_matches_full() {
        let mut mem = GuestMemory::new();
        // Write to several pages
        mem.write_u32(0x100, 0xDEADBEEF).unwrap();
        mem.write_u32(0x2000, 0xCAFEBABE).unwrap();
        mem.write_u32(0x5000, 0x12345678).unwrap();

        // Incremental root
        let inc_root = mem.memory_root();
        // Full root (from scratch)
        let full_root = mem.memory_root_full();
        assert_eq!(inc_root, full_root, "incremental must match full computation");

        // Clear dirty, write more, check again
        mem.clear_dirty();
        mem.write_u32(0x100, 0x11111111).unwrap();  // modify existing page
        mem.write_u32(0x8000, 0x22222222).unwrap();  // new page

        let inc_root2 = mem.memory_root();
        let full_root2 = mem.memory_root_full();
        assert_eq!(inc_root2, full_root2, "incremental must match after second checkpoint");
        assert_ne!(inc_root, inc_root2, "root should change after writes");
    }

    #[test]
    fn test_write_read_bytes() {
        let mut mem = GuestMemory::new();
        let data = b"Hello AXIOM";
        mem.write_bytes(0x300, data).unwrap();
        let read = mem.read_bytes(0x300, data.len() as u32).unwrap();
        assert_eq!(read, data);
    }
}

#[cfg(test)]
mod bench {
    use super::*;

    /// Benchmark: sequential read/write pattern (simulates CBOR parsing)
    #[test]
    fn bench_sequential_rw() {
        let mut mem = GuestMemory::new();
        let start = std::time::Instant::now();
        
        // Write 1MB sequentially (simulates ELF loading + heap alloc)
        for addr in (0..1_048_576u32).step_by(4) {
            mem.write_u32(addr, addr).unwrap();
        }
        let write_elapsed = start.elapsed();
        
        // Read 1MB sequentially (simulates CBOR deserialization)
        let start = std::time::Instant::now();
        let mut sum = 0u64;
        for addr in (0..1_048_576u32).step_by(4) {
            sum += mem.read_u32(addr).unwrap() as u64;
        }
        let read_elapsed = start.elapsed();
        
        // Read 10M random-ish accesses (simulates instruction fetch + data access)
        let start = std::time::Instant::now();
        for i in 0..10_000_000u32 {
            let addr = (i.wrapping_mul(2654435761) % 1_048_576) & !3; // aligned
            sum += mem.read_u32(addr).unwrap() as u64;
        }
        let random_elapsed = start.elapsed();
        
        eprintln!("=== MEMORY BENCHMARK (flat Vec) ===");
        eprintln!("  Sequential write 1MB:   {:?}", write_elapsed);
        eprintln!("  Sequential read 1MB:    {:?}", read_elapsed);
        eprintln!("  Random read 10M:        {:?}", random_elapsed);
        eprintln!("  (sum={} to prevent opt-out)", sum);
        
        // Also benchmark memory_root computation
        let start = std::time::Instant::now();
        let _root = mem.memory_root();
        let root_elapsed = start.elapsed();
        eprintln!("  Memory root (Merkle):   {:?}", root_elapsed);
    }
}
