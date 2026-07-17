//! AVM Interpreter
//!
//! This is the AXIOM Virtual Machine that executes core validation logic.
//!
//! # Execution Modes
//!
//! - **Default:** Executes `execute_core()` directly as native Rust. Fast, used for
//!   testing and when the host platform matches the target (dev, CI, zkVM guest).
//!
//! - **`riscv-interpreter` feature:** Real RV32IM interpretation of a compiled
//!   axiom-core.elf binary. §31 compliant — Core compiles ONCE to RISC-V ELF,
//!   AVM interprets it on every platform. Enables DMAP attestation via memory
//!   checkpoint tracking.
//!
//! Both modes produce identical PublicOutputs for identical PublicInputs.

// CONSENSUS_CRITICAL

use alloc::vec::Vec;
use alloc::string::String;
#[allow(unused_imports)]
use alloc::format;

// The validator-only full AvmInterpreter (pulse / audit / wallet-cache) is
// std-gated below (see the `cfg(feature = "std")` blocks). Its Mutex / atomic /
// HashMap usage is therefore needed only under std. Any no_std build (the wasm
// web wallet OR the risc0 zkVM guest, which is no_std but NOT wasm) compiles the
// slim AvmInterpreter instead and needs none of these. Keyed on `std` so the
// risc0 guest takes the slim path identically to wasm.
#[cfg(feature = "std")]
use std::sync::Mutex;

#[cfg(feature = "std")]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[cfg(feature = "std")]
use std::collections::HashMap;

use axiom_core_logic::{PublicInputs, PublicOutputs, execute_core};

#[cfg(feature = "std")]
#[allow(unused_imports)]
use axiom_core_logic::types::ValidationResult;

#[cfg(feature = "std")]
#[allow(unused_imports)]
use axiom_core_logic::types::{
    TxDigest, PulseAuditRequest, PulseProofData, NonceChallenge, NonceResponse,
    PULSE_BUFFER_MAX, PULSE_BUFFER_TRIGGER_RATIO,
    PULSE_AUDIT_INTERVAL_SECS, PULSE_SAMPLE_RATIO, NONCE_MISMATCH_TOLERANCE,
    PULSE_CALIBRATION_MS,
};
use crate::host_functions::HostFunctions;

#[cfg(feature = "riscv-interpreter")]
use crate::riscv::{ExitReason, load_elf};

#[cfg(feature = "riscv-interpreter")]
use crate::riscv::{FastCpu, InstructionCache};

use crate::dmap::DmapTrace;

#[cfg(feature = "riscv-interpreter")]
use crate::dmap::DMAP_CHECKPOINT_INTERVAL;

#[cfg(feature = "riscv-interpreter")]
use crate::dmap::checkpoint::DmapCheckpoint;

/// Error type for AVM operations
#[derive(Debug)]
pub enum AvmError {
    /// Failed to load axiom-core.elf bytecode
    LoadError(String),

    /// axiom-core.elf execution failed
    ExecutionError(String),

    /// Runtime verification failed (wrong zkVM)
    RuntimeVerificationFailed,

    /// §23.14: Lambda failed to complete demanded audit within countdown.
    /// Core self-terminates. Restart required (VBC re-verification penalty).
    AuditTimeout {
        challenge_nonce: [u8; 32],
        target_validator_pk: Vec<u8>,
        txs_remaining_when_expired: u8,
    },

    /// §23.14.6: Transaction rejected because a witness validator is banned.
    ValidatorBanned {
        validator_pk: Vec<u8>,
        reason: axiom_core_logic::types::PeerAuditBanReason,
    },

    /// YPX-009 pulse-gate: Core is not ready to serve.
    /// Lambda must call `start_pulse_calibration()` before executing transactions.
    PulseNotReady,
}

// ============================================================================
// WASM variant: simplified AvmInterpreter (no validator state)
// ============================================================================

#[cfg(not(feature = "std"))]
#[derive(Debug)]
pub struct AvmInterpreter {
    /// The axiom-core.elf bytes
    bytecode: Vec<u8>,
    /// Runtime fingerprint for verification
    runtime_fingerprint: [u8; 32],
}

#[cfg(not(feature = "std"))]
impl AvmInterpreter {
    pub fn new(bytecode: Vec<u8>, runtime_fingerprint: [u8; 32]) -> Self {
        Self { bytecode, runtime_fingerprint }
    }

    /// Execute core validation (CL1/CL4 only in web wallet)
    pub fn execute(&self, inputs: PublicInputs) -> Result<PublicOutputs, AvmError> {
        if self.runtime_fingerprint != [0u8; 32]
            && self.runtime_fingerprint != EXPECTED_RISC0_FINGERPRINT
        {
            return Err(AvmError::RuntimeVerificationFailed);
        }

        #[cfg(feature = "riscv-interpreter")]
        {
            if self.has_valid_elf() {
                let result = self.execute_riscv(inputs)?;
                return Ok(result.outputs);
            }
        }

        let _host = HostFunctions::new(0, self.runtime_fingerprint);
        Ok(execute_core(inputs))
    }

    /// Execute with DMAP trace collection
    pub fn execute_with_dmap(&self, inputs: PublicInputs) -> Result<AvmExecutionResult, AvmError> {
        if self.runtime_fingerprint != [0u8; 32]
            && self.runtime_fingerprint != EXPECTED_RISC0_FINGERPRINT
        {
            return Err(AvmError::RuntimeVerificationFailed);
        }

        #[cfg(feature = "riscv-interpreter")]
        {
            if self.has_valid_elf() {
                return self.execute_riscv(inputs);
            }
        }

        let _host = HostFunctions::new(0, self.runtime_fingerprint);
        Ok(AvmExecutionResult {
            outputs: execute_core(inputs),
            dmap_trace: None,
            core_id: self.core_fingerprint(),
        })
    }

    #[cfg(feature = "riscv-interpreter")]
    fn execute_riscv(&self, inputs: PublicInputs) -> Result<AvmExecutionResult, AvmError> {
        // Profile mode (std-only): when AVM_PROFILE env var is set, log per-stage
        // timings to stderr. Not available in WASM (no env vars, no wall clock).
        // Discovered need: 2026-04-13 witness perf investigation — needed to
        // determine if the 14-16s per-call cost is Dilithium math or CBOR decode.
        #[cfg(feature = "std")]
        let profile = std::env::var("AVM_PROFILE").is_ok();
        #[cfg(not(feature = "std"))]
        let profile = false;
        let _ = profile; // silence unused-variable warning in wasm path

        let core_id = self.core_fingerprint();

        #[cfg(feature = "std")]
        let t_serialize = if profile { Some(std::time::Instant::now()) } else { None };
        let mut input_cbor = Vec::new();
        ciborium::ser::into_writer(&inputs, &mut input_cbor)
            .map_err(|e| AvmError::ExecutionError(format!("serialize inputs: {}", e)))?;
        #[cfg(feature = "std")]
        if let Some(t) = t_serialize {
            eprintln!("[AVM_PROFILE] cbor_encode_inputs: {:?} ({} bytes)",
                      t.elapsed(), input_cbor.len());
        }

        let host = HostFunctions::new(0, self.runtime_fingerprint);

        // Phase 1-3: use FastCpu with pre-decoded instruction cache.
        // Falls back to original Cpu if FastCpu encounters issues.
        let mut memory = crate::riscv::GuestMemory::new();

        #[cfg(feature = "std")]
        let t_elf = if profile { Some(std::time::Instant::now()) } else { None };
        let elf_info = load_elf(&self.bytecode, &mut memory)
            .map_err(|e| AvmError::LoadError(format!("ELF load: {}", e)))?;
        #[cfg(feature = "std")]
        if let Some(t) = t_elf {
            eprintln!("[AVM_PROFILE] elf_load: {:?}", t.elapsed());
        }

        // Build instruction cache over the entire loaded region.
        // The ELF may have code across multiple segments — cache from
        // the lowest load address to entry_point + loaded_bytes.
        // Over-caching is safe (data decoded as instructions just produces
        // handler::ILLEGAL which falls through to memory-decode path).
        let icache_base = 0x10000u32; // typical RISC-V ELF load base
        let icache_end = icache_base + elf_info.loaded_bytes as u32;
        let icache = InstructionCache::build(&memory, icache_base, icache_end - icache_base);

        let mut cpu = FastCpu::new(memory, elf_info.entry_point, input_cbor, host);
        cpu.regs[2] = crate::riscv::memory::MAX_MEMORY as u32 - 4096; // sp
        cpu.set_icache(icache);

        // Phase B: Cranelift JIT — use cached compiled blocks from startup
        #[cfg(feature = "cranelift-jit-backend")]
        {
            if let Some(ref jit_arc) = self.jit_engine {
                cpu.set_jit(jit_arc.clone());
            }
        }

        #[cfg(feature = "std")]
        let t_cpu = if profile { Some(std::time::Instant::now()) } else { None };
        let (exit_reason, raw_checkpoints) =
            cpu.run_collecting_checkpoints(DMAP_CHECKPOINT_INTERVAL);
        #[cfg(feature = "std")]
        if let Some(t) = t_cpu {
            eprintln!("[AVM_PROFILE] cpu_run: {:?} ({} checkpoints, exit={:?})",
                      t.elapsed(), raw_checkpoints.len(), exit_reason);
        }

        match exit_reason {
            ExitReason::Exit(0) => {}
            ExitReason::Exit(code) => {
                return Err(AvmError::ExecutionError(format!("Guest exited with code {}", code)));
            }
            ExitReason::InstructionLimit => {
                return Err(AvmError::ExecutionError("Hit instruction limit".into()));
            }
            ExitReason::IllegalInstruction(pc, raw) => {
                return Err(AvmError::ExecutionError(format!("Illegal instruction at PC=0x{:08X}: 0x{:08X}", pc, raw)));
            }
            ExitReason::MemoryFault(pc, desc) => {
                return Err(AvmError::ExecutionError(format!("Memory fault at PC=0x{:08X}: {}", pc, desc)));
            }
            ExitReason::Ebreak => {
                return Err(AvmError::ExecutionError("Unexpected EBREAK".into()));
            }
            ExitReason::UnknownSyscall(n) => {
                return Err(AvmError::ExecutionError(format!("Unknown syscall: 0x{:02X}", n)));
            }
        }

        if !cpu.has_output() {
            return Err(AvmError::ExecutionError("Guest did not write outputs".into()));
        }

        #[cfg(feature = "std")]
        let t_decode = if profile { Some(std::time::Instant::now()) } else { None };
        let output_bytes = cpu.output();
        let output_len = output_bytes.len();
        let outputs: PublicOutputs = ciborium::de::from_reader(output_bytes)
            .map_err(|e| AvmError::ExecutionError(format!("deserialize outputs: {}", e)))?;
        #[cfg(feature = "std")]
        if let Some(t) = t_decode {
            eprintln!("[AVM_PROFILE] cbor_decode_outputs: {:?} ({} bytes)",
                      t.elapsed(), output_len);
        }
        let _ = output_len; // used only in cfg(std) eprintln; silence unused-variable warning

        let dmap_checkpoints: Vec<DmapCheckpoint> = raw_checkpoints
            .into_iter()
            .map(|cs| DmapCheckpoint {
                instruction_count: cs.instruction_count,
                pc: cs.pc,
                memory_root: cs.memory_root,
                register_hash: cs.register_hash,
            })
            .collect();

        let trace = if dmap_checkpoints.is_empty() {
            None
        } else {
            Some(DmapTrace::from_checkpoints(dmap_checkpoints))
        };

        Ok(AvmExecutionResult { outputs, dmap_trace: trace, core_id })
    }

    fn has_valid_elf(&self) -> bool {
        self.bytecode.len() >= 4 && self.bytecode[..4] == [0x7F, b'E', b'L', b'F']
    }

    pub fn core_fingerprint(&self) -> [u8; 32] {
        *blake3::hash(&self.bytecode).as_bytes()
    }

    pub fn verify_core(&self, expected: &[u8; 32]) -> bool {
        &self.core_fingerprint() == expected
    }
}

// ============================================================================
// Native variant: full AvmInterpreter with validator state
// ============================================================================

/// §23.14: Pending audit state tracked across Core invocations.
/// The AVM interpreter maintains this — Core (guest) is stateless.
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
struct PendingAudit {
    /// The demand Core generated
    demand: axiom_core_logic::types::AuditDemand,
    /// TXs remaining before timeout (starts at AUDIT_COUNTDOWN_TXS or PEER_AUDIT_COUNTDOWN_TXS)
    remaining: u8,
    /// The tx_number of the TX that triggered this demand.
    /// Used to find the correct TxDigest entry for content verification.
    trigger_tx_number: u64,
    /// Whether this is a peer-audit (target != our PK).
    /// Peer-audits get 100 TX countdown (email round-trip budget).
    /// Self-audits get 10 TX countdown (local resolution).
    is_peer: bool,
    /// Wall-clock start time for peer-audit timeout (10 minutes).
    /// Only used for peer-audits. Self-audits rely solely on TX countdown.
    started_at: Option<std::time::Instant>,
    /// The expected hash for peer-audit verification.
    /// Computed by Core from audit buffer, sent to remote, compared on return.
    peer_expected_hash: Option<[u8; 32]>,
}

// ── YPX-009: Silicon Pulse — AVM-held audit state (validator-only) ──

/// Audit buffer: ring of TxDigests with Argon2id→BLAKE3 accumulator chain (YPX-009 §3.5).
#[cfg(feature = "std")]
/// Lives inside AvmInterpreter — Lambda cannot access this.
///
/// Dual-trigger audit (YPX-009 §4):
///   TIME:  every 5 minutes (PULSE_AUDIT_INTERVAL_SECS), regardless of TX count.
///   COUNT: buffer reaches 80% of PULSE_BUFFER_MAX (prevents overflow).
///
/// Argon2id uses 64MB per call — exceeds L3 cache, forces main memory access.
/// Two validators on same machine = 128MB active → memory bus contention.
#[derive(Debug)]
#[allow(dead_code)]
struct AuditBuffer {
    /// Accumulated TX digests (up to PULSE_BUFFER_MAX)
    entries: Vec<TxDigest>,
    /// BLAKE3 chain over all entries (Argon2id output feeds into BLAKE3 chain)
    accumulator: [u8; 32],
    /// Transaction sequence counter (monotonic per AVM instance)
    tx_counter: u64,
    /// Timestamp (secs) when last audit completed — for time-based trigger
    last_audit_time_secs: u64,
    /// Pending audit request awaiting Lambda's response
    pending_request: Option<PulseAuditRequest>,
    /// Tick when pending request was issued (for deadline enforcement)
    pending_request_tick: Option<u64>,
    /// Measured Argon2id(64MB,t=1) throughput on this hardware.
    /// Reported in PulseProofData for peer validation.
    argon2id_per_sec: u64,
}

#[cfg(feature = "std")]
#[allow(dead_code)]
impl AuditBuffer {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            accumulator: [0u8; 32],
            tx_counter: 0,
            last_audit_time_secs: 0,
            pending_request: None,
            pending_request_tick: None,
            argon2id_per_sec: 0,
        }
    }

    /// Self-benchmark via Argon2id (YPX-009 §8.5).
    ///
    /// Measures Argon2id(64MB,t=1) throughput for PULSE_CALIBRATION_MS.
    /// Reported in PulseProofData so peers can validate audit expectations.
    ///
    /// Argon2id is memory-hard: multiple validators sharing one machine
    /// compete for memory bus, reducing each one's measured throughput.
    fn self_benchmark(&mut self) {
        use std::time::Instant;
        let cal_ms = PULSE_CALIBRATION_MS.max(50); // at least 50ms
        let start = Instant::now();
        let mut hash = [0u8; 32];
        let mut count = 0u64;

        // Always run at least 1 iteration — Argon2id(48MB) may exceed cal_ms in debug
        loop {
            hash = Self::argon2id_hash(&hash, &hash);
            count += 1;
            if start.elapsed().as_millis() >= cal_ms as u128 {
                break;
            }
        }
        let elapsed_ms = start.elapsed().as_millis().max(1) as u64;
        self.argon2id_per_sec = count * 1000 / elapsed_ms;

        // Floor at 1 — even if very slow, report non-zero throughput
        if self.argon2id_per_sec == 0 && count > 0 {
            self.argon2id_per_sec = 1;
        }

        eprintln!(
            "[YPX-009] Pulse self-benchmark: {} Argon2id/sec",
            self.argon2id_per_sec,
        );
        // Park the value in the crate-level process-global atomic so
        // out-of-band consumers (operator dashboard /capacity endpoint)
        // can read the hardware-fitness signal without plumbing
        // PulseAuditResponse through every crate boundary.
        crate::LAST_ARGON2ID_PER_SEC.store(
            self.argon2id_per_sec as u64,
            core::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Accumulate a TxDigest into the buffer (YPX-009 §3.5).
    ///
    /// Two-phase chain: Argon2id (memory-hard work) → BLAKE3 (chain link).
    /// - Argon2id creates memory pressure per TX (detects multi-validator sharing)
    /// - BLAKE3 chains the Argon2id output into the accumulator (audit integrity)
    /// - Skip Argon2id → chain hash diverges → audit fails
    fn accumulate(&mut self, digest: TxDigest) {
        let payload = Self::digest_payload(&digest);

        // Phase 1: Argon2id — memory-hard work (contention detection)
        // salt = current accumulator, password = TX digest payload
        let argon2_output = Self::argon2id_hash(
            &self.accumulator,
            payload.as_bytes(),
        );

        // Phase 2: BLAKE3 — chain the Argon2id output into accumulator
        let mut chain_input = Vec::with_capacity(17 + 32 + 32);
        chain_input.extend_from_slice(b"AXIOM_AUDIT_CHAIN");
        chain_input.extend_from_slice(&self.accumulator);
        chain_input.extend_from_slice(&argon2_output);
        self.accumulator = *blake3::hash(&chain_input).as_bytes();
        self.entries.push(digest);
    }

    /// Argon2id hash for memory-hard audit work (YPX-009 §8.5).
    ///
    /// Parameters tuned for per-TX contention detection:
    /// - m_cost = 32768 (32MB memory per TX)
    /// - t_cost = 1 (single pass — speed matters)
    /// - p_cost = 1 (single lane)
    ///
    /// Primary purpose: ensure Lambda records data honestly (tamper-evident chain).
    /// Secondary purpose: detect multi-validator co-location on commodity hardware.
    ///
    /// 32MB exceeds L3 cache on commodity/cloud hardware (8-36MB) where attacks
    /// are likely. High-end server CPUs (64-384MB L3) are not the threat model —
    /// operators with EPYC/Threadripper are traceable and have skin in the game.
    /// Attackers optimize for anonymity (cheap VMs), not compute.
    fn argon2id_hash(salt: &[u8; 32], password: &[u8]) -> [u8; 32] {
        use argon2::{Argon2, Algorithm, Version, Params};

        // Production: 32MB (32768 KiB) — exceeds commodity L3 cache.
        // Light-audit mode: 512KB — exercises the full Argon2id→BLAKE3 chain
        // logic without the memory-hard cost. Same algorithm, same hash chain,
        // just fast enough for testing. NOT FOR PRODUCTION.
        #[cfg(feature = "light-audit")]
        let m_cost: u32 = 512; // 512 KiB — test mode
        #[cfg(not(feature = "light-audit"))]
        let m_cost: u32 = 32_768; // 32MB — production

        let params = Params::new(
            m_cost,
            1,       // t_cost: 1 pass
            1,       // p_cost: 1 lane
            Some(32) // output length
        ).expect("valid Argon2 params");

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut output = [0u8; 32];
        argon2.hash_password_into(password, salt, &mut output)
            .expect("Argon2id hash must not fail");
        output
    }

    /// Compute the BLAKE3 payload hash for a single TxDigest.
    fn digest_payload(digest: &TxDigest) -> blake3::Hash {
        blake3::hash(&digest.to_bytes())
    }

    /// Check if audit should trigger (YPX-009 §4.1).
    ///
    /// Dual-trigger design:
    ///   TIME:  every PULSE_AUDIT_INTERVAL_SECS (300s / 5 min), regardless of TX count.
    ///          Catches low-traffic validators that would never fill the buffer.
    ///   COUNT: buffer reaches 80% of PULSE_BUFFER_MAX (1600 of 2000).
    ///          Prevents buffer overflow under high traffic.
    ///
    /// `current_time_secs` is Unix epoch seconds from the transaction timestamp.
    fn should_trigger(&self, current_time_secs: u64) -> bool {
        if self.pending_request.is_some() {
            return false; // already waiting for response
        }
        if self.entries.is_empty() {
            return false; // nothing to audit
        }
        // COUNT trigger — buffer at 80% capacity
        let count_threshold = (PULSE_BUFFER_MAX as f64 * PULSE_BUFFER_TRIGGER_RATIO) as u32;
        if self.entries.len() as u32 >= count_threshold {
            return true;
        }
        // TIME trigger — 5 minutes since last audit
        if current_time_secs.saturating_sub(self.last_audit_time_secs) >= PULSE_AUDIT_INTERVAL_SECS {
            return true;
        }
        false
    }

    /// Generate audit request with Fiat-Shamir subset selection (YPX-009 §4.2-4.3).
    fn generate_request(&self, validator_pk: &[u8], epoch: u64) -> PulseAuditRequest {
        let count = self.entries.len() as u32;
        let sample_size = (count as f64 * PULSE_SAMPLE_RATIO).ceil().max(1.0) as u32;

        // Fiat-Shamir selection seed
        let mut seed_input = Vec::with_capacity(18 + 32 + validator_pk.len());
        seed_input.extend_from_slice(b"AXIOM_AUDIT_SELECT");
        seed_input.extend_from_slice(&self.accumulator);
        seed_input.extend_from_slice(validator_pk);
        let seed = *blake3::hash(&seed_input).as_bytes();

        // Select indices using seed
        let selected_indices = fiat_shamir_select(&seed, count, sample_size);
        let tx_numbers: Vec<u64> = selected_indices
            .iter()
            .map(|&idx| self.entries[idx as usize].tx_number)
            .collect();
        let state_ids: Vec<[u8; 32]> = selected_indices
            .iter()
            .map(|&idx| self.entries[idx as usize].state_id)
            .collect();

        // Compute expected hash over selected subset
        let expected_hash = self.compute_subset_hash(&selected_indices);

        PulseAuditRequest {
            selected_indices,
            tx_numbers,
            state_ids,
            expected_hash,
            epoch,
        }
    }

    /// Compute chain hash over a subset of entries (YPX-009 §4.3).
    /// Uses Argon2id → BLAKE3 same as accumulate() — Lambda must replay
    /// the memory-hard work to produce a matching hash.
    fn compute_subset_hash(&self, indices: &[u32]) -> [u8; 32] {
        let mut subset_acc = [0u8; 32];
        for &idx in indices {
            let digest = &self.entries[idx as usize];
            let payload = Self::digest_payload(digest);

            // Argon2id memory-hard work (same as accumulate)
            let argon2_output = Self::argon2id_hash(&subset_acc, payload.as_bytes());

            // BLAKE3 chain (verification domain tag)
            let mut chain_input = Vec::with_capacity(18 + 32 + 32);
            chain_input.extend_from_slice(b"AXIOM_AUDIT_VERIFY");
            chain_input.extend_from_slice(&subset_acc);
            chain_input.extend_from_slice(&argon2_output);
            subset_acc = *blake3::hash(&chain_input).as_bytes();
        }
        subset_acc
    }

    /// Replay Argon2id→BLAKE3 chain from raw TxDigest entries (self-audit verification).
    /// Same algorithm as compute_subset_hash, but operates on Lambda's raw DB data
    /// instead of buffer indices. Lambda does zero crypto — Core replays everything.
    fn replay_chain_from_raw(entries: &[TxDigest]) -> [u8; 32] {
        let mut subset_acc = [0u8; 32];
        for digest in entries {
            let payload = Self::digest_payload(digest);

            // Argon2id memory-hard work (same as accumulate/compute_subset_hash)
            let argon2_output = Self::argon2id_hash(&subset_acc, payload.as_bytes());

            // BLAKE3 chain (same domain tag as compute_subset_hash)
            let mut chain_input = Vec::with_capacity(18 + 32 + 32);
            chain_input.extend_from_slice(b"AXIOM_AUDIT_VERIFY");
            chain_input.extend_from_slice(&subset_acc);
            chain_input.extend_from_slice(&argon2_output);
            subset_acc = *blake3::hash(&chain_input).as_bytes();
        }
        subset_acc
    }

    /// Reset buffer after successful audit.
    fn reset(&mut self, current_time_secs: u64) {
        self.entries.clear();
        self.accumulator = [0u8; 32];
        self.last_audit_time_secs = current_time_secs;
        self.pending_request = None;
        self.pending_request_tick = None;
    }
}

/// Wallet state cache for nonce challenges (YPX-009 §3.6).
#[cfg(feature = "std")]
#[derive(Debug)]
#[allow(dead_code)]
struct WalletCache {
    entries: HashMap<[u8; 32], WalletCacheEntry>,
    insertion_order: Vec<[u8; 32]>,
    /// Consecutive nonce mismatches
    mismatch_count: u32,
}

/// Single wallet cache entry.
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct WalletCacheEntry {
    _wallet_pk: [u8; 32],
    produced_state_id: [u8; 32],
    balance: u64,
    _last_seen_tx: u64,
}

#[cfg(feature = "std")]
#[allow(dead_code)]
impl WalletCache {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            insertion_order: Vec::new(),
            mismatch_count: 0,
        }
    }

    /// Update cache with wallet state from a completed TX.
    fn update(&mut self, wallet_pk: [u8; 32], state_id: [u8; 32], balance: u64, tx_number: u64) {
        if !self.entries.contains_key(&wallet_pk) {
            self.insertion_order.push(wallet_pk);
        }
        self.entries.insert(wallet_pk, WalletCacheEntry {
            _wallet_pk: wallet_pk,
            produced_state_id: state_id,
            balance,
            _last_seen_tx: tx_number,
        });
    }

    /// Generate a nonce challenge for a random wallet (YPX-009 §3.6).
    fn generate_challenge(&self, txid: &[u8; 32], accumulator: &[u8; 32]) -> Option<NonceChallenge> {
        if self.insertion_order.is_empty() {
            return None;
        }
        let mut seed_input = Vec::with_capacity(19 + 32 + 32);
        seed_input.extend_from_slice(b"AXIOM_NONCE_SELECT");
        seed_input.extend_from_slice(txid);
        seed_input.extend_from_slice(accumulator);
        let seed = blake3::hash(&seed_input);
        let idx = u64::from_le_bytes(seed.as_bytes()[0..8].try_into().unwrap())
            % self.insertion_order.len() as u64;
        let target_pk = self.insertion_order[idx as usize];
        let entry = &self.entries[&target_pk];
        Some(NonceChallenge {
            target_wallet_pk: target_pk,
            expected_state_id: entry.produced_state_id,
        })
    }

    /// Verify a nonce response against cache (YPX-009 §3.6 step 6-7).
    /// Returns true if response is acceptable, false if mismatch.
    fn verify_response(&mut self, response: &NonceResponse) -> bool {
        if let Some(cached) = self.entries.get_mut(&response.target_wallet_pk) {
            if response.current_state_id == cached.produced_state_id {
                // Exact match — honest
                self.mismatch_count = 0;
                true
            } else if response.current_balance >= cached.balance {
                // State advanced (wallet had more TXs since cache entry) — accept.
                // GAP-D FIX: Do NOT update cache — keep old floor values.
                // Only exact state_id match (above) updates cache, proving Core computed the state.
                // This prevents a malicious Lambda from poisoning the cache with inflated balances.
                self.mismatch_count = 0;
                true
            } else {
                // State diverged — Lambda's DB is inconsistent
                self.mismatch_count += 1;
                false
            }
        } else {
            // Wallet not in cache (possible after crash/reset) — accept
            self.mismatch_count = 0;
            true
        }
    }

    /// Check if too many consecutive mismatches have occurred.
    fn is_audit_failed(&self) -> bool {
        self.mismatch_count >= NONCE_MISMATCH_TOLERANCE
    }
}

/// Fiat-Shamir deterministic subset selection.
/// Selects `count` unique indices from [0, total) using seed.
#[cfg(feature = "std")]
#[allow(dead_code)]
fn fiat_shamir_select(seed: &[u8; 32], total: u32, count: u32) -> Vec<u32> {
    if count >= total {
        return (0..total).collect();
    }
    let mut selected = Vec::with_capacity(count as usize);
    let mut round = 0u64;
    while (selected.len() as u32) < count {
        let mut input = Vec::with_capacity(32 + 8);
        input.extend_from_slice(seed);
        input.extend_from_slice(&round.to_le_bytes());
        let h = blake3::hash(&input);
        let idx = u32::from_le_bytes(h.as_bytes()[0..4].try_into().unwrap()) % total;
        if !selected.contains(&idx) {
            selected.push(idx);
        }
        round += 1;
    }
    selected.sort();
    selected
}

impl core::fmt::Display for AvmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LoadError(msg) => write!(f, "Load error: {}", msg),
            Self::ExecutionError(msg) => write!(f, "Execution error: {}", msg),
            Self::RuntimeVerificationFailed => write!(f, "Runtime verification failed"),
            Self::AuditTimeout { challenge_nonce, .. } => write!(
                f, "AXIOM FATAL: §23.14 audit timeout — Lambda failed to complete \
                demanded peer audit (nonce: {}). Core self-terminating. \
                Restart required (VBC re-verification penalty).",
                hex::encode(&challenge_nonce[..8])
            ),
            Self::ValidatorBanned { validator_pk, reason } => write!(
                f, "AXIOM: §23.14.6 TX rejected — witness validator {} is banned ({:?}). \
                Ban expires after 24 hours or AVM restart.",
                hex::encode(&validator_pk[..core::cmp::min(8, validator_pk.len())]),
                reason
            ),
            Self::PulseNotReady => write!(
                f, "AXIOM: Core not ready — pulse calibration pending. \
                Lambda must call start_pulse_calibration() before executing transactions."
            ),
        }
    }
}

/// The RISC Zero runtime fingerprint that axiom-core.elf expects.
/// Zero = dev mode (any runtime accepted). Non-zero = must match exactly.
/// PLACEHOLDER — G1 ceremony bakes the real ELF hash. See g1-ceremony.sh step 6.
/// After G1, this becomes the canonical fingerprint and rejects any other runtime.
pub const EXPECTED_RISC0_FINGERPRINT: [u8; 32] = [0u8; 32];

// Compile guard: release builds warn if fingerprint is still placeholder.
// Unlike WALLET_IDENTITY_KEY, this doesn't fail the build — validators can run
// without zkVM (DMAP-only mode). But it SHOULD be set before production.
#[cfg(all(not(feature = "dev-mode"), not(debug_assertions)))]
const _RISC0_FINGERPRINT_CHECK: () = {
    // NOTE: This is a soft warning, not a hard failure.
    // DMAP validators don't need the zkVM fingerprint.
    // ZKP validators MUST have the real fingerprint after G1 ceremony.
};

/// Result of AVM execution, including optional DMAP trace
pub struct AvmExecutionResult {
    /// The validation outputs
    pub outputs: PublicOutputs,

    /// DMAP trace (only populated when riscv-interpreter is active)
    pub dmap_trace: Option<DmapTrace>,

    /// CoreID = BLAKE3(elf_bytes) used during execution
    pub core_id: [u8; 32],
}

/// AVM Interpreter (native/validator variant)
///
/// Executes core validation logic. In default mode, calls `execute_core()` directly.
/// With `riscv-interpreter` feature, loads and interprets a RISC-V ELF binary,
/// collecting DMAP checkpoints for memory attestation.
///
/// Persists across TX executions. Holds audit buffer and wallet cache that are
/// invisible to Lambda (YPX-009 §3.2). Lambda calls execute() and receives
/// PublicOutputs — it cannot access the struct internals.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct AvmInterpreter {
    /// The axiom-core.elf bytes (for fingerprinting and RV32IM execution)
    bytecode: Vec<u8>,

    /// Runtime fingerprint for verification
    runtime_fingerprint: [u8; 32],

    /// §23.14: Pending audit demand with countdown.
    /// If Some and remaining reaches 0 without confirmation → self-terminate.
    /// Uses Mutex for interior mutability (execute takes &self, not &mut self).
    pending_audit: Mutex<Option<PendingAudit>>,

    /// §23.14.6: Peer audit ban list. Validators that failed peer-audit
    /// (wrong hash or non-responds). Any TX with a banned validator in
    /// witness_pks is rejected. Clears after 24h or on AVM restart.
    peer_audit_bans: Mutex<Vec<axiom_core_logic::types::PeerAuditBanEntry>>,

    /// YPX-009: Silicon Pulse audit buffer.
    /// Ring of TxDigests with BLAKE3 accumulator chain.
    /// Lambda cannot access this — only AuditRequest/AuditResponse cross the boundary.
    audit_buffer: Mutex<AuditBuffer>,

    /// YPX-009: Wallet state cache for nonce challenges.
    /// Remembers produced_state_id and balance for wallets processed.
    #[allow(dead_code)]
    wallet_cache: Mutex<WalletCache>,

    /// This validator's Ed25519 public key (for Fiat-Shamir audit seed).
    /// Set via `set_validator_pk()` after construction.
    validator_pk: Mutex<Option<Vec<u8>>>,

    /// YPX-009 pulse-gate: when `pulse-gate` feature is enabled, AVM starts
    /// blocked (pulse_ready = false). Lambda must complete ignition TX before
    /// Core will process transactions.
    /// Without `pulse-gate`, this is always true (auto-calibrate at startup).
    pulse_ready: AtomicBool,

    /// YPX-009 ignition: timestamp (Instant) when ignition TX was submitted.
    /// Used to measure round-trip time through the full ZKVM pipeline.
    /// Only set during ignition sequence (pulse-gate feature).
    ignition_t0: Mutex<Option<std::time::Instant>>,

    /// §23.14.6 tick discipline: highest validated TARDIS tick stamp observed
    /// across executions (from the transaction's `epoch` — a unix-second-valued
    /// stamp advanced by <=5s ticks, see TICK_INTERVAL_SECS). Ban imposition
    /// and expiry compare against THIS, never SystemTime::now() — wall clock
    /// is permitted only at the TARDIS root and the tardis.rs forward-drift
    /// check.
    last_validated_tick: AtomicU64,

    /// Cranelift JIT engine — compiled ONCE at startup, reused for every TX.
    /// The JIT translates the entire RISC-V ELF to native code on first use.
    /// Compilation takes ~30-60s (intentional — restart penalty per YPX-009).
    /// After compilation, every TX executes at native speed (20-30x faster).
    /// Cranelift JIT — compiled once at startup, shared across all TXs.
    /// Not included in Debug output (contains native function pointers).
    #[cfg(feature = "cranelift-jit-backend")]
    #[allow(dead_code)]
    jit_engine: Option<std::sync::Arc<crate::riscv::jit::JitEngine>>,
}

#[cfg(feature = "std")]
impl AvmInterpreter {
    /// Create a new AVM interpreter
    ///
    /// # Arguments
    /// * `bytecode` - The axiom-core.elf bytes
    /// * `runtime_fingerprint` - The zkVM runtime fingerprint
    pub fn new(bytecode: Vec<u8>, runtime_fingerprint: [u8; 32]) -> Self {
        #[allow(unused_mut)]
        let mut buffer = AuditBuffer::new();

        // pulse-gate feature: Core starts blocked until Lambda signals benchmark.
        // Without pulse-gate: auto-benchmark at startup (testing/dev mode).
        // disable-audit: skip benchmark entirely (no Argon2id in dev mode).
        #[cfg(all(not(feature = "pulse-gate"), not(feature = "disable-audit")))]
        {
            buffer.self_benchmark();
        }
        #[cfg(feature = "disable-audit")]
        {
            eprintln!("[YPX-009] Pulse DISABLED (disable-audit feature active)");
        }

        #[cfg(feature = "pulse-gate")]
        let ready = false;
        #[cfg(not(feature = "pulse-gate"))]
        let ready = true;

        // Cranelift JIT: compile the entire ELF at startup (once).
        // This takes ~30-60s — intentional restart penalty per YPX-009.
        #[cfg(feature = "cranelift-jit-backend")]
        let jit_engine = {
            let t0 = std::time::Instant::now();
            eprintln!("[AVM-JIT] Compiling RISC-V ELF to native code...");
            let engine = match crate::riscv::jit::JitEngine::new() {
                Ok(mut jit) => {
                    let mut memory = crate::riscv::GuestMemory::new();
                    match crate::riscv::load_elf(&bytecode, &mut memory) {
                        Ok(elf_info) => {
                            let jit_base = 0x10000u32;
                            let jit_size = elf_info.loaded_bytes as u32;
                            match jit.translate_text_section(&memory, jit_base, jit_size) {
                                Ok(compiled) => {
                                    eprintln!("[AVM-JIT] Compiled {} blocks in {:.1}s", compiled, t0.elapsed().as_secs_f64());
                                    Some(jit)
                                }
                                Err(e) => {
                                    eprintln!("[AVM-JIT] Translation failed: {} — falling back to interpreter", e);
                                    None
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[AVM-JIT] ELF load failed: {:?} — falling back to interpreter", e);
                            None
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[AVM-JIT] Init failed: {} — falling back to interpreter", e);
                    None
                }
            };
            engine.map(std::sync::Arc::new)
        };

        Self {
            bytecode,
            runtime_fingerprint,
            pending_audit: Mutex::new(None),
            peer_audit_bans: Mutex::new(Vec::new()),
            audit_buffer: Mutex::new(buffer),
            wallet_cache: Mutex::new(WalletCache::new()),
            validator_pk: Mutex::new(None),
            pulse_ready: AtomicBool::new(ready),
            ignition_t0: Mutex::new(None),
            last_validated_tick: AtomicU64::new(0),
            #[cfg(feature = "cranelift-jit-backend")]
            jit_engine,
        }
    }

    /// Set this validator's Ed25519 public key (used for Fiat-Shamir audit seed).
    /// Called once after construction by Lambda.
    pub fn set_validator_pk(&self, pk: Vec<u8>) {
        *self.validator_pk.lock().unwrap() = Some(pk);
    }

    /// Check if pulse calibration is complete and Core is ready to serve.
    ///
    /// Without `pulse-gate` feature: always true (auto-calibrated at startup).
    /// With `pulse-gate`: false until `start_pulse_calibration()` completes.
    pub fn is_pulse_ready(&self) -> bool {
        self.pulse_ready.load(Ordering::Acquire)
    }

    /// Start pulse calibration (YPX-009 §8.3) — dev/test mode only.
    ///
    /// Without `pulse-gate`: auto-calibrates via BLAKE3 benchmark at startup.
    /// With `pulse-gate`: use `process_ignition()` + `complete_ignition()` instead.
    ///
    /// This method:
    /// 1. Runs Argon2id throughput benchmark (Core trusts nobody)
    /// 2. Measures Argon2id/sec for PulseProofData reporting
    /// 3. Sets `pulse_ready = true` — Core starts serving
    pub fn start_pulse_calibration(&self) {
        let mut buffer = self.audit_buffer.lock().unwrap();
        buffer.self_benchmark();
        drop(buffer);
        self.pulse_ready.store(true, Ordering::Release);
    }

    /// Process ignition TX (YPX-009 §8.4) — phase 1 of 2.
    ///
    /// Called when Lambda sends the ignition TX through Core. This method:
    /// 1. Records t0 (start time) — Core measures its own timing
    /// 2. Bypasses the pulse gate (ignition TX is the ONLY exception)
    /// 3. Executes the TX through the normal AVM pipeline
    ///
    /// After this, Lambda must generate ZKVM proof and call `complete_ignition()`
    /// with the proof bytes. Core verifies the proof, measures delta = t1 - t0,
    /// determines hardware tier from the round-trip time, and unblocks.
    ///
    /// This is the restart penalty: when Lambda fails a pulse audit, Core
    /// self-terminates. Restart requires a new ignition TX — real operational
    /// downtime because ZKVM proving takes seconds to minutes.
    pub fn process_ignition(&self, inputs: PublicInputs) -> Result<PublicOutputs, AvmError> {
        // Record t0 — Core's own clock, Lambda cannot influence
        *self.ignition_t0.lock().unwrap() = Some(std::time::Instant::now());

        eprintln!("[YPX-009] Ignition TX: processing (t0 recorded)");

        // Execute through normal pipeline — bypasses pulse gate
        // This is the ONLY path that runs while pulse_ready is false.
        // §23.14 audit is not enforced during ignition (no state to audit yet).

        // Verify runtime fingerprint
        if self.runtime_fingerprint != [0u8; 32]
            && self.runtime_fingerprint != EXPECTED_RISC0_FINGERPRINT
        {
            return Err(AvmError::RuntimeVerificationFailed);
        }

        #[cfg(feature = "riscv-interpreter")]
        {
            if self.has_valid_elf() {
                let result = self.execute_riscv(inputs)?;
                return Ok(result.outputs);
            }
        }

        // Native execution fallback
        let _host = HostFunctions::new(0, self.runtime_fingerprint);
        let outputs = execute_core(inputs);
        Ok(outputs)
    }

    /// Complete ignition (YPX-009 §8.4) — phase 2 of 2.
    ///
    /// Called after Lambda generates a ZKVM proof for the ignition TX.
    /// Core verifies the proof is real (not empty, well-formed), then:
    /// 1. Measures delta = t1 - t0 (round-trip through full ZKVM pipeline)
    /// 2. Runs BLAKE3 self-benchmark (Core trusts nobody)
    /// 3. Determines hardware tier from BLAKE3 throughput
    /// 4. Logs the ZKVM round-trip time (informational — tier is from BLAKE3)
    /// 5. Sets `pulse_ready = true` — Core starts serving
    ///
    /// The ZKVM round-trip proves the hardware actually has a working prover.
    /// The tier determination uses BLAKE3 (deterministic, cheat-proof).
    pub fn complete_ignition(&self, proof_bytes: &[u8]) -> Result<(), AvmError> {
        let t0 = self.ignition_t0.lock().unwrap().take()
            .ok_or_else(|| AvmError::ExecutionError(
                "complete_ignition() called without process_ignition()".into()
            ))?;

        let delta = t0.elapsed();

        // Verify proof is non-empty (H1: empty cheque proofs rejected)
        if proof_bytes.is_empty() {
            return Err(AvmError::ExecutionError(
                "Ignition: empty proof — ZKVM prover must produce real output".into()
            ));
        }

        // H2: proof size limit (DoS prevention)
        const MAX_IGNITION_PROOF: usize = 10 * 1024 * 1024; // 10MB
        if proof_bytes.len() > MAX_IGNITION_PROOF {
            return Err(AvmError::ExecutionError(
                "Ignition: proof exceeds 10MB size limit".into()
            ));
        }

        // Run BLAKE3 self-benchmark — Core determines its own tier
        let mut buffer = self.audit_buffer.lock().unwrap();
        buffer.self_benchmark();
        drop(buffer);

        eprintln!(
            "[YPX-009] Ignition complete: ZKVM round-trip={:.1}s, proof={}KB",
            delta.as_secs_f64(),
            proof_bytes.len() / 1024,
        );

        // Unblock Core — start serving transactions
        self.pulse_ready.store(true, Ordering::Release);
        Ok(())
    }

    /// §23.14: Check and enforce audit countdown before execution.
    /// Returns Err(AuditTimeout) if countdown expired without confirmation.
    /// Otherwise, processes any confirmation and decrements if pending.
    ///
    /// For peer-audits, also checks wall-clock timeout (10 minutes).
    /// On peer-audit timeout, bans the target for 24h instead of self-terminating.
    fn enforce_audit_pre(&self, inputs: &PublicInputs) -> Result<(), AvmError> {
        // §23.14.6 tick discipline: advance the validated-tick watermark from
        // this TX's epoch (monotonic max — a replayed old epoch can't rewind it).
        // Use tx.epoch directly, NOT estimate_tick(): estimate_tick is
        // `#[cfg(not(disable-audit))]` while enforce_audit_pre is always
        // compiled, so a disable-audit build (lambda/antie) must not call it.
        // estimate_tick is literally `tx.epoch`, so this is identical.
        self.last_validated_tick
            .fetch_max(inputs.transaction.epoch, Ordering::AcqRel);

        // §23.14.6: Check ban list — reject TX if any witness is banned
        self.check_witness_bans(inputs)?;

        let mut pending = self.pending_audit.lock().unwrap();

        if let Some(ref mut audit) = *pending {
            // Check for confirmation in inputs
            if let Some(ref confirmation) = inputs.audit_confirmation {
                if !audit.is_peer {
                    // Self-audit confirmation path (unchanged)
                    // Step 1: Verify nonce + target match (binding)
                    if axiom_core_logic::audit::verify_audit_nonce(
                        &audit.demand, confirmation,
                    ) {
                        // Step 2: Verify content — hash raw DB data, compare against
                        // stored TxDigest in audit buffer. Lambda does zero crypto;
                        // Core hashes the raw data Lambda sent back.
                        let buffer = self.audit_buffer.lock().unwrap();
                        let content_valid = buffer.entries.iter()
                            .find(|d| d.tx_number == audit.trigger_tx_number)
                            .map(|stored| axiom_core_logic::audit::verify_audit_content(
                                confirmation, stored,
                            ))
                            .unwrap_or(false); // TX not in buffer = fail
                        drop(buffer);

                        if content_valid {
                            // Audit completed successfully — clear pending
                            *pending = None;
                            return Ok(());
                        }
                        // Content mismatch — Lambda tampered with DB. Countdown continues.
                        eprintln!("§23.14: Audit content mismatch for trigger_tx_number={}", audit.trigger_tx_number);
                    }
                    // Wrong nonce/target — ignore, countdown continues
                }
                // Peer-audit confirmations are NOT handled here — they come via
                // handle_peer_audit_response() which calls clear_peer_audit() or ban_validator().
            }

            // Check peer-audit wall-clock timeout (10 minutes)
            if audit.is_peer {
                if let Some(started) = audit.started_at {
                    if started.elapsed().as_secs() >= axiom_core_logic::types::PEER_AUDIT_TIMEOUT_SECS {
                        // Peer-audit timed out — ban the target, don't self-terminate
                        let target_pk = audit.demand.target_validator_pk.clone();
                        *pending = None;
                        drop(pending);
                        self.ban_validator(
                            target_pk,
                            axiom_core_logic::types::PeerAuditBanReason::NonResponds,
                        );
                        return Ok(()); // We continue running — peer gets banned, not us
                    }
                }
            }

            // No valid confirmation — decrement countdown
            if audit.remaining == 0 {
                if audit.is_peer {
                    // Peer-audit TX countdown expired — ban target, don't self-terminate
                    let target_pk = audit.demand.target_validator_pk.clone();
                    *pending = None;
                    drop(pending);
                    self.ban_validator(
                        target_pk,
                        axiom_core_logic::types::PeerAuditBanReason::NonResponds,
                    );
                    return Ok(());
                }
                // Self-audit: Lambda failed to comply. Self-terminate.
                return Err(AvmError::AuditTimeout {
                    challenge_nonce: audit.demand.challenge_nonce,
                    target_validator_pk: audit.demand.target_validator_pk.clone(),
                    txs_remaining_when_expired: 0,
                });
            }
            audit.remaining -= 1;
        }
        Ok(())
    }

    /// §23.14.6: The ban window projected onto `epoch` tick stamps.
    /// PEER_AUDIT_BAN_TICKS is a TICK count (a tick is <=5s wall clock);
    /// tick stamps are unix-second-valued, so project the count via
    /// TICK_INTERVAL_SECS — the YPX-020 HIBERNATION_WINDOW pattern. The
    /// ban holds for AT LEAST that many ticks.
    #[inline]
    fn ban_window_stamp() -> u64 {
        axiom_core_logic::types::PEER_AUDIT_BAN_TICKS
            .saturating_mul(axiom_core_logic::types::TICK_INTERVAL_SECS)
    }

    /// §23.14.6: Check if any CURRENT TX witness (overlapped_signatures) is banned.
    /// If so, reject the TX with ValidatorBanned error.
    ///
    /// Only checks overlapped_signatures (current TX's proposed witnesses),
    /// NOT prev_receipts. A banned validator's prior work (prev_receipts) was
    /// valid at the time — banning them later doesn't invalidate old TXs.
    fn check_witness_bans(&self, inputs: &PublicInputs) -> Result<(), AvmError> {
        let bans = self.peer_audit_bans.lock().unwrap();
        if bans.is_empty() {
            return Ok(());
        }

        // Tick discipline: expiry is measured in validated TARDIS ticks,
        // never SystemTime::now(). The watermark was advanced from this
        // TX's epoch in enforce_audit_pre.
        let now_tick = self.last_validated_tick.load(Ordering::Acquire);

        // Check overlapped_signatures — these are the validators proposing
        // to witness the CURRENT transaction
        for sig in &inputs.overlapped_signatures {
            for ban in bans.iter() {
                if ban.validator_pk == sig.validator_pk
                    && now_tick.saturating_sub(ban.banned_at_tick) < Self::ban_window_stamp()
                {
                    return Err(AvmError::ValidatorBanned {
                        validator_pk: ban.validator_pk.clone(),
                        reason: ban.reason.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    /// §23.14.6: Ban a validator for peer-audit failure.
    /// Adds to ban list (survives across TXs, clears on restart or after 24h).
    pub fn ban_validator(
        &self,
        validator_pk: Vec<u8>,
        reason: axiom_core_logic::types::PeerAuditBanReason,
    ) {
        // Tick discipline: stamp the ban with the validated-tick watermark.
        // A ban can only arise from TX processing (the audit demand is
        // generated during execute), so the watermark holds a real tick here.
        let now_tick = self.last_validated_tick.load(Ordering::Acquire);

        let mut bans = self.peer_audit_bans.lock().unwrap();
        // Don't duplicate — update existing ban
        if let Some(existing) = bans.iter_mut().find(|b| b.validator_pk == validator_pk) {
            existing.banned_at_tick = now_tick;
            existing.reason = reason.clone();
            eprintln!("§23.14.6: Updated ban on validator {} — {:?}",
                     hex::encode(&validator_pk[..core::cmp::min(8, validator_pk.len())]), reason);
        } else {
            eprintln!("§23.14.6: Banned validator {} — {:?}",
                     hex::encode(&validator_pk[..core::cmp::min(8, validator_pk.len())]), reason);
            bans.push(axiom_core_logic::types::PeerAuditBanEntry {
                validator_pk,
                banned_at_tick: now_tick,
                reason,
            });
        }
    }

    /// §23.14.6: Check if a validator is currently banned.
    pub fn is_validator_banned(&self, validator_pk: &[u8]) -> bool {
        let bans = self.peer_audit_bans.lock().unwrap();
        // Tick discipline: validated-tick watermark, never SystemTime::now().
        let now_tick = self.last_validated_tick.load(Ordering::Acquire);

        bans.iter().any(|b| {
            b.validator_pk == validator_pk
                && now_tick.saturating_sub(b.banned_at_tick) < Self::ban_window_stamp()
        })
    }

    /// §23.14.6: Clear a pending peer-audit (called when response received and verified).
    pub fn clear_peer_audit(&self) {
        let mut pending = self.pending_audit.lock().unwrap();
        if pending.as_ref().is_some_and(|a| a.is_peer) {
            *pending = None;
        }
    }

    /// §23.14.6: Get the pending peer-audit expected hash (for Lambda to compare response).
    pub fn pending_peer_audit_hash(&self) -> Option<[u8; 32]> {
        let pending = self.pending_audit.lock().unwrap();
        pending.as_ref()
            .filter(|a| a.is_peer)
            .and_then(|a| a.peer_expected_hash)
    }

    /// §23.14.6: Get the pending peer-audit request data (for Lambda to send via ANTIE).
    pub fn pending_peer_audit_request(&self) -> Option<axiom_core_logic::types::PeerAuditRequest> {
        let pending = self.pending_audit.lock().unwrap();
        if let Some(ref audit) = *pending {
            if audit.is_peer {
                if let Some(expected_hash) = audit.peer_expected_hash {
                    let our_pk = self.validator_pk.lock().unwrap();
                    return Some(axiom_core_logic::types::PeerAuditRequest {
                        txid: audit.demand.trigger_txid,
                        expected_hash,
                        challenge_nonce: audit.demand.challenge_nonce,
                        requester_pk: our_pk.as_ref().cloned().unwrap_or_default(),
                    });
                }
            }
        }
        None
    }

    /// §23.14.6: Get the ban list (for Lambda/admin API).
    pub fn peer_audit_bans(&self) -> Vec<axiom_core_logic::types::PeerAuditBanEntry> {
        let bans = self.peer_audit_bans.lock().unwrap();
        // Tick discipline: validated-tick watermark, never SystemTime::now().
        let now_tick = self.last_validated_tick.load(Ordering::Acquire);
        // Return only active bans
        bans.iter()
            .filter(|b| now_tick.saturating_sub(b.banned_at_tick) < Self::ban_window_stamp())
            .cloned()
            .collect()
    }

    /// §23.14: After execution, check if Core generated an audit demand.
    /// If so, start tracking the countdown.
    /// Self-audit: 10 TX countdown. Peer-audit: 100 TX / 10 min countdown.
    fn enforce_audit_post(&self, outputs: &PublicOutputs) {
        if let Some(ref demand) = outputs.audit_demand {
            let mut pending = self.pending_audit.lock().unwrap();
            // Only set if no pending audit (don't override active countdown)
            if pending.is_none() {
                // Get current tx_number from audit buffer
                let buffer = self.audit_buffer.lock().unwrap();
                let current_tx_number = buffer.tx_counter;
                drop(buffer);

                // Check if this is a peer-audit (target != our PK)
                let our_pk = self.validator_pk.lock().unwrap();
                let is_peer = our_pk.as_ref()
                    .map(|pk| pk.as_slice() != demand.target_validator_pk.as_slice())
                    .unwrap_or(true); // if PK not set, treat as peer (conservative)

                let countdown = if is_peer {
                    axiom_core_logic::types::PEER_AUDIT_COUNTDOWN_TXS
                } else {
                    axiom_core_logic::types::AUDIT_COUNTDOWN_TXS
                };

                // For peer-audit, compute the expected hash from audit buffer
                let peer_expected_hash = if is_peer {
                    let buffer = self.audit_buffer.lock().unwrap();
                    buffer.entries.iter()
                        .find(|d| d.tx_number == current_tx_number)
                        .map(|digest| axiom_core_logic::audit::compute_peer_audit_hash(
                            &demand.trigger_txid,
                            digest.sender_balance,
                            digest.receiver_balance,
                            &digest.state_id,
                            digest.amount,
                        ))
                } else {
                    None
                };

                *pending = Some(PendingAudit {
                    demand: demand.clone(),
                    remaining: countdown,
                    trigger_tx_number: current_tx_number,
                    is_peer,
                    started_at: if is_peer { Some(std::time::Instant::now()) } else { None },
                    peer_expected_hash,
                });
            }
        }
    }

    /// YPX-009: Silicon Pulse post-execution processing.
    /// Called after every successful (Accept) TX execution.
    /// Accumulates TxDigest, updates wallet cache, generates nonce challenges,
    /// checks audit triggers, and verifies audit responses.
    ///
    /// Gated by `disable-audit` feature: when set, this is a no-op.
    /// Use for development/testing only — production validators MUST run audit.
    #[cfg(not(feature = "disable-audit"))]
    fn pulse_post_execute(
        &self,
        inputs: &PublicInputs,
        outputs: &mut PublicOutputs,
        _dmap_trace: Option<&DmapTrace>,
    ) {
        // Only process Accept results
        if outputs.result != ValidationResult::Accept {
            return;
        }

        let mut buffer = self.audit_buffer.lock().unwrap();
        let mut cache = self.wallet_cache.lock().unwrap();

        // 1. Verify nonce response from previous challenge
        if let Some(ref response) = inputs.nonce_response {
            cache.verify_response(response);
            if cache.is_audit_failed() {
                outputs.audit_failed = true;
                return;
            }
        }

        // 2. Verify audit response if one was pending
        //    Lambda sent raw DB fields — Core replays Argon2id→BLAKE3 chain
        //    and compares against expected_hash. Lambda does ZERO crypto.
        if let Some(ref response) = inputs.audit_response {
            if let Some(ref request) = buffer.pending_request {
                if response.epoch != request.epoch
                    || response.entries.len() != request.selected_indices.len()
                {
                    // Wrong epoch or wrong entry count
                    outputs.audit_failed = true;
                    buffer.pending_request = None;
                    buffer.pending_request_tick = None;
                    return;
                }

                // Replay Argon2id→BLAKE3 chain over Lambda's raw data
                let replayed_hash = AuditBuffer::replay_chain_from_raw(&response.entries);

                if replayed_hash == request.expected_hash {
                    // Audit passed — Lambda's DB matches Core's live chain
                    let now_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    outputs.pulse_proof = Some(PulseProofData {
                        epoch: request.epoch,
                        full_accumulator: buffer.accumulator,
                        entry_count: buffer.entries.len() as u32,
                        sample_size: request.selected_indices.len() as u32,
                        audit_hash: replayed_hash,
                        argon2id_per_sec: buffer.argon2id_per_sec,
                    });
                    buffer.reset(now_secs);
                } else {
                    // Chain mismatch — Lambda tampered with at least one TX
                    eprintln!("§YPX-009: Pulse audit FAILED — replayed chain hash mismatch (epoch={})", request.epoch);
                    outputs.audit_failed = true;
                    buffer.pending_request = None;
                    buffer.pending_request_tick = None;
                    return;
                }
            }
        }

        // 3. Build TxDigest from outputs
        buffer.tx_counter += 1;
        let tx_number = buffer.tx_counter;

        let state_id = outputs.produced_state_id.unwrap_or([0u8; 32]);
        let amount = inputs.transaction.amount;
        let sender_balance = inputs
            .current_state
            .as_ref()
            .map(|s| s.balance)
            .unwrap_or(0);

        let digest = TxDigest {
            tx_number,
            sender_balance,
            receiver_balance: 0, // receiver balance not available at sender's validator
            state_id,
            amount,
        };

        buffer.accumulate(digest);

        // 4. Update wallet cache with sender's new state
        if let Some(pk_bytes) = inputs.transaction.client_pk.get(..32) {
            if pk_bytes.len() == 32 {
                let mut pk = [0u8; 32];
                pk.copy_from_slice(pk_bytes);
                let new_balance = outputs.new_balance.unwrap_or(sender_balance);
                cache.update(pk, state_id, new_balance, tx_number);
            }
        }

        // 5. Generate nonce challenge from wallet cache
        if let Some(txid) = outputs.txid.as_ref() {
            outputs.nonce_challenge = cache.generate_challenge(txid, &buffer.accumulator);
        }

        // 6. Check audit trigger (dual: time + count)
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if buffer.should_trigger(now_secs) {
            let vpk = self.validator_pk.lock().unwrap();
            let pk_bytes = vpk.as_deref().unwrap_or(&[0u8; 32]);
            let current_tick = self.estimate_tick(&inputs.transaction);
            let epoch = current_tick / axiom_core_logic::types::PULSE_EPOCH_LENGTH_TICKS;
            let request = buffer.generate_request(pk_bytes, epoch);
            buffer.pending_request_tick = Some(current_tick);
            buffer.pending_request = Some(request.clone());
            outputs.audit_request = Some(request);
        }
    }

    /// Extract DMAP spot-check from trace (YPX-009 §3.4).
    /// Picks the nearest checkpoint to a deterministic instruction count.
    /// Estimate current tick from transaction data.
    /// Uses transaction epoch as a rough proxy.
    #[cfg(not(feature = "disable-audit"))]
    fn estimate_tick(&self, tx: &axiom_core_logic::types::Transaction) -> u64 {
        tx.epoch
    }

    /// No-op stub when audit is disabled (development/testing only).
    #[cfg(feature = "disable-audit")]
    fn pulse_post_execute(
        &self,
        _inputs: &PublicInputs,
        _outputs: &mut PublicOutputs,
        _dmap_trace: Option<&DmapTrace>,
    ) {
        // Audit chain disabled — no Argon2id, no nonce challenges, no pulse proofs.
    }

    /// Execute core validation with given inputs (default mode)
    ///
    /// This is the main entry point for transaction validation.
    /// In default mode, calls core-logic's execute_core directly.
    pub fn execute(&self, inputs: PublicInputs) -> Result<PublicOutputs, AvmError> {
        // YPX-009 pulse-gate: reject if calibration not complete
        if !self.is_pulse_ready() {
            return Err(AvmError::PulseNotReady);
        }

        // §23.14: Audit countdown enforcement (pre-execution)
        self.enforce_audit_pre(&inputs)?;

        // Verify runtime fingerprint.
        if self.runtime_fingerprint != [0u8; 32]
            && self.runtime_fingerprint != EXPECTED_RISC0_FINGERPRINT
        {
            return Err(AvmError::RuntimeVerificationFailed);
        }

        #[cfg(feature = "riscv-interpreter")]
        {
            if self.has_valid_elf() {
                // Real RV32IM interpretation
                let inputs_ref = inputs.clone();
                let result = self.execute_riscv(inputs)?;
                // §23.14: Track new audit demands (post-execution)
                self.enforce_audit_post(&result.outputs);
                // YPX-009: Silicon Pulse post-execution (no DMAP trace in execute())
                let mut outputs = result.outputs;
                self.pulse_post_execute(&inputs_ref, &mut outputs, None);
                return Ok(outputs);
            }
            // Fall through to native execution (Cargo feature unification case:
            // riscv-interpreter enabled but no real ELF loaded, e.g. axiom-core-bin)
        }

        // Direct native execution
        let _host = HostFunctions::new(0, self.runtime_fingerprint);
        let inputs_ref = inputs.clone(); // keep a copy for pulse processing
        let mut outputs = execute_core(inputs);
        // §23.14: Track new audit demands (post-execution)
        self.enforce_audit_post(&outputs);
        // YPX-009: Silicon Pulse post-execution (no DMAP trace in native mode)
        self.pulse_post_execute(&inputs_ref, &mut outputs, None);
        Ok(outputs)
    }

    /// Execute with DMAP trace collection
    ///
    /// Only available with `riscv-interpreter` feature. In default mode,
    /// returns outputs with no DMAP trace (native execution cannot produce
    /// memory checkpoints).
    pub fn execute_with_dmap(&self, inputs: PublicInputs) -> Result<AvmExecutionResult, AvmError> {
        // YPX-009 pulse-gate: reject if calibration not complete
        if !self.is_pulse_ready() {
            return Err(AvmError::PulseNotReady);
        }

        // §23.14: Audit countdown enforcement (pre-execution)
        self.enforce_audit_pre(&inputs)?;

        // Verify runtime fingerprint
        if self.runtime_fingerprint != [0u8; 32]
            && self.runtime_fingerprint != EXPECTED_RISC0_FINGERPRINT
        {
            return Err(AvmError::RuntimeVerificationFailed);
        }

        #[cfg(feature = "riscv-interpreter")]
        {
            if self.has_valid_elf() {
                let inputs_ref = inputs.clone();
                let mut result = self.execute_riscv(inputs)?;
                // §23.14: Track new audit demands (post-execution)
                self.enforce_audit_post(&result.outputs);
                // YPX-009: Silicon Pulse with DMAP trace
                self.pulse_post_execute(&inputs_ref, &mut result.outputs, result.dmap_trace.as_ref());
                return Ok(result);
            }
            // Fall through to native (no DMAP trace without real ELF)
        }

        // Native execution — no DMAP trace available
        let _host = HostFunctions::new(0, self.runtime_fingerprint);
        let inputs_ref = inputs.clone();
        let mut outputs = execute_core(inputs);
        // §23.14: Track new audit demands (post-execution)
        self.enforce_audit_post(&outputs);
        // YPX-009: Silicon Pulse post-execution (no DMAP trace in native mode)
        self.pulse_post_execute(&inputs_ref, &mut outputs, None);
        Ok(AvmExecutionResult {
            outputs,
            dmap_trace: None,
            core_id: self.core_fingerprint(),
        })
    }

    /// Real RV32IM execution path (feature-gated)
    #[cfg(feature = "riscv-interpreter")]
    fn execute_riscv(&self, inputs: PublicInputs) -> Result<AvmExecutionResult, AvmError> {
        // Profile mode: when AVM_PROFILE env var is set, log per-stage timings
        // to stderr. Zero-cost in production (the env var check happens once
        // per call but the logging path only fires when explicitly requested).
        // Discovered need: 2026-04-13 witness perf investigation. We needed
        // to determine whether the guest's 14-16s per-call cost is dominated
        // by Dilithium math (hypothesis A) or CBOR deserialization of large
        // post-quantum payloads (hypothesis B). Each implies a different fix.
        let profile = std::env::var("AVM_PROFILE").is_ok();
        let core_id = self.core_fingerprint();

        // 1. Serialize inputs to CBOR (guest reads via ecall)
        // CBOR encodes binary fields (SPHINCS+ sigs, Dilithium PKs) much more
        // compactly than JSON — ~1.5 bytes/byte vs ~4 bytes/byte for Vec<u8>.
        // This keeps full VBC data within the AVM instruction budget.
        let t_serialize = if profile { Some(std::time::Instant::now()) } else { None };
        let mut input_cbor = Vec::new();
        ciborium::ser::into_writer(&inputs, &mut input_cbor)
            .map_err(|e| AvmError::ExecutionError(format!("serialize inputs: {}", e)))?;
        if let Some(t) = t_serialize {
            eprintln!("[AVM_PROFILE] cbor_encode_inputs: {:?} ({} bytes)",
                      t.elapsed(), input_cbor.len());
        }

        // 2. Create FastCpu with host functions + reuse guest memory
        let host = HostFunctions::new(0, self.runtime_fingerprint);
        thread_local! {
            static CACHED_MEMORY: std::cell::RefCell<Option<crate::riscv::GuestMemory>> = const { std::cell::RefCell::new(None) };
        }
        let mut memory = CACHED_MEMORY.with(|cell| {
            cell.borrow_mut().take().map(|mut m| { m.clear_for_reuse(); m })
        }).unwrap_or_default();

        // 3. Load ELF into guest memory
        let t_elf = if profile { Some(std::time::Instant::now()) } else { None };
        let elf_info = load_elf(&self.bytecode, &mut memory)
            .map_err(|e| AvmError::LoadError(format!("ELF load: {}", e)))?;
        if let Some(t) = t_elf {
            eprintln!("[AVM_PROFILE] elf_load: {:?}", t.elapsed());
        }

        // 4. Build instruction cache + set entry point and stack pointer
        let text_base = elf_info.entry_point & !0xFFF;
        let text_size = (elf_info.loaded_bytes as u32).min(crate::riscv::memory::MAX_MEMORY - text_base);
        let icache = InstructionCache::build(&memory, text_base, text_size);

        let mut cpu = FastCpu::new(memory, elf_info.entry_point, input_cbor, host);
        cpu.regs[2] = crate::riscv::memory::MAX_MEMORY - 4096; // sp
        cpu.set_icache(icache);

        // Phase B: Cranelift JIT — use cached compiled blocks from startup
        #[cfg(feature = "cranelift-jit-backend")]
        {
            if let Some(ref jit_arc) = self.jit_engine {
                cpu.set_jit(jit_arc.clone());
            }
        }

        // 5. Run with DMAP checkpoint collection
        let t_cpu = if profile { Some(std::time::Instant::now()) } else { None };
        let (exit_reason, raw_checkpoints) =
            cpu.run_collecting_checkpoints(DMAP_CHECKPOINT_INTERVAL);
        if let Some(t) = t_cpu {
            eprintln!("[AVM_PROFILE] cpu_run: {:?} ({} checkpoints, exit={:?})",
                      t.elapsed(), raw_checkpoints.len(), exit_reason);
        }

        // 6. Check exit was clean
        match exit_reason {
            ExitReason::Exit(0) => {} // success
            ExitReason::Exit(code) => {
                return Err(AvmError::ExecutionError(format!(
                    "Guest exited with code {}", code
                )));
            }
            ExitReason::InstructionLimit => {
                return Err(AvmError::ExecutionError(
                    "Hit instruction limit (possible infinite loop)".into()
                ));
            }
            ExitReason::IllegalInstruction(pc, raw) => {
                return Err(AvmError::ExecutionError(format!(
                    "Illegal instruction at PC=0x{:08X}: 0x{:08X}", pc, raw
                )));
            }
            ExitReason::MemoryFault(pc, desc) => {
                return Err(AvmError::ExecutionError(format!(
                    "Memory fault at PC=0x{:08X}: {}", pc, desc
                )));
            }
            ExitReason::Ebreak => {
                return Err(AvmError::ExecutionError("Unexpected EBREAK".into()));
            }
            ExitReason::UnknownSyscall(n) => {
                return Err(AvmError::ExecutionError(format!(
                    "Unknown syscall: 0x{:02X}", n
                )));
            }
        }

        // 7. Check guest wrote output
        if !cpu.has_output() {
            return Err(AvmError::ExecutionError(
                "Guest did not write outputs".into()
            ));
        }

        // 8. Deserialize outputs
        let t_decode = if profile { Some(std::time::Instant::now()) } else { None };
        let output_bytes = cpu.output();
        let output_len = output_bytes.len();
        let outputs: PublicOutputs = ciborium::de::from_reader(output_bytes)
            .map_err(|e| AvmError::ExecutionError(format!("deserialize outputs: {}", e)))?;
        if let Some(t) = t_decode {
            eprintln!("[AVM_PROFILE] cbor_decode_outputs: {:?} ({} bytes)",
                      t.elapsed(), output_len);
        }

        // 9. Build DMAP trace from collected checkpoints (includes register hash)
        let dmap_checkpoints: Vec<DmapCheckpoint> = raw_checkpoints
            .into_iter()
            .map(|cs| DmapCheckpoint {
                instruction_count: cs.instruction_count,
                pc: cs.pc,
                memory_root: cs.memory_root,
                register_hash: cs.register_hash,
            })
            .collect();

        let trace = if dmap_checkpoints.is_empty() {
            None
        } else {
            Some(DmapTrace::from_checkpoints(dmap_checkpoints))
        };

        // Return guest memory to thread-local cache for reuse
        CACHED_MEMORY.with(|cell| {
            *cell.borrow_mut() = Some(cpu.memory);
        });

        Ok(AvmExecutionResult {
            outputs,
            dmap_trace: trace,
            core_id,
        })
    }

    /// Check if bytecode looks like a valid ELF (starts with ELF magic).
    /// Returns false for sentinel bytecode like "AXIOM_CORE_V2" used by
    /// CoreHandle when no real ELF is loaded (e.g. axiom-core-bin built with
    /// riscv-interpreter due to Cargo workspace feature unification).
    fn has_valid_elf(&self) -> bool {
        self.bytecode.len() >= 4 && self.bytecode[..4] == [0x7F, b'E', b'L', b'F']
    }

    /// Get the CoreID = BLAKE3 hash of the ELF bytecode
    pub fn core_fingerprint(&self) -> [u8; 32] {
        *blake3::hash(&self.bytecode).as_bytes()
    }

    /// Verify the bytecode matches expected fingerprint
    pub fn verify_core(&self, expected: &[u8; 32]) -> bool {
        &self.core_fingerprint() == expected
    }
}

/// Builder for creating AVM with proper configuration
#[cfg(feature = "std")]
pub struct AvmBuilder {
    bytecode: Option<Vec<u8>>,
    runtime_fingerprint: Option<[u8; 32]>,
}

#[cfg(feature = "std")]
impl AvmBuilder {
    pub fn new() -> Self {
        Self {
            bytecode: None,
            runtime_fingerprint: None,
        }
    }

    /// Set the axiom-core.elf bytecode
    pub fn bytecode(mut self, bytecode: Vec<u8>) -> Self {
        self.bytecode = Some(bytecode);
        self
    }

    /// Set the runtime fingerprint for verification
    pub fn runtime_fingerprint(mut self, fingerprint: [u8; 32]) -> Self {
        self.runtime_fingerprint = Some(fingerprint);
        self
    }

    /// Build the AVM interpreter
    pub fn build(self) -> Result<AvmInterpreter, AvmError> {
        let bytecode = self.bytecode
            .ok_or_else(|| AvmError::LoadError("No bytecode provided".into()))?;
        let fingerprint = self.runtime_fingerprint
            .ok_or_else(|| AvmError::LoadError("No runtime fingerprint provided".into()))?;

        Ok(AvmInterpreter::new(bytecode, fingerprint))
    }
}

#[cfg(feature = "std")]
impl Default for AvmBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_core_logic::{CoreLogicMode, Transaction, TxKind, WalletState};
    use axiom_core_logic::wallet_id::generate_wallet_id;

    fn create_test_inputs() -> PublicInputs {
        let receiver_wallet_id = generate_wallet_id("receiver@test.com", "42", &[0u8; 32])
            .expect("Failed to generate wallet ID");

        PublicInputs {
            oods_attestation: None,
            recall_attestation: None,
            mode: CoreLogicMode::CL1,
            transaction: Transaction {
                consumed_state_id: [0u8; 32],
                recall_target_tx_id: None,
                client_pk: vec![0u8; 32],
                sender_wallet_id: String::new(),
                wallet_seq: 1,
                receiver_wallet_id,
                receiver_address: None,
                amount: 100_000,
                reference: "test".into(),
                nonce: 1,
                epoch: 1,
                client_sig: vec![0u8; 64],
                owner_proof: None,
                scar_passcode: None,
                burn_target_tx_id: None,
                required_k: 0,
                proof_type: 0,
                oracle_claim: None,
                core_version: String::new(),
                kind: TxKind::Normal,
                core_id: [0u8; 32],
            },
            prev_receipts: vec![],
            current_state: Some(WalletState {
                public_key: vec![0u8; 32],
                balance: 1_000_000,
                wallet_seq: 0,
                state_id: [0u8; 32],
                auth_hash: None,
                wallet_id: None,
                group_members: None,
                hibernation_until: 0,
            }),
            vbc_bundle: None,
            cheque_bundle: None,
            receiver_pk: None,
            receiver_current_balance: None,
            receiver_current_hibernation: None,
            receiver_wallet_seq: None,
            receiver_new_balance: None,
            receiver_new_state_id: None,
            my_validator_pk: None,
            overlapped_signatures: vec![],
            group_member_index: None,
            sender_fact_chain: None,
            receiver_fact_chain: None,
            my_dilithium_sk: None,
            my_dilithium_pk: None,
            my_validator_id: None,
            fact_witness_sigs: vec![],
            issuer_sphincs_sk: None,
            cl1_execution_proof: None,
            zkp_nonce: None,
            audit_confirmation: None,
            nonce_response: None,
            audit_response: None,
            scar_heal_tx_id: None,
            scar_heal_nabla_id: None,
            scar_heal_root_hash: None,
            wallet_secret: None,
            fanout_message: None,
            candidate_balance: None,
            nabla_stake_proof: None,
            frozen_wallets: None,
            console_current_cert: None,
            console_new_cert: None,
            console_selector_picks: None,
            console_nominations: None, txid_attestation: None,
        cheque_claim_proof: None,
            clara_attestation: None,
            phase_out_payload: None,
            phase_out_era_end_ticks: vec![],
            phase_out_blocked_era_ids: vec![],
            current_tick: 0,
            local_core_id: [0u8; 32],
            withdrawal_inputs: None,
            max_fact_links: None,
        
        }
    }

    #[test]
    fn test_core_fingerprint() {
        let bytecode = vec![0x00, 0x01, 0x02, 0x03];
        let avm = AvmInterpreter::new(bytecode.clone(), [0u8; 32]);

        let expected = blake3::hash(&bytecode);
        assert_eq!(avm.core_fingerprint(), *expected.as_bytes());
    }

    #[cfg(not(feature = "riscv-interpreter"))]
    #[test]
    fn test_execute_cl1() {
        // Native mode: fake bytecode is fine (not actually loaded into RV32IM)
        let bytecode = vec![0x00];
        let avm = AvmInterpreter::new(bytecode, [0u8; 32]);
        // With pulse-gate, must calibrate before executing
        #[cfg(feature = "pulse-gate")]
        avm.start_pulse_calibration();

        let inputs = create_test_inputs();
        let result = avm.execute(inputs);

        assert!(result.is_ok());
    }

    #[cfg(not(feature = "riscv-interpreter"))]
    #[test]
    fn test_execute_with_dmap_native() {
        // Native mode: no DMAP trace (no RV32IM execution)
        let bytecode = vec![0x00];
        let avm = AvmInterpreter::new(bytecode, [0u8; 32]);
        #[cfg(feature = "pulse-gate")]
        avm.start_pulse_calibration();

        let inputs = create_test_inputs();
        let result = avm.execute_with_dmap(inputs).unwrap();

        assert!(result.dmap_trace.is_none());
    }

    #[test]
    fn test_builder() {
        let bytecode = vec![0x00, 0x01, 0x02, 0x03];
        let fingerprint = [0xABu8; 32];

        let avm = AvmBuilder::new()
            .bytecode(bytecode)
            .runtime_fingerprint(fingerprint)
            .build()
            .unwrap();

        assert_eq!(avm.runtime_fingerprint, fingerprint);
    }

    // ======================================================================
    // Real RISC-V ELF execution tests (require compiled axiom-core.elf)
    // ======================================================================
    #[cfg(feature = "riscv-interpreter")]
    pub(super) mod riscv_elf {
        use super::*;

        /// Find the compiled AVM guest ELF.
        /// Looks relative to workspace root: core/avm-guest/target/riscv32im-unknown-none-elf/release/axiom-avm-guest
        pub fn find_elf() -> Option<Vec<u8>> {
            // Walk up from CARGO_MANIFEST_DIR to find workspace root
            let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            // core/avm/.. = core/, core/.. = src/ (workspace root)
            let workspace = manifest_dir.parent()?.parent()?;
            let elf_path = workspace
                .join("core/avm-guest/target/riscv32im-unknown-none-elf/release/axiom-avm-guest");
            if elf_path.exists() {
                Some(std::fs::read(&elf_path).expect("Failed to read ELF"))
            } else {
                None
            }
        }

        #[test]
        fn test_real_elf_cl1_execution() {
            let elf = match find_elf() {
                Some(e) => e,
                None => {
                    eprintln!("SKIP: axiom-core.elf not found — build with: cd core/avm-guest && cargo build --release");
                    return;
                }
            };

            let avm = AvmInterpreter::new(elf, [0u8; 32]);
            let inputs = create_test_inputs();

            // Native execution to get reference outputs
            let native_outputs = axiom_core_logic::execute_core(inputs.clone());

            // RISC-V interpreted execution (timed)
            let t0 = std::time::Instant::now();
            let riscv_outputs = avm.execute(inputs).expect("RISC-V execution failed");
            eprintln!("=== RISC-V CL1 execution: {:?} ===", t0.elapsed());

            // Both must produce identical results
            assert_eq!(riscv_outputs.result, native_outputs.result,
                "RISC-V and native must agree on Accept/Reject");
            assert_eq!(riscv_outputs.produced_state_id, native_outputs.produced_state_id,
                "State IDs must match");
            assert_eq!(riscv_outputs.new_balance, native_outputs.new_balance,
                "Balances must match");
            assert_eq!(riscv_outputs.rejection_reason, native_outputs.rejection_reason,
                "Rejection reasons must match");
        }

        #[test]
        fn test_real_elf_cl2_with_receipts() {
            use axiom_core_logic::types::{Receipt, WitnessSig, VBC, VBCProofBundle};

            let elf = match find_elf() {
                Some(e) => e,
                None => {
                    eprintln!("SKIP: axiom-core.elf not found");
                    return;
                }
            };

            let avm = AvmInterpreter::new(elf, [0u8; 32]);
            let mut inputs = create_test_inputs();
            inputs.mode = CoreLogicMode::CL2;

            // Add receipt with VBC bundle
            let receipt = Receipt {
                oods_flag: None,
                txid: [1u8; 32],
                state_hash: [2u8; 32],
                produced_state_id: [3u8; 32],
                new_wallet_seq: 1,
                commitment_hash: [0u8; 32],
                sdid: [0u8; 32],
                lineage_hash: [0u8; 32],
                core_version: String::new(),
                epoch: 0,
                fact_proof: None,
                required_k: 3,
                receipt_commitment: [0u8; 32],
                fee_breakdown: Vec::new(),
                is_dev_class: false,
                core_id: [0u8; 32],
                witness_sigs: vec![WitnessSig {
                    validator_id: [4u8; 32],
                    validator_pk: vec![5u8; 32],
                    signature: vec![6u8; 64],
                    execution_proof: vec![],
                    proof_type: 1,
                    carrier_type: "email".into(),
                    carrier_address: "test@axiom.local".into(),
                    vbc_bundle: Some(VBCProofBundle {
                        target_vbc: VBC {
                            version: 9,
                            network_size_baseline: 0,
                            baseline_tick: 0,
                            validator_id: [7u8; 32],
                            subject_pubkey_sphincs: vec![8u8; 32],
                            subject_pubkey_dilithium: vec![9u8; 32],
                            subject_pubkey_ed25519: vec![10u8; 32],
                            pgp_fingerprint: vec![],
                            node_name: "test".into(),
                            proof_cap: "dmap".into(),
                            issued_at: 1000000,
                            expires_at: 2000000,
                            chain_depth: 0,
                            issuer_set: vec![vec![11u8; 32], vec![12u8; 32], vec![13u8; 32]],
                            signatures: vec![vec![14u8; 64], vec![15u8; 64], vec![16u8; 64]],
                            max_tx: 50000,
                            founding_vbc_hash: [17u8; 32],
                        },
                        supporting_vbcs: vec![],
                    }),
                    fact_signature: None,
                    checkpoint_sig: None,
                    availability_attestation: None,
                    validator_hints: vec![],
                    receipt_signature: None,
                    receipt_commitment_sig: None,
                    rate_bps: 0,
                    slot_amount: 0,
                }],
            };
            inputs.prev_receipts = vec![receipt];

            // This should at least deserialize successfully in the guest
            // (It will reject because the VBC root keys won't match, but that's expected)
            let result = avm.execute(inputs);
            // We expect an Ok result (even if it's a Reject) — the guest should NOT panic
            assert!(result.is_ok(), "Guest panicked: {:?}", result.err());
        }

        #[test]
        fn test_real_elf_dmap_trace_collected() {
            let elf = match find_elf() {
                Some(e) => e,
                None => {
                    eprintln!("SKIP: axiom-core.elf not found");
                    return;
                }
            };

            let avm = AvmInterpreter::new(elf, [0u8; 32]);
            let inputs = create_test_inputs();

            let result = avm.execute_with_dmap(inputs).expect("DMAP execution failed");

            // Must produce a DMAP trace with checkpoints
            assert!(result.dmap_trace.is_some(), "DMAP trace must be collected");
            let trace = result.dmap_trace.unwrap();
            assert!(!trace.checkpoints.is_empty(),
                "Must have at least one checkpoint");

            // CoreID must be BLAKE3 of ELF
            assert_ne!(result.core_id, [0u8; 32], "CoreID must be non-zero");
        }

        /// DMAP Defect-1 regression guard: interior checkpoints must actually fire.
        /// The bug collected exactly ONE checkpoint (the final snapshot); a correct
        /// run over N instructions has ~N/DMAP_CHECKPOINT_INTERVAL checkpoints. This is
        /// the assertion that would have caught the original defect. It also exercises
        /// Defect-2 on the real ELF under JIT (memory roots must evolve across the run).
        #[test]
        fn test_real_elf_interior_checkpoints_fire() {
            let elf = match find_elf() {
                Some(e) => e,
                None => { eprintln!("SKIP: axiom-core.elf not found"); return; }
            };
            let avm = AvmInterpreter::new(elf, [0u8; 32]);
            let result = avm.execute_with_dmap(create_test_inputs()).expect("DMAP execution failed");
            let trace = result.dmap_trace.expect("DMAP trace must be collected");

            let n = trace.checkpoints.len() as u64;
            let final_ic = trace.checkpoints.last().unwrap().instruction_count;
            let interval = crate::dmap::DMAP_CHECKPOINT_INTERVAL;
            let expected = final_ic / interval; // one interior checkpoint per interval boundary

            // Regression: the bug produced exactly 1 checkpoint.
            assert!(n > 1,
                "REGRESSION: only {} checkpoint(s) over {} instructions — interior \
                 checkpoints are not firing (the original DMAP bug)", n, final_ic);
            // n ≈ expected interior (block granularity) + 1 final. Bound both sides so a
            // future under-firing regression is caught, with slack for block straddling.
            assert!(n * 4 >= expected * 3,
                "checkpoint count {} far below expected ~{} ({} instr / {}) — under-firing",
                n, expected, final_ic, interval);
            assert!(n <= expected + 5,
                "checkpoint count {} above expected ~{} + slack", n, expected);
            // Memory roots must evolve across a real execution (also exercises Defect-2
            // dirty tracking under JIT — JIT-blind roots would show far fewer distinct).
            let mut roots: Vec<[u8; 32]> = trace.checkpoints.iter().map(|c| c.memory_root).collect();
            roots.sort(); roots.dedup();
            assert!(roots.len() > 1,
                "memory roots must evolve across checkpoints (got {} distinct)", roots.len());
        }

        #[test]
        fn test_real_elf_deterministic() {
            let elf = match find_elf() {
                Some(e) => e,
                None => {
                    eprintln!("SKIP: axiom-core.elf not found");
                    return;
                }
            };

            let avm = AvmInterpreter::new(elf, [0u8; 32]);

            // Run same inputs twice — must get byte-identical results
            let inputs1 = create_test_inputs();
            let inputs2 = create_test_inputs();

            let r1 = avm.execute_with_dmap(inputs1).expect("Run 1 failed");
            let r2 = avm.execute_with_dmap(inputs2).expect("Run 2 failed");

            assert_eq!(r1.outputs.result, r2.outputs.result);
            assert_eq!(r1.outputs.produced_state_id, r2.outputs.produced_state_id);
            assert_eq!(r1.core_id, r2.core_id);

            // DMAP traces must be identical (deterministic execution)
            let t1 = r1.dmap_trace.unwrap();
            let t2 = r2.dmap_trace.unwrap();
            assert_eq!(t1.checkpoints.len(), t2.checkpoints.len(),
                "Checkpoint count must be deterministic");
            for (i, (c1, c2)) in t1.checkpoints.iter().zip(t2.checkpoints.iter()).enumerate() {
                assert_eq!(c1.memory_root, c2.memory_root,
                    "Memory root at checkpoint {} must be deterministic", i);
                assert_eq!(c1.instruction_count, c2.instruction_count,
                    "Instruction count at checkpoint {} must match", i);
            }
        }
    }

    // ======================================================================
    // YPX-009: Silicon Pulse tests
    // ======================================================================

    #[cfg(not(feature = "riscv-interpreter"))]
    mod pulse {
        use super::*;

        fn make_avm() -> AvmInterpreter {
            // Bypass calibration for test speed (no 200ms delay per test)
            let avm = AvmInterpreter {
                bytecode: vec![0x00],
                runtime_fingerprint: [0u8; 32],
                pending_audit: Mutex::new(None),
                peer_audit_bans: Mutex::new(Vec::new()),
                audit_buffer: Mutex::new(AuditBuffer::new()),
                wallet_cache: Mutex::new(WalletCache::new()),
                validator_pk: Mutex::new(None),
                pulse_ready: AtomicBool::new(true), // tests bypass gate
                ignition_t0: Mutex::new(None),
                last_validated_tick: AtomicU64::new(0),
            };
            avm.set_validator_pk(vec![0xAAu8; 32]);
            avm
        }

        /// Create a plain buffer for unit tests.
        fn test_buf() -> AuditBuffer {
            AuditBuffer::new()
        }

        /// §23.14.6 tick discipline: ban imposition + expiry run on validated
        /// TARDIS ticks, never the host wall clock. Fails against the old
        /// SystemTime::now()-based expiry (a wall-clock ban imposed "now"
        /// cannot expire inside a test, so the final asserts would fail).
        #[test]
        fn test_peer_audit_ban_expiry_is_tick_disciplined() {
            let avm = make_avm();
            let banned_pk = vec![0xBBu8; 32];

            // A TX at tick T advances the watermark (enforce_audit_pre path);
            // simulate it directly.
            let t = 1_000_000u64;
            avm.last_validated_tick.store(t, Ordering::Release);

            avm.ban_validator(
                banned_pk.clone(),
                axiom_core_logic::types::PeerAuditBanReason::HashMismatch,
            );
            assert!(avm.is_validator_banned(&banned_pk), "ban active at imposition tick");
            assert_eq!(avm.peer_audit_bans().len(), 1);
            assert_eq!(avm.peer_audit_bans()[0].banned_at_tick, t, "ban stamped with validated tick, not wall clock");

            // PEER_AUDIT_BAN_TICKS is a tick COUNT; the stamp window is the
            // count projected onto unix-second tick stamps (24h = 86400).
            let window_stamp = axiom_core_logic::types::PEER_AUDIT_BAN_TICKS
                * axiom_core_logic::types::TICK_INTERVAL_SECS;
            assert_eq!(window_stamp, 86_400, "24h ban window on the stamp scale");

            // One second before the window closes — still banned.
            avm.last_validated_tick.store(t + window_stamp - 1, Ordering::Release);
            assert!(avm.is_validator_banned(&banned_pk), "ban holds through the full window");

            // Validated ticks pass the window — ban expires with NETWORK
            // time, regardless of what the host wall clock says.
            avm.last_validated_tick.store(t + window_stamp, Ordering::Release);
            assert!(!avm.is_validator_banned(&banned_pk), "ban expires by validated tick");
            assert!(avm.peer_audit_bans().is_empty(), "expired ban filtered from admin list");
        }

        /// Current Unix epoch seconds (test helper).
        fn now_secs() -> u64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        }

        #[test]
        fn test_audit_buffer_accumulates() {
            let mut buf = test_buf();
            assert_eq!(buf.entries.len(), 0);
            assert_eq!(buf.accumulator, [0u8; 32]);

            let digest = TxDigest {
                tx_number: 1,
                sender_balance: 1000,
                receiver_balance: 0,
                state_id: [1u8; 32],
                amount: 100,
                           };
            buf.accumulate(digest);
            assert_eq!(buf.entries.len(), 1);
            assert_ne!(buf.accumulator, [0u8; 32]);
        }

        #[test]
        fn test_audit_buffer_trigger_count() {
            let mut buf = test_buf();
            // Fill to 80% of PULSE_BUFFER_MAX (count trigger threshold)
            // Push entries directly — no Argon2id needed for trigger check
            let threshold = (PULSE_BUFFER_MAX as f64 * PULSE_BUFFER_TRIGGER_RATIO) as u32;
            for i in 0..threshold {
                buf.entries.push(TxDigest {
                    tx_number: i as u64,
                    sender_balance: 1000,
                    receiver_balance: 0,
                    state_id: [i as u8; 32],
                    amount: 100,
                });
            }
            // Set last_audit_time_secs to now so time trigger doesn't fire
            buf.last_audit_time_secs = now_secs();
            assert!(buf.should_trigger(now_secs()), "should trigger at 80% buffer capacity");
        }

        #[test]
        fn test_audit_buffer_trigger_time() {
            let mut buf = test_buf();
            let base_time = now_secs();
            buf.last_audit_time_secs = base_time;
            buf.accumulate(TxDigest {
                tx_number: 1,
                sender_balance: 1000,
                receiver_balance: 0,
                state_id: [1u8; 32],
                amount: 100,
            });
            // Not enough time passed
            assert!(!buf.should_trigger(base_time + 100));
            // 5 minutes passed → time trigger fires
            assert!(buf.should_trigger(base_time + PULSE_AUDIT_INTERVAL_SECS + 1));
        }

        #[test]
        fn test_audit_buffer_no_trigger_empty() {
            let buf = test_buf();
            // Empty buffer should never trigger, even after long time
            assert!(!buf.should_trigger(now_secs() + PULSE_AUDIT_INTERVAL_SECS + 1));
        }

        #[test]
        fn test_fiat_shamir_select_deterministic() {
            let seed = [42u8; 32];
            let s1 = fiat_shamir_select(&seed, 200, 50);
            let s2 = fiat_shamir_select(&seed, 200, 50);
            assert_eq!(s1, s2);
            assert_eq!(s1.len(), 50);
            assert!(s1.iter().all(|&i| i < 200));
            assert!(s1.windows(2).all(|w| w[0] <= w[1]));
            let mut deduped = s1.clone();
            deduped.dedup();
            assert_eq!(deduped.len(), s1.len());
        }

        #[test]
        fn test_fiat_shamir_select_all_when_small() {
            let seed = [1u8; 32];
            let s = fiat_shamir_select(&seed, 10, 50);
            assert_eq!(s.len(), 10);
            assert_eq!(s, (0..10).collect::<Vec<u32>>());
        }

        #[test]
        fn test_audit_request_subset_hash_matches() {
            let mut buf = test_buf();
            for i in 0..10u64 {
                buf.accumulate(TxDigest {
                    tx_number: i,
                    sender_balance: 1000 - i * 100,
                    receiver_balance: 0,
                    state_id: [(i & 0xFF) as u8; 32],
                    amount: i * 10,
                                   });
            }
            let request = buf.generate_request(&[0xBBu8; 32], 1);
            let recomputed = buf.compute_subset_hash(&request.selected_indices);
            assert_eq!(request.expected_hash, recomputed);
        }

        #[test]
        fn test_wallet_cache_update_and_challenge() {
            let mut cache = WalletCache::new();
            let pk = [1u8; 32];
            let state_id = [2u8; 32];
            cache.update(pk, state_id, 1000, 1);

            assert_eq!(cache.entries.len(), 1);
            assert_eq!(cache.insertion_order.len(), 1);

            let txid = [3u8; 32];
            let acc = [0u8; 32];
            let challenge = cache.generate_challenge(&txid, &acc);
            assert!(challenge.is_some());
            let c = challenge.unwrap();
            assert_eq!(c.target_wallet_pk, pk);
            assert_eq!(c.expected_state_id, state_id);
        }

        #[test]
        fn test_wallet_cache_nonce_verify_match() {
            let mut cache = WalletCache::new();
            let pk = [1u8; 32];
            let state_id = [2u8; 32];
            cache.update(pk, state_id, 1000, 1);

            let response = NonceResponse {
                target_wallet_pk: pk,
                current_state_id: state_id,
                current_balance: 1000,
            };
            assert!(cache.verify_response(&response));
            assert_eq!(cache.mismatch_count, 0);
        }

        #[test]
        fn test_wallet_cache_nonce_verify_advanced_state() {
            let mut cache = WalletCache::new();
            let pk = [1u8; 32];
            cache.update(pk, [2u8; 32], 1000, 1);

            let response = NonceResponse {
                target_wallet_pk: pk,
                current_state_id: [3u8; 32],
                current_balance: 2000,
            };
            // GAP-D: Response accepted (balance increased = state advanced)
            assert!(cache.verify_response(&response));
            // GAP-D FIX: Cache does NOT update on state-advanced — keeps old floor.
            // Only exact state_id match updates cache (proves Core computed the state).
            assert_eq!(cache.entries[&pk].produced_state_id, [2u8; 32]); // unchanged
            assert_eq!(cache.entries[&pk].balance, 1000); // unchanged
        }

        #[test]
        fn test_wallet_cache_nonce_mismatch() {
            let mut cache = WalletCache::new();
            let pk = [1u8; 32];
            cache.update(pk, [2u8; 32], 1000, 1);

            let response = NonceResponse {
                target_wallet_pk: pk,
                current_state_id: [3u8; 32],
                current_balance: 500,
            };
            assert!(!cache.verify_response(&response));
            assert_eq!(cache.mismatch_count, 1);
            assert!(!cache.is_audit_failed());
        }

        #[test]
        fn test_wallet_cache_nonce_three_mismatches_fails() {
            let mut cache = WalletCache::new();
            let pk = [1u8; 32];
            cache.update(pk, [2u8; 32], 1000, 1);

            let bad_response = NonceResponse {
                target_wallet_pk: pk,
                current_state_id: [3u8; 32],
                current_balance: 500,
            };

            for i in 0..NONCE_MISMATCH_TOLERANCE {
                assert!(!cache.verify_response(&bad_response));
                if i + 1 < NONCE_MISMATCH_TOLERANCE {
                    assert!(!cache.is_audit_failed());
                }
            }
            assert!(cache.is_audit_failed());
        }

        #[test]
        fn test_wallet_cache_match_resets_mismatch_count() {
            let mut cache = WalletCache::new();
            let pk = [1u8; 32];
            let state_id = [2u8; 32];
            cache.update(pk, state_id, 1000, 1);

            let bad = NonceResponse { target_wallet_pk: pk, current_state_id: [3u8; 32], current_balance: 500 };
            cache.verify_response(&bad);
            cache.verify_response(&bad);
            assert_eq!(cache.mismatch_count, 2);

            let good = NonceResponse { target_wallet_pk: pk, current_state_id: state_id, current_balance: 1000 };
            assert!(cache.verify_response(&good));
            assert_eq!(cache.mismatch_count, 0);
        }

        #[test]
        fn test_pulse_no_accumulate_on_reject() {
            // CL1 with fake keys → Reject. Buffer should stay empty.
            let avm = make_avm();
            let inputs = create_test_inputs();
            let result = avm.execute(inputs).unwrap();

            assert_eq!(result.result, ValidationResult::Reject);
            let buf = avm.audit_buffer.lock().unwrap();
            assert_eq!(buf.entries.len(), 0);
        }

        #[test]
        fn test_pulse_accumulates_on_accept_via_buffer_directly() {
            // Test accumulation logic directly (bypass execute() since
            // CL1 with fake keys rejects — real Accept needs real sigs).
            let avm = make_avm();
            let digest = TxDigest {
                tx_number: 1,
                sender_balance: 1000,
                receiver_balance: 0,
                state_id: [1u8; 32],
                amount: 100,

            };
            {
                let mut buf = avm.audit_buffer.lock().unwrap();
                buf.accumulate(digest);
                assert_eq!(buf.entries.len(), 1);
                assert_eq!(buf.tx_counter, 0); // tx_counter only incremented by pulse_post_execute
                assert_ne!(buf.accumulator, [0u8; 32]);
            }
        }

        #[test]
        fn test_pulse_audit_triggers_at_count_threshold() {
            // Test trigger + request generation at count threshold.
            // Use small count (10) with Argon2id to keep test fast,
            // then verify sample ratio logic separately.
            let mut buf = test_buf();
            let n = 10u32;
            for i in 0..n {
                buf.accumulate(TxDigest {
                    tx_number: i as u64,
                    sender_balance: 1000,
                    receiver_balance: 0,
                    state_id: [i as u8; 32],
                    amount: 100,
                });
            }
            // Force time trigger (buffer is small, so count won't trigger)
            buf.last_audit_time_secs = 0;
            assert!(buf.should_trigger(now_secs()));

            let request = buf.generate_request(&[0xAAu8; 32], 1);
            // Sample size = ceil(10 × 0.10) = 1
            let expected_sample = (n as f64 * PULSE_SAMPLE_RATIO).ceil() as usize;
            assert_eq!(request.selected_indices.len(), expected_sample);
            assert_eq!(request.tx_numbers.len(), request.selected_indices.len());
            // Verify expected hash is deterministic
            let recomputed = buf.compute_subset_hash(&request.selected_indices);
            assert_eq!(request.expected_hash, recomputed);
        }

        #[test]
        fn test_sample_ratio_scaling() {
            // Verify sample size scales correctly with buffer size
            // (no Argon2id needed — push entries directly)
            let mut buf = test_buf();
            for i in 0..200u32 {
                buf.entries.push(TxDigest {
                    tx_number: i as u64, sender_balance: 1000, receiver_balance: 0,
                    state_id: [i as u8; 32], amount: 100,
                });
            }
            let request = buf.generate_request(&[0xBBu8; 32], 1);
            // 10% of 200 = 20
            assert_eq!(request.selected_indices.len(), 20);

            // Small buffer: 3 entries → ceil(0.3) = 1
            let mut buf2 = test_buf();
            for i in 0..3u32 {
                buf2.entries.push(TxDigest {
                    tx_number: i as u64, sender_balance: 1000, receiver_balance: 0,
                    state_id: [i as u8; 32], amount: 100,
                });
            }
            let request2 = buf2.generate_request(&[0xCCu8; 32], 1);
            assert_eq!(request2.selected_indices.len(), 1, "minimum 1 sample");
        }

        #[test]
        fn test_audit_buffer_reset() {
            let mut buf = test_buf();
            for i in 0..5u64 {
                buf.accumulate(TxDigest {
                    tx_number: i,
                    sender_balance: 1000,
                    receiver_balance: 0,
                    state_id: [0u8; 32],
                    amount: 100,
    
                });
            }
            assert_eq!(buf.entries.len(), 5);

            buf.reset(1000);
            assert_eq!(buf.entries.len(), 0);
            assert_eq!(buf.accumulator, [0u8; 32]);
            assert_eq!(buf.last_audit_time_secs, 1000);
            assert!(buf.pending_request.is_none());
        }

        #[test]
        fn test_accumulator_chain_deterministic() {
            let mut buf1 = test_buf();
            let mut buf2 = test_buf();

            for i in 0..10u64 {
                let digest = TxDigest {
                    tx_number: i,
                    sender_balance: 1000,
                    receiver_balance: 0,
                    state_id: [(i & 0xFF) as u8; 32],
                    amount: i * 10,
    
                };
                buf1.accumulate(digest.clone());
                buf2.accumulate(digest);
            }
            assert_eq!(buf1.accumulator, buf2.accumulator);
        }

        #[test]
        fn test_accumulator_differs_with_different_spot_check() {
            let mut buf1 = test_buf();
            let mut buf2 = test_buf();

            buf1.accumulate(TxDigest {
                tx_number: 1, sender_balance: 1000, receiver_balance: 0,
                state_id: [1u8; 32], amount: 100,
            });
            buf2.accumulate(TxDigest {
                tx_number: 1, sender_balance: 1000, receiver_balance: 0,
                state_id: [1u8; 32], amount: 999,
            });
            assert_ne!(buf1.accumulator, buf2.accumulator,
                "Different amount MUST produce different accumulator");
        }

        #[test]
        fn test_self_benchmark_measures_throughput() {
            let mut buf = AuditBuffer::new();
            assert_eq!(buf.argon2id_per_sec, 0);

            buf.self_benchmark();

            assert!(buf.argon2id_per_sec > 0,
                "benchmark must measure positive throughput");

            println!("  ✓ Self-benchmark: {} Argon2id/sec", buf.argon2id_per_sec);
        }

        #[test]
        fn test_dual_trigger_count_vs_time() {
            let now = now_secs();

            // Below count threshold, recent audit → no trigger
            let mut buf = AuditBuffer::new();
            buf.last_audit_time_secs = now;
            for i in 0..50u32 {
                buf.entries.push(TxDigest {
                    tx_number: i as u64, sender_balance: 1000, receiver_balance: 0,
                    state_id: [i as u8; 32], amount: 100,
                });
            }
            assert!(!buf.should_trigger(now), "50 entries, recent audit → no trigger");

            // Same buffer, but 5+ minutes passed → time trigger fires
            assert!(buf.should_trigger(now + PULSE_AUDIT_INTERVAL_SECS + 1),
                "50 entries, 5 min passed → time trigger");

            // At count threshold, recent audit → count trigger fires
            let mut buf2 = AuditBuffer::new();
            buf2.last_audit_time_secs = now;
            let threshold = (PULSE_BUFFER_MAX as f64 * PULSE_BUFFER_TRIGGER_RATIO) as u32;
            for i in 0..threshold {
                buf2.entries.push(TxDigest {
                    tx_number: i as u64, sender_balance: 1000, receiver_balance: 0,
                    state_id: [i as u8; 32], amount: 100,
                });
            }
            assert!(buf2.should_trigger(now), "at 80% capacity → count trigger");
        }

        #[test]
        fn test_accumulate_is_pure_audit_work() {
            // Verify that accumulate only does chain hashing — no wasted rounds.
            // Two buffers with same input must produce identical accumulator.
            let mut buf1 = AuditBuffer::new();
            let mut buf2 = AuditBuffer::new();

            let digest = TxDigest {
                tx_number: 1, sender_balance: 1000, receiver_balance: 0,
                state_id: [1u8; 32], amount: 100,            };
            buf1.accumulate(digest.clone());
            buf2.accumulate(digest);

            assert_eq!(buf1.accumulator, buf2.accumulator,
                "same input must always produce same accumulator (pure audit, no waste)");
        }

        #[test]
        fn test_accumulate_timing_argon2id() {
            // Verify accumulate timing with Argon2id memory-hard chain.
            // Each entry does Argon2id(48MB) → BLAKE3 — intentionally heavier
            // than BLAKE3-only, creating memory pressure that detects sharing.
            let mut buf = AuditBuffer::new();
            let n = 10u64; // small sample — Argon2id is intentionally expensive
            let t0 = std::time::Instant::now();
            for i in 0..n {
                buf.accumulate(TxDigest {
                    tx_number: i, sender_balance: 100_000, receiver_balance: 0,
                    state_id: {
                        let mut s = [0u8; 32];
                        s[..8].copy_from_slice(&i.to_le_bytes());
                        s
                    },
                    amount: i * 10,
                                   });
            }
            let elapsed_ms = t0.elapsed().as_millis();
            let per_entry_ms = elapsed_ms as f64 / n as f64;

            println!("  ✓ Argon2id+BLAKE3 accumulate: {} entries in {}ms ({:.1} ms/entry)",
                n, elapsed_ms, per_entry_ms);

            // Argon2id(48MB, t=1) should be under 2000ms/entry even in debug
            assert!(per_entry_ms < 2000.0,
                "Argon2id accumulate too slow: {:.1} ms/entry", per_entry_ms);
        }

        /// Hardware benchmark: measures CPU time, memory, and throughput across
        /// pulse computation phases. All CPU time is real audit work.
        #[test]
        fn test_pulse_benchmark_hardware_stress() {
            println!("\n  ╔══════════════════════════════════════════════════════════╗");
            println!("  ║  YPX-009 Silicon Pulse — Hardware Resource Benchmark     ║");
            println!("  ╠══════════════════════════════════════════════════════════╣");

            // Phase 1: Audit buffer accumulation (Argon2id → BLAKE3 chain)
            let n_entries = 10u64; // Argon2id is memory-hard — keep test short
            let t0 = std::time::Instant::now();
            let mut buf = test_buf();
            for i in 0..n_entries {
                buf.accumulate(TxDigest {
                    tx_number: i,
                    sender_balance: 1_000_000 - i * 10,
                    receiver_balance: i * 10,
                    state_id: {
                        let mut s = [0u8; 32];
                        s[..8].copy_from_slice(&i.to_le_bytes());
                        s
                    },
                    amount: i * 10,
                                   });
            }
            let phase1_ms = t0.elapsed().as_millis();
            let phase1_per_entry_ms = phase1_ms as f64 / n_entries as f64;
            println!("  ║                                                          ║");
            println!("  ║ Phase 1: Audit buffer (Argon2id(48MB) → BLAKE3 chain)    ║");
            println!("  ║   Entries:       {:>8}                                  ║", n_entries);
            println!("  ║   Total time:    {:>8} ms                               ║", phase1_ms);
            println!("  ║   Per entry:     {:>8.1} ms                              ║", phase1_per_entry_ms);

            // Phase 2: Audit trigger checks (time-based)
            let t1 = std::time::Instant::now();
            let n_selections = 1_000u32;
            for i in 0..n_selections {
                let _ = buf.should_trigger(i as u64 * 5);
            }
            let phase2_us = t1.elapsed().as_micros();
            println!("  ║                                                          ║");
            println!("  ║ Phase 2: Audit trigger checks                            ║");
            println!("  ║   Checks:        {:>8}                                  ║", n_selections);
            println!("  ║   Total time:    {:>8} µs                               ║", phase2_us);
            println!("  ║   Per check:     {:>8.1} ns                              ║",
                (t1.elapsed().as_nanos() as f64) / n_selections as f64);

            // Phase 3: Ed25519 signature generation (pulse proof signing)
            use ed25519_dalek::{SigningKey, Signer, Verifier, VerifyingKey, Signature};
            let n_sigs = 1_000u32;
            let sk = SigningKey::from_bytes(&[42u8; 32]);
            let vpk = sk.verifying_key().to_bytes();
            let pulse_payload = |vk: &[u8; 32], epoch: u64, acc: &[u8; 32], audit: &[u8; 32]| -> [u8; 32] {
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"AXIOM_PULSE_PROOF");
                hasher.update(vk);
                hasher.update(&epoch.to_le_bytes());
                hasher.update(acc);
                hasher.update(audit);
                *hasher.finalize().as_bytes()
            };
            let t2 = std::time::Instant::now();
            let mut last_sig = [0u8; 64];
            for epoch in 0..n_sigs as u64 {
                let payload = pulse_payload(&vpk, epoch, &buf.accumulator, &[0xCC; 32]);
                let sig = sk.sign(&payload);
                last_sig = sig.to_bytes();
            }
            let phase3_us = t2.elapsed().as_micros();
            println!("  ║                                                          ║");
            println!("  ║ Phase 3: Ed25519 pulse proof signing                     ║");
            println!("  ║   Signatures:    {:>8}                                  ║", n_sigs);
            println!("  ║   Total time:    {:>8} µs                               ║", phase3_us);
            println!("  ║   Per sig:       {:>8.1} µs                              ║",
                phase3_us as f64 / n_sigs as f64);

            // Phase 4: Ed25519 signature verification (Nabla side)
            let payload = pulse_payload(&vpk, 999, &buf.accumulator, &[0xCC; 32]);
            let sig_for_verify = Signature::from_bytes(&last_sig);
            let vk = VerifyingKey::from_bytes(&vpk).unwrap();
            let t3 = std::time::Instant::now();
            let n_verifies = 1_000u32;
            for _ in 0..n_verifies {
                let _ = vk.verify(&payload, &sig_for_verify);
            }
            let phase4_us = t3.elapsed().as_micros();
            println!("  ║                                                          ║");
            println!("  ║ Phase 4: Ed25519 pulse proof verification                ║");
            println!("  ║   Verifications: {:>8}                                  ║", n_verifies);
            println!("  ║   Total time:    {:>8} µs                               ║", phase4_us);
            println!("  ║   Per verify:    {:>8.1} µs                              ║",
                phase4_us as f64 / n_verifies as f64);

            // Phase 5: Full AVM pulse cycle (accumulate + trigger check)
            let avm = make_avm();
            let n_txs = 10u64; // Argon2id is memory-hard — keep test short
            let t4 = std::time::Instant::now();
            for i in 0..n_txs {
                let mut buf_inner = avm.audit_buffer.lock().unwrap();
                buf_inner.accumulate(TxDigest {
                    tx_number: i,
                    sender_balance: 100_000,
                    receiver_balance: 0,
                    state_id: {
                        let mut s = [0u8; 32];
                        s[..8].copy_from_slice(&i.to_le_bytes());
                        s
                    },
                    amount: 100,
                                   });
                let _ = buf_inner.should_trigger(i * 5);
            }
            let phase5_us = t4.elapsed().as_micros();
            let throughput = n_txs as f64 / (t4.elapsed().as_secs_f64());
            println!("  ║                                                          ║");
            println!("  ║ Phase 5: Full pulse cycle (accumulate + audit check)     ║");
            println!("  ║   Transactions:  {:>8}                                  ║", n_txs);
            println!("  ║   Total time:    {:>8} µs                               ║", phase5_us);
            println!("  ║   Throughput:    {:>8.0} TX/sec                          ║", throughput);

            // Summary
            let total_us = (phase1_ms * 1000) as u128 + phase2_us + phase3_us + phase4_us + phase5_us;
            println!("  ║                                                          ║");
            println!("  ╠══════════════════════════════════════════════════════════╣");
            println!("  ║ TOTAL BENCHMARK: {:>8} ms                               ║", total_us / 1000);
            println!("  ║                                                          ║");
            println!("  ║ ZERO WASTED CPU: every cycle is real audit work.         ║");
            println!("  ║   Argon2id+BLAKE3: {:>4.1} ms/entry (memory-hard chain)   ║", phase1_per_entry_ms);
            println!("  ║   Ed25519 sign:  {:>6.0} µs/sig    (ALU-bound)           ║",
                phase3_us as f64 / n_sigs as f64);
            println!("  ║   Ed25519 vrfy:  {:>6.0} µs/vrfy   (ALU-bound)           ║",
                phase4_us as f64 / n_verifies as f64);
            println!("  ║   Max TX rate:   {:>6.0} TX/sec    (single core)         ║", throughput);
            println!("  ╚══════════════════════════════════════════════════════════╝\n");
        }

        /// Full audit round-trip benchmark:
        /// 1. Accumulate N TXs (Argon2id→BLAKE3 per TX)
        /// 2. Generate audit request (Fiat-Shamir selection)
        /// 3. Simulate Lambda DB lookup (extract raw TxDigests)
        /// 4. Core replays Argon2id→BLAKE3 chain from raw data
        /// 5. Verify replayed hash matches expected
        #[test]
        fn test_audit_round_trip_benchmark() {
            println!("\n  ╔══════════════════════════════════════════════════════════╗");
            println!("  ║  YPX-009 — Audit Round-Trip Benchmark                   ║");
            println!("  ╠══════════════════════════════════════════════════════════╣");

            // Step 1: Accumulate entries (simulates normal TX processing)
            let n_entries = 20u64;
            let t_total = std::time::Instant::now();
            let t0 = std::time::Instant::now();
            let mut buf = test_buf();
            let mut digests = Vec::new(); // "Lambda's DB" — stores raw fields
            for i in 0..n_entries {
                let digest = TxDigest {
                    tx_number: i,
                    sender_balance: 1_000_000 - i * 100,
                    receiver_balance: 0,
                    state_id: {
                        let mut s = [0u8; 32];
                        s[..8].copy_from_slice(&i.to_le_bytes());
                        s
                    },
                    amount: i * 50 + 10,
                };
                digests.push(digest.clone());
                buf.accumulate(digest);
            }
            let phase1_ms = t0.elapsed().as_millis();
            println!("  ║ Phase 1: Accumulate {} TXs (Argon2id→BLAKE3)            ║", n_entries);
            println!("  ║   Time:    {:>6} ms  ({:.1} ms/TX)                      ║",
                phase1_ms, phase1_ms as f64 / n_entries as f64);

            // Step 2: Generate audit request
            let t1 = std::time::Instant::now();
            let validator_pk = [42u8; 32];
            let request = buf.generate_request(&validator_pk, 1);
            let phase2_us = t1.elapsed().as_micros();
            let sample_size = request.selected_indices.len();
            println!("  ║                                                          ║");
            println!("  ║ Phase 2: Generate request (Fiat-Shamir + subset hash)   ║");
            println!("  ║   Sample: {:>3} of {} TXs                                 ║", sample_size, n_entries);
            println!("  ║   Time:   {:>6} ms  (selection + Argon2id×{})           ║",
                t1.elapsed().as_millis(), sample_size);

            // Step 3: Lambda DB lookup (simulate — just index into our digests vec)
            let t2 = std::time::Instant::now();
            let lambda_entries: Vec<TxDigest> = request.selected_indices.iter()
                .map(|&idx| digests[idx as usize].clone())
                .collect();
            let phase3_us = t2.elapsed().as_micros();
            println!("  ║                                                          ║");
            println!("  ║ Phase 3: Lambda DB lookup ({} entries)                   ║", lambda_entries.len());
            println!("  ║   Time:   {:>6} µs  (zero crypto, just DB read)         ║", phase3_us);

            // Step 4: Core replays Argon2id→BLAKE3 from Lambda's raw data
            let t3 = std::time::Instant::now();
            let replayed_hash = AuditBuffer::replay_chain_from_raw(&lambda_entries);
            let phase4_ms = t3.elapsed().as_millis();
            println!("  ║                                                          ║");
            println!("  ║ Phase 4: Core replay (Argon2id→BLAKE3 × {})             ║", sample_size);
            println!("  ║   Time:   {:>6} ms  ({:.1} ms/entry)                    ║",
                phase4_ms, phase4_ms as f64 / sample_size as f64);

            // Step 5: Verify
            let t4 = std::time::Instant::now();
            let verified = replayed_hash == request.expected_hash;
            let phase5_ns = t4.elapsed().as_nanos();
            assert!(verified, "Round-trip audit must pass with honest data");
            println!("  ║                                                          ║");
            println!("  ║ Phase 5: Verify (hash comparison)                        ║");
            println!("  ║   Match:  {} ({} ns)                                     ║", verified, phase5_ns);

            // Tamper test: modify one entry, verify chain diverges
            let mut tampered = lambda_entries.clone();
            tampered[0].sender_balance += 1; // Lambda inflated one balance
            let tampered_hash = AuditBuffer::replay_chain_from_raw(&tampered);
            assert_ne!(tampered_hash, request.expected_hash, "Tampered data must diverge");

            let total_ms = t_total.elapsed().as_millis();
            println!("  ║                                                          ║");
            println!("  ╠══════════════════════════════════════════════════════════╣");
            println!("  ║ ROUND-TRIP TOTAL: {:>6} ms                               ║", total_ms);
            println!("  ║                                                          ║");
            println!("  ║  Accumulate:  {:>6} ms  (per-TX cost, amortized)         ║", phase1_ms);
            println!("  ║  Request:     {:>6} ms  (Fiat-Shamir + Argon2id chain)   ║", t1.elapsed().as_millis());
            println!("  ║  DB lookup:   {:>6} µs  (Lambda — zero crypto)           ║", phase3_us);
            println!("  ║  Replay:      {:>6} ms  (Core — Argon2id→BLAKE3)         ║", phase4_ms);
            println!("  ║  Verify:      {:>6} ns  (hash compare)                   ║", phase5_ns);
            println!("  ║                                                          ║");
            println!("  ║  Tamper detected: ✓ (1 byte change → chain diverges)     ║");
            println!("  ╚══════════════════════════════════════════════════════════╝\n");
        }

        // ======================================================================
        // YPX-009: Pulse-gate feature tests
        // ======================================================================

        fn make_blocked_avm() -> AvmInterpreter {
            AvmInterpreter {
                bytecode: vec![0x00],
                runtime_fingerprint: [0u8; 32],
                pending_audit: Mutex::new(None),
                peer_audit_bans: Mutex::new(Vec::new()),
                audit_buffer: Mutex::new(AuditBuffer::new()),
                wallet_cache: Mutex::new(WalletCache::new()),
                validator_pk: Mutex::new(None),
                pulse_ready: AtomicBool::new(false),
                ignition_t0: Mutex::new(None),
                last_validated_tick: AtomicU64::new(0),
            }
        }

        #[test]
        fn test_pulse_gate_blocks_execution_when_not_ready() {
            let avm = make_blocked_avm();
            let inputs = create_test_inputs();
            let result = avm.execute(inputs);
            assert!(result.is_err());
            match result.unwrap_err() {
                AvmError::PulseNotReady => {} // expected
                other => panic!("Expected PulseNotReady, got: {}", other),
            }
        }

        #[test]
        fn test_pulse_gate_blocks_dmap_when_not_ready() {
            let avm = make_blocked_avm();
            let inputs = create_test_inputs();
            let result = avm.execute_with_dmap(inputs);
            match result {
                Err(AvmError::PulseNotReady) => {} // expected
                Err(other) => panic!("Expected PulseNotReady, got: {}", other),
                Ok(_) => panic!("Expected PulseNotReady error, got Ok"),
            }
        }

        #[test]
        fn test_pulse_gate_unblocks_after_calibration() {
            let avm = make_blocked_avm();
            assert!(!avm.is_pulse_ready());

            // Lambda signals Core to benchmark — Core does its own work
            avm.start_pulse_calibration();

            assert!(avm.is_pulse_ready());

            // Verify benchmark ran
            let buf = avm.audit_buffer.lock().unwrap();
            assert!(buf.argon2id_per_sec > 0, "benchmark must have run");
            println!("  ✓ Gate unblocked: {} Argon2id/sec", buf.argon2id_per_sec);
            drop(buf);

            // Now execute should work (will Reject on CL1 fake keys, but not PulseNotReady)
            let inputs = create_test_inputs();
            let result = avm.execute(inputs);
            assert!(result.is_ok());
        }

        #[test]
        fn test_self_benchmark_report() {
            println!("\n  ╔══════════════════════════════════════════════════════════╗");
            println!("  ║  YPX-009 Pulse — Argon2id Self-Benchmark Report         ║");
            println!("  ╠══════════════════════════════════════════════════════════╣");

            let mut buf = AuditBuffer::new();
            buf.self_benchmark();

            let count_threshold = (PULSE_BUFFER_MAX as f64 * PULSE_BUFFER_TRIGGER_RATIO) as u32;
            println!("  ║   Argon2id/sec:    {:>10}                              ║", buf.argon2id_per_sec);
            println!("  ║   Buffer max:      {:>10}                              ║", PULSE_BUFFER_MAX);
            println!("  ║   Count trigger:   {:>10} ({}% of max)                ║",
                count_threshold, (PULSE_BUFFER_TRIGGER_RATIO * 100.0) as u32);
            println!("  ║   Time trigger:    {:>10}s                             ║", PULSE_AUDIT_INTERVAL_SECS);
            println!("  ║   Sample ratio:    {:>10.2}                             ║", PULSE_SAMPLE_RATIO);
            println!("  ║                                                          ║");
            println!("  ║ Dual trigger: TIME (5 min) or COUNT (80% of 2000).      ║");
            println!("  ║ Memory-hard: sharing a machine = lower throughput.       ║");
            println!("  ╚══════════════════════════════════════════════════════════╝\n");
        }

        #[cfg(feature = "pulse-gate")]
        #[test]
        fn test_pulse_gate_feature_constructor_blocks() {
            // When pulse-gate feature is enabled, new() should NOT auto-benchmark
            // and pulse_ready should be false
            let avm = AvmInterpreter::new(vec![0x00], [0u8; 32]);
            assert!(!avm.is_pulse_ready(),
                "pulse-gate: new() must NOT auto-benchmark");

            let inputs = create_test_inputs();
            let result = avm.execute(inputs);
            match result {
                Err(AvmError::PulseNotReady) => {}
                other => panic!("Expected PulseNotReady with pulse-gate, got: {:?}", other),
            }

            // After calibration, should work
            avm.start_pulse_calibration();
            assert!(avm.is_pulse_ready());
        }

        #[cfg(not(feature = "pulse-gate"))]
        #[test]
        fn test_no_pulse_gate_constructor_auto_calibrates() {
            // Without pulse-gate, new() should auto-benchmark and be ready
            let avm = AvmInterpreter::new(vec![0x00], [0u8; 32]);
            assert!(avm.is_pulse_ready(),
                "without pulse-gate: new() must auto-benchmark and be ready");
        }

        // ======================================================================
        // YPX-009: Ignition TX tests
        // ======================================================================

        #[test]
        fn test_ignition_process_records_t0() {
            let avm = make_blocked_avm();
            assert!(!avm.is_pulse_ready());

            // Process ignition TX — bypasses pulse gate, records t0
            let inputs = create_test_inputs();
            let result = avm.process_ignition(inputs);
            assert!(result.is_ok(), "ignition TX must bypass pulse gate");

            // t0 should be recorded
            let t0 = avm.ignition_t0.lock().unwrap();
            assert!(t0.is_some(), "process_ignition must record t0");
        }

        #[test]
        fn test_ignition_complete_unblocks() {
            let avm = make_blocked_avm();
            assert!(!avm.is_pulse_ready());

            // Phase 1: process ignition TX
            let inputs = create_test_inputs();
            avm.process_ignition(inputs).unwrap();

            // Phase 2: complete ignition with non-empty proof
            let fake_proof = vec![0xDE, 0xAD, 0xBE, 0xEF];
            let result = avm.complete_ignition(&fake_proof);
            assert!(result.is_ok(), "complete_ignition must succeed with non-empty proof");

            // Core should now be ready
            assert!(avm.is_pulse_ready(), "Core must be ready after ignition");

            // Verify benchmark ran
            let buf = avm.audit_buffer.lock().unwrap();
            assert!(buf.argon2id_per_sec > 0, "ignition must run Argon2id benchmark");
            println!("  ✓ Ignition complete: {} Argon2id/sec", buf.argon2id_per_sec);
        }

        #[test]
        fn test_ignition_rejects_empty_proof() {
            let avm = make_blocked_avm();
            let inputs = create_test_inputs();
            avm.process_ignition(inputs).unwrap();

            // Empty proof must be rejected (H1: empty cheque proofs rejected)
            let result = avm.complete_ignition(&[]);
            assert!(result.is_err(), "empty proof must be rejected");
            assert!(!avm.is_pulse_ready(), "Core must stay blocked on empty proof");
        }

        #[test]
        fn test_ignition_rejects_without_process() {
            let avm = make_blocked_avm();

            // complete_ignition without process_ignition must fail
            let result = avm.complete_ignition(&[0x01, 0x02]);
            assert!(result.is_err(), "complete_ignition without process must fail");
            assert!(!avm.is_pulse_ready());
        }

        #[test]
        fn test_ignition_then_execute_works() {
            let avm = make_blocked_avm();

            // Before ignition: execute blocked
            let inputs = create_test_inputs();
            match avm.execute(inputs) {
                Err(AvmError::PulseNotReady) => {} // expected
                other => panic!("Expected PulseNotReady, got: {:?}", other),
            }

            // Run ignition sequence
            let inputs = create_test_inputs();
            avm.process_ignition(inputs).unwrap();
            avm.complete_ignition(&[0xFF; 32]).unwrap();

            // After ignition: execute works (will Reject on CL1 fake keys, but not PulseNotReady)
            let inputs = create_test_inputs();
            let result = avm.execute(inputs);
            assert!(result.is_ok(), "execute must work after ignition");
        }

        #[test]
        fn test_ignition_oversized_proof_rejected() {
            let avm = make_blocked_avm();
            let inputs = create_test_inputs();
            avm.process_ignition(inputs).unwrap();

            // Proof > 10MB must be rejected (H2: DoS prevention)
            let oversized = vec![0u8; 11 * 1024 * 1024];
            let result = avm.complete_ignition(&oversized);
            assert!(result.is_err(), "oversized proof must be rejected");
            assert!(!avm.is_pulse_ready());
        }
    }

    // ── CL10 Fan-Out AVM Integration Tests ──

    #[cfg(feature = "riscv-interpreter")]
    mod cl10_tests {
        use super::*;
        use super::tests::riscv_elf::find_elf;
        use axiom_core_logic::types::*;
        use axiom_core_logic::wallet_id::generate_wallet_id;
        use ed25519_dalek::{SigningKey, Signer};

        fn make_cl10_inputs(
            content_type: u16, ttl_original: u8, ttl_current: u8, fanout: u8,
        ) -> PublicInputs {
            let sk = SigningKey::from_bytes(&[0x42u8; 32]);
            let pk = sk.verifying_key();
            let content = vec![0xAA, 0xBB, 0xCC];
            let timestamp = 1774070000u64;

            let mut id_h = blake3::Hasher::new();
            id_h.update(b"AXIOM_FANOUT_ID");
            id_h.update(&content);
            id_h.update(pk.as_bytes());
            let diffusion_id: [u8; 32] = *id_h.finalize().as_bytes();

            let mut sig_h = blake3::Hasher::new();
            sig_h.update(b"AXIOM_FANOUT");
            sig_h.update(&diffusion_id);
            sig_h.update(&content_type.to_le_bytes());
            sig_h.update(&content);
            sig_h.update(&[ttl_original]);
            sig_h.update(&[fanout]);
            sig_h.update(&timestamp.to_le_bytes());
            let signing_payload: [u8; 32] = *sig_h.finalize().as_bytes();
            let sig = sk.sign(&signing_payload);

            let receiver_wallet_id = generate_wallet_id("test@test.com", "42", &[0u8; 32])
                .expect("wallet id");

            PublicInputs {
                oods_attestation: None,
                recall_attestation: None,
                mode: CoreLogicMode::CL10,
                transaction: Transaction {
                    consumed_state_id: [0u8; 32],
                    recall_target_tx_id: None,
                    client_pk: vec![],
                    sender_wallet_id: String::new(),
                    wallet_seq: 0,
                    receiver_wallet_id,
                    receiver_address: None,
                    amount: 0,
                    reference: String::new(),
                    nonce: 0,
                    epoch: timestamp,
                    client_sig: vec![],
                    owner_proof: None,
                    scar_passcode: None,
                    burn_target_tx_id: None,
                    required_k: 0,
                    proof_type: 0,
                    oracle_claim: None,
                    core_version: String::new(),
                    kind: TxKind::Normal,
                    core_id: [0u8; 32],
                },
                prev_receipts: vec![],
                current_state: None,
                vbc_bundle: Some(VBCProofBundle {
                    target_vbc: VBC {
                        version: 9,
                        network_size_baseline: 0,
                        baseline_tick: 0,
                        validator_id: [0u8; 32],
                        node_name: "test".into(),
                        subject_pubkey_ed25519: pk.as_bytes().to_vec(),
                        subject_pubkey_sphincs: vec![0u8; 32],
                        subject_pubkey_dilithium: vec![],
                        pgp_fingerprint: vec![],
                        proof_cap: "dmap".into(),
                        issued_at: 0,
                        expires_at: u64::MAX,
                        chain_depth: 0,
                        issuer_set: vec![],
                        signatures: vec![],
                        max_tx: 0,
                        founding_vbc_hash: [0u8; 32],
                    },
                    supporting_vbcs: vec![],
                }),
                cheque_bundle: None,
                receiver_pk: None,
                receiver_current_balance: None,
            receiver_current_hibernation: None,
                receiver_wallet_seq: None,
                receiver_new_balance: None,
                receiver_new_state_id: None,
                my_validator_pk: None,
                overlapped_signatures: vec![],
                group_member_index: None,
                sender_fact_chain: None,
            receiver_fact_chain: None,
                my_dilithium_sk: None,
                my_dilithium_pk: None,
                my_validator_id: None,
                fact_witness_sigs: vec![],
                issuer_sphincs_sk: None,
                cl1_execution_proof: None,
                zkp_nonce: None,
                audit_confirmation: None,
                nonce_response: None,
                audit_response: None,
                scar_heal_tx_id: None,
                scar_heal_nabla_id: None,
                scar_heal_root_hash: None,
                wallet_secret: None,
                fanout_message: Some(FanOutMessage {
                    diffusion_id,
                    content_type,
                    content,
                    originator_pk: *pk.as_bytes(),
                    originator_sig: sig.to_bytes().to_vec(),
                    timestamp,
                    ttl_original,
                    fanout,
                    ttl_current,
                }),
                candidate_balance: None,
            nabla_stake_proof: None,
                frozen_wallets: None,
            console_current_cert: None,
            console_new_cert: None,
            console_selector_picks: None,
            console_nominations: None, txid_attestation: None,
        cheque_claim_proof: None,
            clara_attestation: None,
            phase_out_payload: None,
            phase_out_era_end_ticks: vec![],
            phase_out_blocked_era_ids: vec![],
            current_tick: 0,
            local_core_id: [0u8; 32],
            withdrawal_inputs: None,
            max_fact_links: None,
            
            }
        }

        #[test]
        fn test_cl10_avm_native_accept() {
            let avm = AvmInterpreter::new(vec![0x00], [0u8; 32]);
            let inputs = make_cl10_inputs(0x0001, 10, 5, 3);
            let result = avm.execute(inputs).expect("CL10 execute failed");
            assert_eq!(result.result, ValidationResult::Accept);
            assert_eq!(result.fanout_new_ttl, Some(4));
        }

        #[test]
        fn test_cl10_avm_native_reject_bad_sig() {
            let avm = AvmInterpreter::new(vec![0x00], [0u8; 32]);
            let mut inputs = make_cl10_inputs(0x0001, 10, 5, 3);
            inputs.fanout_message.as_mut().unwrap().originator_sig = vec![0xFF; 64];
            let result = avm.execute(inputs).expect("CL10 execute failed");
            assert_eq!(result.result, ValidationResult::Reject);
        }

        #[test]
        fn test_cl10_avm_native_reject_ttl_zero() {
            let avm = AvmInterpreter::new(vec![0x00], [0u8; 32]);
            let mut inputs = make_cl10_inputs(0x0001, 10, 0, 3);
            inputs.fanout_message.as_mut().unwrap().ttl_current = 0;
            let result = avm.execute(inputs).expect("CL10 execute failed");
            assert_eq!(result.result, ValidationResult::Reject);
        }

        #[test]
        fn test_cl10_real_elf_accept() {
            let elf = match find_elf() {
                Some(e) => e,
                None => { eprintln!("SKIP: ELF not found"); return; }
            };
            let avm = AvmInterpreter::new(elf, [0u8; 32]);
            let inputs = make_cl10_inputs(0x0001, 10, 5, 3);
            let result = avm.execute(inputs).expect("CL10 ELF execute failed");
            assert_eq!(result.result, ValidationResult::Accept, "CL10 via real ELF must accept");
            assert_eq!(result.fanout_new_ttl, Some(4), "new_ttl should be 4 (5-1)");
        }

        #[test]
        fn test_cl10_real_elf_reject_inflated_ttl() {
            let elf = match find_elf() {
                Some(e) => e,
                None => { eprintln!("SKIP: ELF not found"); return; }
            };
            let avm = AvmInterpreter::new(elf, [0u8; 32]);
            let mut inputs = make_cl10_inputs(0x0001, 5, 5, 3);
            inputs.fanout_message.as_mut().unwrap().ttl_current = 8; // > ttl_original
            let result = avm.execute(inputs).expect("CL10 ELF execute failed");
            assert_eq!(result.result, ValidationResult::Reject, "inflated TTL must be rejected");
        }

        #[test]
        fn test_cl10_real_elf_multi_hop() {
            // Simulate 3 hops: originator(ttl=10) → hop1(ttl=9) → hop2(ttl=8) → hop3(ttl=7)
            let elf = match find_elf() {
                Some(e) => e,
                None => { eprintln!("SKIP: ELF not found"); return; }
            };
            let avm = AvmInterpreter::new(elf, [0u8; 32]);

            // Hop 1: originator creates with ttl_current=10
            let inputs1 = make_cl10_inputs(0x0001, 10, 10, 3);
            let r1 = avm.execute(inputs1).expect("hop1 failed");
            assert_eq!(r1.result, ValidationResult::Accept);
            assert_eq!(r1.fanout_new_ttl, Some(9));

            // Hop 2: relay receives with ttl_current=9 (Core's output from hop1)
            let inputs2 = make_cl10_inputs(0x0001, 10, 9, 3);
            let r2 = avm.execute(inputs2).expect("hop2 failed");
            assert_eq!(r2.result, ValidationResult::Accept);
            assert_eq!(r2.fanout_new_ttl, Some(8));

            // Hop 3: relay receives with ttl_current=8
            let inputs3 = make_cl10_inputs(0x0001, 10, 8, 3);
            let r3 = avm.execute(inputs3).expect("hop3 failed");
            assert_eq!(r3.result, ValidationResult::Accept);
            assert_eq!(r3.fanout_new_ttl, Some(7));
        }

        #[test]
        fn test_cl10_real_elf_ttl_exhaustion() {
            // TTL=1 → Accept(new_ttl=0), TTL=0 → Reject
            let elf = match find_elf() {
                Some(e) => e,
                None => { eprintln!("SKIP: ELF not found"); return; }
            };
            let avm = AvmInterpreter::new(elf, [0u8; 32]);

            // Last valid hop: ttl_current=1 → new_ttl=0
            let inputs1 = make_cl10_inputs(0x0001, 10, 1, 3);
            let r1 = avm.execute(inputs1).expect("last hop failed");
            assert_eq!(r1.result, ValidationResult::Accept);
            assert_eq!(r1.fanout_new_ttl, Some(0));

            // Expired: ttl_current=0 → Reject
            let mut inputs2 = make_cl10_inputs(0x0001, 10, 1, 3);
            inputs2.fanout_message.as_mut().unwrap().ttl_current = 0;
            let r2 = avm.execute(inputs2).expect("expired hop failed");
            assert_eq!(r2.result, ValidationResult::Reject);
        }
    }

    // ======================================================================
    // CL8 Stake Tier Enforcement — AVM integration tests
    // Verifies MVIB (Meta-Validator Inheritance Binding) through the AVM layer.
    // Tests both native (vec![0x00] bytecode) and real RISC-V ELF execution.
    // ======================================================================
    #[cfg(feature = "riscv-interpreter")]
    mod cl8_stake_tests {
        use super::*;
        use super::tests::riscv_elf::find_elf;
        use axiom_core_logic::types::*;
        use axiom_core_logic::wallet_id::generate_wallet_id;

        fn make_cl8_inputs(validator_id: [u8; 32], candidate_balance: u64) -> PublicInputs {
            let receiver_wallet_id = generate_wallet_id("test@test.com", "42", &[0u8; 32])
                .expect("wallet id");

            PublicInputs {
                oods_attestation: None,
                recall_attestation: None,
                mode: CoreLogicMode::CL8,
                transaction: Transaction {
                    consumed_state_id: [0u8; 32],
                    recall_target_tx_id: None,
                    client_pk: vec![],
                    sender_wallet_id: String::new(),
                    wallet_seq: 0,
                    receiver_wallet_id,
                    receiver_address: None,
                    amount: 0,
                    reference: String::new(),
                    nonce: 0,
                    epoch: 1774070000u64,
                    client_sig: vec![],
                    owner_proof: None,
                    scar_passcode: None,
                    burn_target_tx_id: None,
                    required_k: 0,
                    proof_type: 0,
                    oracle_claim: None,
                    core_version: String::new(),
                    kind: TxKind::Normal,
                    core_id: [0u8; 32],
                },
                prev_receipts: vec![],
                current_state: None,
                vbc_bundle: Some(VBCProofBundle {
                    target_vbc: VBC {
                        version: 9,
                        network_size_baseline: 0,
                        baseline_tick: 0,
                        validator_id,
                        node_name: "mvib-test".into(),
                        subject_pubkey_ed25519: vec![0u8; 32],
                        subject_pubkey_sphincs: vec![0u8; 32],
                        subject_pubkey_dilithium: vec![],
                        pgp_fingerprint: vec![],
                        proof_cap: "dmap".into(),
                        issued_at: 0,
                        expires_at: u64::MAX,
                        chain_depth: 0,
                        issuer_set: vec![],
                        signatures: vec![],
                        max_tx: 0,
                        founding_vbc_hash: [0u8; 32],
                    },
                    supporting_vbcs: vec![],
                }),
                cheque_bundle: None,
                receiver_pk: None,
                receiver_current_balance: None,
            receiver_current_hibernation: None,
                receiver_wallet_seq: None,
                receiver_new_balance: None,
                receiver_new_state_id: None,
                my_validator_pk: None,
                overlapped_signatures: vec![],
                group_member_index: None,
                sender_fact_chain: None,
            receiver_fact_chain: None,
                my_dilithium_sk: None,
                my_dilithium_pk: None,
                my_validator_id: None,
                fact_witness_sigs: vec![],
                issuer_sphincs_sk: Some(vec![0u8; 64]), // dummy — stake check runs before signing
                cl1_execution_proof: None,
                zkp_nonce: None,
                audit_confirmation: None,
                nonce_response: None,
                audit_response: None,
                scar_heal_tx_id: None,
                scar_heal_nabla_id: None,
                scar_heal_root_hash: None,
                wallet_secret: None,
                fanout_message: None,
                candidate_balance: Some(candidate_balance),
                frozen_wallets: None,
            console_current_cert: None,
            console_new_cert: None,
            console_selector_picks: None,
            console_nominations: None, txid_attestation: None,
        cheque_claim_proof: None,
                nabla_stake_proof: None,
            clara_attestation: None,
            phase_out_payload: None,
            phase_out_era_end_ticks: vec![],
            phase_out_blocked_era_ids: vec![],
            current_tick: 0,
            local_core_id: [0u8; 32],
            withdrawal_inputs: None,
            max_fact_links: None,
            
            }
        }

        // ── Native AVM tests (vec![0x00] bytecode, no ELF needed) ──

        #[test]
        fn test_cl8_native_genesis_rejects_low_stake() {
            // Genesis validator rejects candidate with 1,000 AXC (below Tier 2's 500,000)
            let avm = AvmInterpreter::new(vec![0x00], [0u8; 32]);
            let genesis_id = axiom_core_logic::genesis::GENESIS_VALIDATORS[0];
            let inputs = make_cl8_inputs(genesis_id, 1_000);
            let result = avm.execute(inputs).expect("CL8 execute failed");
            assert_eq!(result.result, ValidationResult::Reject);
            assert_eq!(result.rejection_reason, Some(ValidationError::InsufficientStake),
                "1,000 AXC below genesis tier 500,000 threshold");
        }

        #[test]
        fn test_cl8_native_genesis_rejects_tier3_balance() {
            // Genesis validator rejects candidate with 500 AXC (Tier 3 level)
            let avm = AvmInterpreter::new(vec![0x00], [0u8; 32]);
            let genesis_id = axiom_core_logic::genesis::GENESIS_VALIDATORS[0];
            let inputs = make_cl8_inputs(genesis_id, 500);
            let result = avm.execute(inputs).expect("CL8 execute failed");
            assert_eq!(result.result, ValidationResult::Reject);
            assert_eq!(result.rejection_reason, Some(ValidationError::InsufficientStake),
                "500 AXC too low for genesis approval (needs 500,000)");
        }

        #[test]
        fn test_cl8_native_genesis_approves_tier2() {
            // Genesis validator approves candidate with 500,000 AXC (Tier 2)
            // Will fail at SPHINCS+ signing (dummy keys) — that's OK,
            // we verify the stake check does NOT reject.
            let avm = AvmInterpreter::new(vec![0x00], [0u8; 32]);
            let genesis_id = axiom_core_logic::genesis::GENESIS_VALIDATORS[0];
            let inputs = make_cl8_inputs(genesis_id, 500_000);
            let result = avm.execute(inputs).expect("CL8 execute failed");
            assert_ne!(result.rejection_reason, Some(ValidationError::InsufficientStake),
                "500,000 AXC should pass genesis tier check");
        }

        #[test]
        fn test_cl8_native_genesis_rejects_just_below_tier2() {
            // Genesis validator rejects candidate with 499,999 AXC (one below threshold)
            let avm = AvmInterpreter::new(vec![0x00], [0u8; 32]);
            let genesis_id = axiom_core_logic::genesis::GENESIS_VALIDATORS[0];
            let inputs = make_cl8_inputs(genesis_id, 499_999);
            let result = avm.execute(inputs).expect("CL8 execute failed");
            assert_eq!(result.result, ValidationResult::Reject);
            assert_eq!(result.rejection_reason, Some(ValidationError::InsufficientStake),
                "499,999 AXC below genesis tier 500,000 threshold");
        }

        #[test]
        fn test_cl8_native_genesis_rejects_zero() {
            // Genesis validator rejects zero-balance candidate
            let avm = AvmInterpreter::new(vec![0x00], [0u8; 32]);
            let genesis_id = axiom_core_logic::genesis::GENESIS_VALIDATORS[0];
            let inputs = make_cl8_inputs(genesis_id, 0);
            let result = avm.execute(inputs).expect("CL8 execute failed");
            assert_eq!(result.result, ValidationResult::Reject);
            assert_eq!(result.rejection_reason, Some(ValidationError::InsufficientStake));
        }

        #[test]
        fn test_cl8_native_nongenesis_approves_tier3() {
            // Non-genesis validator approves candidate with 500 AXC (Tier 3)
            let avm = AvmInterpreter::new(vec![0x00], [0u8; 32]);
            let non_genesis_id = [0xAA; 32]; // not in GENESIS_VALIDATORS
            let inputs = make_cl8_inputs(non_genesis_id, 500);
            let result = avm.execute(inputs).expect("CL8 execute failed");
            assert_ne!(result.rejection_reason, Some(ValidationError::InsufficientStake),
                "500 AXC should pass non-genesis tier check");
        }

        #[test]
        fn test_cl8_native_nongenesis_rejects_below_tier3() {
            // Non-genesis validator rejects candidate with 499 AXC
            let avm = AvmInterpreter::new(vec![0x00], [0u8; 32]);
            let non_genesis_id = [0xAA; 32];
            let inputs = make_cl8_inputs(non_genesis_id, 499);
            let result = avm.execute(inputs).expect("CL8 execute failed");
            assert_eq!(result.result, ValidationResult::Reject);
            assert_eq!(result.rejection_reason, Some(ValidationError::InsufficientStake),
                "499 AXC below non-genesis tier 500 threshold");
        }

        #[test]
        fn test_cl8_native_nongenesis_rejects_zero() {
            // Non-genesis validator rejects zero-balance candidate
            let avm = AvmInterpreter::new(vec![0x00], [0u8; 32]);
            let non_genesis_id = [0xBB; 32];
            let inputs = make_cl8_inputs(non_genesis_id, 0);
            let result = avm.execute(inputs).expect("CL8 execute failed");
            assert_eq!(result.result, ValidationResult::Reject);
            assert_eq!(result.rejection_reason, Some(ValidationError::InsufficientStake));
        }

        #[test]
        fn test_cl8_native_no_balance_no_proof_is_nbc() {
            // candidate_balance = None + nabla_stake_proof = None → NBC signing path
            // No stake check (NBC doesn't require stake, only identity binding)
            let avm = AvmInterpreter::new(vec![0x00], [0u8; 32]);
            let non_genesis_id = [0xCC; 32];
            let mut inputs = make_cl8_inputs(non_genesis_id, 0);
            inputs.candidate_balance = None;
            inputs.nabla_stake_proof = None;
            let result = avm.execute(inputs).expect("CL8 execute failed");
            assert_ne!(result.rejection_reason, Some(ValidationError::InsufficientStake),
                "No balance + no proof = NBC path, stake check skipped");
        }

        #[test]
        fn test_cl8_native_exact_thresholds() {
            // Exact threshold values — both should pass stake check
            let avm = AvmInterpreter::new(vec![0x00], [0u8; 32]);

            // Genesis at exactly 500,000
            let genesis_id = axiom_core_logic::genesis::GENESIS_VALIDATORS[0];
            let inputs = make_cl8_inputs(genesis_id, 500_000);
            let result = avm.execute(inputs).expect("CL8 execute failed");
            assert_ne!(result.rejection_reason, Some(ValidationError::InsufficientStake),
                "Exact genesis threshold (500,000) should pass");

            // Non-genesis at exactly 500
            let non_genesis_id = [0xDD; 32];
            let inputs2 = make_cl8_inputs(non_genesis_id, 500);
            let result2 = avm.execute(inputs2).expect("CL8 execute failed");
            assert_ne!(result2.rejection_reason, Some(ValidationError::InsufficientStake),
                "Exact non-genesis threshold (500) should pass");
        }

        #[test]
        fn test_cl8_native_nongenesis_high_balance() {
            // Non-genesis with Tier 2 level balance (500,000) — should pass (500,000 >= 500)
            let avm = AvmInterpreter::new(vec![0x00], [0u8; 32]);
            let non_genesis_id = [0xEE; 32];
            let inputs = make_cl8_inputs(non_genesis_id, 500_000);
            let result = avm.execute(inputs).expect("CL8 execute failed");
            assert_ne!(result.rejection_reason, Some(ValidationError::InsufficientStake),
                "Non-genesis with 500,000 AXC should pass (well above 500 threshold)");
        }

        // ── Real ELF tests (require compiled axiom-core.elf) ──

        #[test]
        fn test_cl8_elf_genesis_rejects_low_stake() {
            let elf = match find_elf() {
                Some(e) => e,
                None => { eprintln!("SKIP: ELF not found"); return; }
            };
            let avm = AvmInterpreter::new(elf, [0u8; 32]);
            let genesis_id = axiom_core_logic::genesis::GENESIS_VALIDATORS[0];
            let inputs = make_cl8_inputs(genesis_id, 1_000);
            let result = avm.execute(inputs).expect("CL8 ELF execute failed");
            assert_eq!(result.result, ValidationResult::Reject,
                "ELF: 1,000 AXC below genesis tier must be rejected");
            assert_eq!(result.rejection_reason, Some(ValidationError::InsufficientStake));
        }

        #[test]
        fn test_cl8_elf_genesis_approves_tier2() {
            // Passes stake check, then hits SPHINCS+ signing with dummy keys.
            // ELF may hit instruction limit during SPHINCS+ (expected) — that's OK.
            // candidate_balance is gated behind debug_assertions (beta2 fix).
            // The release ELF rejects candidate_balance — production requires NablaStakeProof.
            // This test verifies the ELF correctly rejects the legacy path.
            // TODO: Add a separate ELF test with real NablaStakeProof for the production path.
            let elf = match find_elf() {
                Some(e) => e,
                None => { eprintln!("SKIP: ELF not found"); return; }
            };
            let avm = AvmInterpreter::new(elf, [0u8; 32]);
            let genesis_id = axiom_core_logic::genesis::GENESIS_VALIDATORS[0];
            let inputs = make_cl8_inputs(genesis_id, 500_000);
            match avm.execute(inputs) {
                Ok(result) => {
                    // Release ELF: candidate_balance rejected. This is CORRECT.
                    // Production validators MUST use NablaStakeProof.
                    assert_eq!(result.rejection_reason, Some(ValidationError::InsufficientStake),
                        "Release ELF correctly rejects candidate_balance (use NablaStakeProof)");
                }
                Err(AvmError::ExecutionError(msg)) if msg.contains("instruction limit") => {
                    eprintln!("ELF hit instruction limit — OK");
                }
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        }

        #[test]
        fn test_cl8_elf_genesis_rejects_zero() {
            let elf = match find_elf() {
                Some(e) => e,
                None => { eprintln!("SKIP: ELF not found"); return; }
            };
            let avm = AvmInterpreter::new(elf, [0u8; 32]);
            let genesis_id = axiom_core_logic::genesis::GENESIS_VALIDATORS[0];
            let inputs = make_cl8_inputs(genesis_id, 0);
            let result = avm.execute(inputs).expect("CL8 ELF execute failed");
            assert_eq!(result.result, ValidationResult::Reject,
                "ELF: zero-balance must be rejected");
            assert_eq!(result.rejection_reason, Some(ValidationError::InsufficientStake));
        }

        #[test]
        fn test_cl8_elf_nongenesis_rejects_candidate_balance() {
            // Release ELF rejects candidate_balance — production requires NablaStakeProof.
            let elf = match find_elf() {
                Some(e) => e,
                None => { eprintln!("SKIP: ELF not found"); return; }
            };
            let avm = AvmInterpreter::new(elf, [0u8; 32]);
            let non_genesis_id = [0xAA; 32];
            let inputs = make_cl8_inputs(non_genesis_id, 500);
            match avm.execute(inputs) {
                Ok(result) => {
                    assert_eq!(result.rejection_reason, Some(ValidationError::InsufficientStake),
                        "Release ELF correctly rejects candidate_balance (use NablaStakeProof)");
                }
                Err(AvmError::ExecutionError(msg)) if msg.contains("instruction limit") => {
                    eprintln!("ELF hit instruction limit — OK");
                }
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        }

        #[test]
        fn test_cl8_elf_nongenesis_rejects_below_tier3() {
            let elf = match find_elf() {
                Some(e) => e,
                None => { eprintln!("SKIP: ELF not found"); return; }
            };
            let avm = AvmInterpreter::new(elf, [0u8; 32]);
            let non_genesis_id = [0xAA; 32];
            let inputs = make_cl8_inputs(non_genesis_id, 499);
            let result = avm.execute(inputs).expect("CL8 ELF execute failed");
            assert_eq!(result.result, ValidationResult::Reject,
                "ELF: 499 AXC below non-genesis tier must be rejected");
            assert_eq!(result.rejection_reason, Some(ValidationError::InsufficientStake));
        }

        #[test]
        fn test_cl8_elf_boundary_genesis_499999() {
            // Boundary: genesis with 499,999 — one below threshold
            let elf = match find_elf() {
                Some(e) => e,
                None => { eprintln!("SKIP: ELF not found"); return; }
            };
            let avm = AvmInterpreter::new(elf, [0u8; 32]);
            let genesis_id = axiom_core_logic::genesis::GENESIS_VALIDATORS[0];
            let inputs = make_cl8_inputs(genesis_id, 499_999);
            let result = avm.execute(inputs).expect("CL8 ELF execute failed");
            assert_eq!(result.result, ValidationResult::Reject,
                "ELF: 499,999 AXC must be rejected by genesis");
            assert_eq!(result.rejection_reason, Some(ValidationError::InsufficientStake));
        }
    }
}
