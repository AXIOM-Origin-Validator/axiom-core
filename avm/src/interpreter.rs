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

        let _host = HostFunctions::new();
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

        let _host = HostFunctions::new();
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

        let host = HostFunctions::new();

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
    /// The validated-tick watermark at DISPATCH (`mark_peer_audit_dispatched`).
    /// B's response deadline is `PEER_AUDIT_TIMEOUT_TICKS` past this, measured
    /// against `last_validated_tick` — a TICK count, never wall clock (§23.14.1
    /// tick discipline; the `Instant`-based `PEER_AUDIT_TIMEOUT_SECS` arm was
    /// retired 2026-09-24). Set at dispatch, not at arming: B has nothing to
    /// answer until A has actually sent the request. Peer-audits only.
    dispatched_at_tick: Option<u64>,
    /// The expected hash for peer-audit verification.
    /// Computed by Core from audit buffer, sent to remote, compared on return.
    peer_expected_hash: Option<[u8; 32]>,
    /// §23.14 — whether Lambda has actually HANDED the peer-audit request to
    /// the carrier (`mark_peer_audit_dispatched`). Peer-audits only.
    ///
    /// Until 2026-09-24 the AVM had no notion of this: the countdown and the
    /// wall-clock deadline ran from the DEMAND, and at expiry the TARGET was
    /// banned `NonResponds` whether or not a request had ever left this node.
    /// Measured live (tier C, `ab98b539`): Lambda's target lookup could never
    /// match (KI#207 — it keyed on the wrong hint column), so `0 sent` and
    /// **32 innocent co-witnesses banned** in one run, each ban rejecting every
    /// TX they witnessed for 24 h. That is the exact griefing the §23.14.1
    /// silence ruling forbids: a ban must follow an ATTRIBUTABLE failure of B,
    /// and a request A never sent is attributable only to A. So:
    ///   - `dispatched == true`  → B's silence past the full budget → ban B.
    ///   - `dispatched == false` → A did not initiate the audit Core demanded
    ///     → §23.14 "if Lambda does not comply within a countdown window, the
    ///     DMAP-VM terminates Core" — `AuditTimeout`, A's own penalty, never
    ///     a ban of B.
    /// Host-only state (like `remaining`): never written to `PublicOutputs`,
    /// so re-executors see identical outputs — CoreID-neutral.
    dispatched: bool,
    /// SELF-audit only: the digest of the triggering execution, fixed at
    /// arming. Lambda's confirmation (its DB record for `trigger_txid`) is
    /// judged against THIS, never against a ring lookup.
    ///
    /// ⚠ WRONG READING, live until 2026-09-24: the self branch looked the
    /// trigger up in the audit ring by `trigger_tx_number` — taken from
    /// `tx_counter` BEFORE the tx was accumulated (the previous entry), and the
    /// pulse audit clears the ring after every accepted tx — so a correct
    /// confirmation could never verify after a reset ("TX not in buffer =
    /// fail") and the countdown self-terminated. the owner 2026-09-24: "we should
    /// get the self audit fixed" — this is the fix; `trigger_tx_number` is kept
    /// for admin display only.
    self_expected_digest: Option<axiom_core_logic::types::TxDigest>,
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
/// Argon2id uses 32MB per call (m_cost = 32768, see `argon2id_hash`) — exceeds L3
/// cache on commodity hardware, forcing main memory access. Two validators on one
/// machine = 64MB active → memory bus contention.
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
    /// Measured Argon2id(32MB,t=1) throughput on this hardware.
    /// Reported in PulseProofData for peer validation.
    argon2id_per_sec: u64,
}

/// §23.14.6: the peer-audit ban window on the tick-stamp scale (seconds):
/// `PEER_AUDIT_BAN_TICKS × TICK_INTERVAL_SECS` — 86 400 on a real build, 3 600
/// on a `dev-mode` build. THE one source for both the expiry check and every
/// message that states the duration.
pub fn peer_audit_ban_window_secs() -> u64 {
    axiom_core_logic::types::PEER_AUDIT_BAN_TICKS
        .saturating_mul(axiom_core_logic::types::TICK_INTERVAL_SECS)
}

/// Human wording of the ban window for log lines and rejection text ("1 h",
/// "24 h", "90 min"). Replaces a hardcoded "24 hours" that was wrong on every
/// dev build (the dev ban is 1 h, `peer_audit_ban_ticks_dev`, 2026-09-26).
pub fn peer_audit_ban_duration_text() -> String {
    duration_text(peer_audit_ban_window_secs())
}

fn duration_text(secs: u64) -> String {
    if secs >= 3600 && secs % 3600 == 0 {
        format!("{} h", secs / 3600)
    } else if secs >= 60 && secs % 60 == 0 {
        format!("{} min", secs / 60)
    } else {
        format!("{} s", secs)
    }
}

/// §5.2.2e — an unsigned self-audit Pulse (see `AuditBuffer::self_audit_pulse`).
/// The SDK / `validator-setup` sign it into a `PulseProofRequest`.
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct SelfAuditPulse {
    /// The Nabla-attested tick the chain was seeded with (part iii).
    pub tick: u64,
    pub epoch: u64,
    pub full_accumulator: [u8; 32],
    pub entry_count: u32,
    pub sample_size: u32,
    pub audit_hash: [u8; 32],
    pub argon2id_per_sec: u64,
}

/// §5.2.2e — produce the candidacy self-audit for `validator_pk` (the stake
/// wallet's key) at `epoch`, over `entries` synthetic digests.
#[cfg(feature = "std")]
pub fn self_audit_pulse(validator_pk: &[u8; 32], tick: u64, entries: u32) -> SelfAuditPulse {
    AuditBuffer::self_audit_pulse(validator_pk, tick, entries)
}

/// §5.2.2e part iii — the issuers' native replay of a candidacy proof's
/// Fiat-Shamir sample (see `AuditBuffer::verify_self_audit_sample`).
#[cfg(feature = "std")]
pub fn verify_self_audit_sample(validator_pk: &[u8; 32], tick: u64, entry_count: u32, sample_size: u32, full_accumulator: &[u8; 32], audit_hash: &[u8; 32]) -> Result<(), &'static str> {
    AuditBuffer::verify_self_audit_sample(validator_pk, tick, entry_count, sample_size, full_accumulator, audit_hash)
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
    /// Measures Argon2id(32MB,t=1) throughput for PULSE_CALIBRATION_MS.
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

        // Always run at least 1 iteration — Argon2id(32MB) may exceed cal_ms in debug
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

        // Fiat-Shamir selection seed — THE builder (KI#55 B2#2).
        let seed = audit_select_seed(&self.accumulator, validator_pk);

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
    /// KI#55 B2#2 (2026-10-02): the prover's chain IS the verifier's replay —
    /// one loop (`replay_chain_from_raw`) over the selected entries, not a hand-
    /// matched copy of it.
    fn compute_subset_hash(&self, indices: &[u32]) -> [u8; 32] {
        let selected: Vec<TxDigest> = indices.iter()
            .map(|&idx| self.entries[idx as usize].clone())
            .collect();
        Self::replay_chain_from_raw(&selected)
    }

    /// Replay Argon2id→BLAKE3 chain from raw TxDigest entries (self-audit verification).
    /// Same algorithm as compute_subset_hash, but operates on Lambda's raw DB data
    /// instead of buffer indices. Lambda does zero crypto — Core replays everything.
    /// §5.2.2e — SELF-AUDIT. The candidacy Pulse a machine produces WITHOUT
    /// any validation role (the owner, 2026-09-09: "never accept an uncertified
    /// node taking part in validation"): the same Argon2id→BLAKE3 chain,
    /// the same Fiat-Shamir request and the same replay a live audit uses,
    /// run over `entries` synthetic digests derived from the candidate's own
    /// key. The cost is real (entries × 32 MB Argon2id); the proof carries
    /// the measured throughput. The caller signs the result with the key
    /// (`pulse::pulse_proof_sign_payload`). `epoch` = the request's tick /
    /// PULSE_EPOCH_LENGTH_TICKS.
    /// `tick` = the Nabla-attested tick of the request round (part iii,
    /// KI#142): entry `i` is `pulse::self_audit_entry_seed(pk, tick, i)`, so a
    /// new round is a new chain and the work cannot be re-signed later.
    pub fn self_audit_pulse(validator_pk: &[u8; 32], tick: u64, entries: u32) -> SelfAuditPulse {
        let epoch = axiom_core_logic::pulse::pulse_epoch_of_tick(tick);
        let mut buf = AuditBuffer::new();
        buf.self_benchmark();
        for i in 0..entries {
            buf.accumulate(Self::self_audit_entry(validator_pk, tick, i));
        }
        let request = buf.generate_request(validator_pk, epoch);
        let selected: Vec<TxDigest> = request.selected_indices.iter()
            .map(|&i| buf.entries[i as usize].clone()).collect();
        let audit_hash = Self::replay_chain_from_raw(&selected);
        debug_assert_eq!(audit_hash, request.expected_hash, "self-audit replay must match its own request");
        SelfAuditPulse {
            tick,
            epoch,
            full_accumulator: buf.accumulator,
            entry_count: entries,
            sample_size: selected.len() as u32,
            audit_hash,
            argon2id_per_sec: buf.argon2id_per_sec,
        }
    }

    /// The synthetic entry `i` of a self-audit — ONE derivation for the
    /// producer above and the issuers' replay below.
    fn self_audit_entry(validator_pk: &[u8; 32], tick: u64, i: u32) -> TxDigest {
        TxDigest {
            tx_number: i as u64 + 1,
            sender_balance: 0,
            receiver_balance: 0,
            state_id: axiom_core_logic::pulse::self_audit_entry_seed(validator_pk, tick, i),
            amount: 0,
        }
    }

    /// §5.2.2e part iii — an ISSUER replays the Fiat-Shamir sample a candidacy
    /// proof claims, natively, before Core signs. The selection is derived
    /// from the proof itself (`AXIOM_AUDIT_SELECT` ‖ full_accumulator ‖ pk —
    /// the same seed `generate_request` uses), the selected entries are
    /// regenerated from `(pk, tick, i)`, and the Argon2id→BLAKE3 replay must
    /// reproduce `audit_hash`. Cost = sample × 32 MB Argon2id (7 of 64 ≈ 0.2 s
    /// on this box) — Core cannot pay it in the guest; the issuer can. The
    /// accumulator itself is not replayed: grinding it costs the full chain.
    pub fn verify_self_audit_sample(
        validator_pk: &[u8; 32],
        tick: u64,
        entry_count: u32,
        sample_size: u32,
        full_accumulator: &[u8; 32],
        audit_hash: &[u8; 32],
    ) -> Result<(), &'static str> {
        if entry_count == 0 { return Err("empty audit"); }
        let expected_sample = (entry_count as f64 * PULSE_SAMPLE_RATIO).ceil().max(1.0) as u32;
        if sample_size != expected_sample.min(entry_count) { return Err("sample size is not the protocol's for this entry count"); }
        let seed = audit_select_seed(full_accumulator, validator_pk);
        let selected = fiat_shamir_select(&seed, entry_count, sample_size);
        let entries: Vec<TxDigest> = selected.iter().map(|&i| Self::self_audit_entry(validator_pk, tick, i)).collect();
        if Self::replay_chain_from_raw(&entries) != *audit_hash { return Err("audit_hash does not reproduce from the claimed seed — the work was not done for this key and tick"); }
        Ok(())
    }

    fn replay_chain_from_raw(entries: &[TxDigest]) -> [u8; 32] {
        let mut subset_acc = [0u8; 32];
        for digest in entries {
            let payload = Self::digest_payload(digest);

            // Argon2id memory-hard work (same as accumulate/compute_subset_hash)
            let argon2_output = Self::argon2id_hash(&subset_acc, payload.as_bytes());

            // BLAKE3 chain — THE builder (KI#55 B2#2).
            subset_acc = audit_chain_step(&subset_acc, &argon2_output);
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

#[cfg(feature = "std")]
/// `AXIOM_AUDIT_SELECT` — the Fiat-Shamir seed of a Pulse audit sample (YPX-009
/// §4.2; YP Appendix): BLAKE3("AXIOM_AUDIT_SELECT" ‖ accumulator ‖ validator_pk).
/// ONE builder (Pattern 1, KI#55 B2#2, 2026-10-02) for the prover
/// (`AuditBuffer::generate_request`) and the issuer's verifier
/// (`verify_self_audit_sample`) — until this date each assembled it by hand.
fn audit_select_seed(accumulator: &[u8; 32], validator_pk: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_AUDIT_SELECT");
    h.update(accumulator);
    h.update(validator_pk);
    *h.finalize().as_bytes()
}

/// `AXIOM_AUDIT_VERIFY` — one step of the audit-subset chain (YPX-009 §4.3; YP
/// Appendix): BLAKE3("AXIOM_AUDIT_VERIFY" ‖ subset_acc ‖ argon2id_output).
/// ONE builder (KI#55 B2#2): `replay_chain_from_raw` is the only caller, and the
/// prover's `compute_subset_hash` goes through it.
#[cfg(feature = "std")]
fn audit_chain_step(subset_acc: &[u8; 32], argon2id_output: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"AXIOM_AUDIT_VERIFY");
    h.update(subset_acc);
    h.update(argon2id_output);
    *h.finalize().as_bytes()
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
            // Corrected 2026-09-26: this text said "demanded PEER audit … Core
            // self-terminating". `AuditTimeout` is returned ONLY for a SELF audit
            // (`enforce_audit_pre`; a peer timeout bans the target instead), and it
            // is a refusal of this and every later execution until restart, not a
            // process exit (YP §23.14 AS BUILT item 3).
            Self::AuditTimeout { challenge_nonce, .. } => write!(
                f, "AXIOM FATAL: §23.14 audit timeout — Lambda did not confirm this validator's \
                own SELF-audit demand (nonce: {}). Every execution is refused until restart \
                (VBC re-verification penalty).",
                hex::encode(&challenge_nonce[..8])
            ),
            Self::ValidatorBanned { validator_pk, reason } => write!(
                f, "AXIOM: §23.14.6 TX rejected — witness validator {} is banned ({:?}). \
                Ban expires after {} or AVM restart.",
                hex::encode(&validator_pk[..core::cmp::min(8, validator_pk.len())]),
                reason,
                peer_audit_ban_duration_text()
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

    // `ignition_t0` (a host `Instant`) DELETED 2026-10-03 (KI#125): the forbidden
    // host timer. The ignition is timed by two Nabla-signed readings judged by Core
    // mode `ZkpQualify` (YPX-007 §9, YPX-009 §6.1a).

    /// §23.14.6 tick discipline: highest validated TARDIS tick stamp observed
    /// across executions (from the transaction's `epoch` — a unix-second-valued
    /// stamp advanced by <=5s ticks, see TICK_INTERVAL_SECS). Ban imposition
    /// and expiry compare against THIS, never SystemTime::now() — wall clock
    /// is permitted only at the TARDIS root and the tardis.rs forward-drift
    /// check.
    last_validated_tick: AtomicU64,

    /// OPERATIONAL DISPLAY ONLY (dashboard audit-demand card) — never a consensus
    /// input. The AVM host is created fresh on every Lambda start
    /// (`CoreClient::new`), so these mark the LAST AVM RESTART: `restart_wall_clock`
    /// is the unix-second wall clock at creation, and `restart_tick` is the FIRST
    /// attested tick observed after restart (set-once). Wall clock is permitted
    /// here because it is pure operator display — §23.14 bans still judge only on
    /// `last_validated_tick`, never on this. Both reset on restart, which is the point.
    restart_wall_clock: u64,
    restart_tick: AtomicU64,

    /// §23.14.1 peer-audit TIME-BOND: the ATTESTED tick (oods) at which this
    /// host last fired a peer-audit demand — volume trigger OR time-bond. HOST
    /// MEMORY, exactly like `pending_audit` and the pulse buffer: it is NOT a
    /// consensus input, is never carried on the wire, is never written into a
    /// re-executed `PublicOutputs` field, and resets to 0 on AVM restart (which
    /// merely lets one early time-bond fire after a restart — harmless). It is
    /// consistent across every execution until the ELF restarts, which is the
    /// same model the peer audit is already built on (the owner, 2026-09-21). 0 =
    /// none fired yet. Advanced only under the `pending_audit` lock in
    /// `enforce_audit_post`.
    last_peer_audit_demand_tick: AtomicU64,

    /// §23.14 AS BUILT item 10 (2026-09-26): which trigger armed each PEER
    /// demand — the guest volume trigger vs the host time-bond — so a run can
    /// prove BOTH paths executed ("make sure time bonded audit is executed").
    peer_audits_armed_volume: AtomicU64,
    peer_audits_armed_time_bond: AtomicU64,
    /// Operator counters for the validator dashboard (2026-09-26, the owner: "how many
    /// time self/peer audit happend"): SELF demands armed / confirmed, and every
    /// ban this validator issued (cumulative — `peer_audit_bans` holds only the
    /// live ones, and a ban lifts). Host-side, CoreID-neutral; reset on restart.
    self_audits_armed: AtomicU64,
    self_audits_passed: AtomicU64,
    peer_audit_bans_issued: AtomicU64,

    /// Cranelift JIT engine — compiled ONCE at startup, reused for every TX.
    /// The JIT translates the entire RISC-V ELF to native code on first use.
    /// Compilation takes ~30-60s (intentional — restart penalty per YPX-009).
    /// After compilation, every TX executes at native speed (20-30x faster).
    /// Cranelift JIT — compiled once at startup, shared across all TXs.
    /// Not included in Debug output (contains native function pointers).
    #[cfg(feature = "cranelift-jit-backend")]
    #[allow(dead_code)]
    jit_engine: Option<std::sync::Arc<crate::riscv::jit::JitEngine>>,

    /// True when the JIT backend was compiled in but FAILED to build at startup
    /// (the host could not map executable memory) and execution fell back to the
    /// interpreter. Correctness is unaffected — the interpreter runs the SAME
    /// committed ELF and produces a valid DMAP attestation — but throughput drops
    /// ~20-30x. Surfaced via `jit_degraded()` so health/status can flag a validator
    /// whose host needs fixing and a restart. False in a clean JIT build, and in
    /// any build without `cranelift-jit-backend` (interpreter is the chosen runtime).
    jit_degraded: AtomicBool,
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
                                // ALERT-AND-CONTINUE (not silent, not fatal). The JIT is a pure
                                // PERFORMANCE backend (~20-30x over the interpreter, per Cargo.toml).
                                // It has NOTHING to do with DMAP correctness: the interpreter executes
                                // the SAME committed ELF (same CoreID) and produces a VALID DMAP
                                // attestation (Merkle-consistent, CoreID-bound) that verifies exactly
                                // like a JIT-produced one — the verifier never asks which backend ran.
                                // So a JIT build here ALSO ships the interpreter (default features), and
                                // a fallback is CORRECT, just ~20-30x slower. The only real defect is
                                // SILENCE: an operator can't tell a validator dropped to 1/20-1/30 speed.
                                // So warn LOUD + keep running on the interpreter, and set jit_degraded so
                                // health/status surfaces it until the host is fixed and the process
                                // restarts. We do NOT crash a correct-but-slow validator (a dead validator
                                // is worse than a slow one). See "AVM is production runtime".
                                Err(e) => {
                                    Self::jit_degraded_warn(&format!("JIT translation failed ({})", e));
                                    None
                                }
                            }
                        }
                        Err(e) => {
                            Self::jit_degraded_warn(&format!("ELF load into JIT memory failed ({:?})", e));
                            None
                        }
                    }
                }
                Err(e) => {
                    Self::jit_degraded_warn(&format!("JIT engine init failed ({})", e));
                    None
                }
            };
            engine.map(std::sync::Arc::new)
        };

        Self::assemble(
            bytecode, runtime_fingerprint, buffer, ready,
            #[cfg(feature = "cranelift-jit-backend")] jit_engine,
        )
    }

    /// THE ONE PLACE THE STRUCT IS ASSEMBLED. `new()` and the test-only
    /// constructor both come through here, so a field added to the struct is
    /// added once (RULE 1). Before 2026-09-10 the `mod pulse` tests carried
    /// two hand-written struct literals; when `jit_degraded` was added they
    /// silently stopped compiling in every non-riscv build (handoff §14.21).
    fn assemble(
        bytecode: Vec<u8>,
        runtime_fingerprint: [u8; 32],
        buffer: AuditBuffer,
        ready: bool,
        #[cfg(feature = "cranelift-jit-backend")] jit_engine: Option<std::sync::Arc<crate::riscv::jit::JitEngine>>,
    ) -> Self {
        Self {
            bytecode,
            runtime_fingerprint,
            pending_audit: Mutex::new(None),
            peer_audit_bans: Mutex::new(Vec::new()),
            audit_buffer: Mutex::new(buffer),
            wallet_cache: Mutex::new(WalletCache::new()),
            validator_pk: Mutex::new(None),
            pulse_ready: AtomicBool::new(ready),
            last_validated_tick: AtomicU64::new(0),
            restart_wall_clock: {
                #[cfg(feature = "std")]
                { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }
                #[cfg(not(feature = "std"))]
                { 0 }
            },
            restart_tick: AtomicU64::new(0),
            last_peer_audit_demand_tick: AtomicU64::new(0),
            peer_audits_armed_volume: AtomicU64::new(0),
            peer_audits_armed_time_bond: AtomicU64::new(0),
            self_audits_armed: AtomicU64::new(0),
            self_audits_passed: AtomicU64::new(0),
            peer_audit_bans_issued: AtomicU64::new(0),
            #[cfg(feature = "cranelift-jit-backend")]
            jit_degraded: AtomicBool::new(jit_engine.is_none()),
            #[cfg(not(feature = "cranelift-jit-backend"))]
            jit_degraded: AtomicBool::new(false),
            #[cfg(feature = "cranelift-jit-backend")]
            jit_engine,
        }
    }

    /// Tests only: no self-benchmark (~200 ms of Argon2id per construction),
    /// no JIT; `ready` sets the pulse gate directly. Same assembly as `new()`.
    #[cfg(test)]
    pub(crate) fn new_uncalibrated(bytecode: Vec<u8>, runtime_fingerprint: [u8; 32], ready: bool) -> Self {
        Self::assemble(
            bytecode, runtime_fingerprint, AuditBuffer::new(), ready,
            #[cfg(feature = "cranelift-jit-backend")] None,
        )
    }

    /// Whether the JIT backend failed to build and this instance is running on the
    /// interpreter (correct, valid DMAP, but ~20-30x slower). Health/status surfaces
    /// this so an operator knows the host needs fixing + a restart. See the
    /// alert-and-continue path in `new()`.
    pub fn jit_degraded(&self) -> bool {
        self.jit_degraded.load(Ordering::Acquire)
    }

    /// Emit the LOUD, greppable degraded-mode warning (used at each JIT-init failure
    /// point in `new()`). Not silent by design, and not fatal: the interpreter is a
    /// correct executor of the committed ELF — it just cannot keep up under load.
    #[cfg(feature = "cranelift-jit-backend")]
    fn jit_degraded_warn(reason: &str) {
        eprintln!(
            "[AVM-JIT] *** DEGRADED *** {reason}. The host could not map executable memory \
             (free memory, or relax W^X / allow executable mappings). Falling back to the \
             INTERPRETER: CORRECT — same committed ELF, valid DMAP attestation (CoreID-bound) — \
             but ~20-30x SLOWER, so this validator may not keep up under load. This is a pure \
             PERFORMANCE fallback (the JIT does nothing for DMAP correctness). Not silent and not \
             a crash by design; FIX THE HOST and RESTART to restore JIT speed. jit_degraded()=true \
             until then."
        );
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

    /// Process ignition TX (YPX-009 §6.1) — phase 1 of 2.
    ///
    /// Called when Lambda sends the ignition TX through Core. This method:
    /// 1. Bypasses the pulse gate (ignition TX is the ONLY exception)
    /// 2. Executes the TX through the normal AVM pipeline
    ///
    /// After this, Lambda proves the TX (when it has a prover) and calls
    /// `complete_ignition()`. Timing is NOT measured here: the ignition is also the
    /// ZKP qualification run, timed by two Nabla-signed readings and judged by Core
    /// mode `ZkpQualify` (YPX-007 §9, YPX-009 §6.1a).
    ///
    /// This is the restart penalty: when Lambda fails a pulse audit, Core
    /// self-terminates. Restart requires a new ignition TX — real operational
    /// downtime because ZKVM proving takes seconds to minutes.
    pub fn process_ignition(&self, inputs: PublicInputs) -> Result<PublicOutputs, AvmError> {
        eprintln!("[YPX-009] Ignition TX: processing");

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
        let _host = HostFunctions::new();
        let outputs = execute_core(inputs);
        Ok(outputs)
    }

    /// Complete ignition (YPX-009 §6.1) — phase 2 of 2.
    ///
    /// Called after Lambda proved the ignition TX (or, with no prover, with the
    /// DMAP marker). It checks ONLY that the proof bytes are non-empty and ≤ 10 MB —
    /// it never verified a STARK (YPX-009 §6.1a: STARK validity is Lambda's host
    /// `ZkvmVerifier::verify_checkpoint`; timing is the Nabla tick bracket judged by
    /// Core mode `ZkpQualify`, YPX-007 §9). Then it runs the Argon2id self-benchmark
    /// and sets `pulse_ready = true` — Core starts serving.
    pub fn complete_ignition(&self, proof_bytes: &[u8]) -> Result<(), AvmError> {
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

        eprintln!("[YPX-009] Ignition complete: proof={}KB", proof_bytes.len() / 1024);

        // Unblock Core — start serving transactions
        self.pulse_ready.store(true, Ordering::Release);
        Ok(())
    }

    /// §23.14: Check and enforce audit countdown before execution.
    /// Returns Err(AuditTimeout) if countdown expired without confirmation.
    /// Otherwise, processes any confirmation and decrements if pending.
    ///
    /// For peer-audits, also checks wall-clock timeout (10 minutes).
    /// On peer-audit timeout, bans the target for the ban window (`peer_audit_ban_duration_text`: 24 h real, 1 h dev) instead of self-terminating.
    fn enforce_audit_pre(&self, inputs: &PublicInputs) -> Result<(), AvmError> {
        // §23.14.6 tick discipline: advance the validated-tick watermark from
        // this TX's epoch (monotonic max — a replayed old epoch can't rewind it).
        // Use tx.epoch directly, NOT estimate_tick(): estimate_tick is
        // `#[cfg(not(disable-audit))]` while enforce_audit_pre is always
        // compiled, so a disable-audit build (lambda/antie) must not call it.
        // estimate_tick is literally `tx.epoch`, so this is identical.
        self.last_validated_tick
            .fetch_max(inputs.transaction.epoch, Ordering::AcqRel);

        // OPERATIONAL DISPLAY: record the FIRST attested tick observed after this
        // AVM host restarted (set-once; the CAS fails harmlessly on every later tx).
        let _ = self.restart_tick.compare_exchange(
            0, inputs.transaction.epoch, Ordering::AcqRel, Ordering::Relaxed);

        // §23.14.6: Check ban list — reject TX if any witness is banned
        self.check_witness_bans(inputs)?;

        let mut pending = self.pending_audit.lock().unwrap();

        if let Some(ref mut audit) = *pending {
            // Check for confirmation in inputs
            if let Some(ref confirmation) = inputs.audit_confirmation {
                if !audit.is_peer {
                    // Self-audit confirmation path (FIXED 2026-09-24, see
                    // `PendingAudit::self_expected_digest`)
                    // Step 1: Verify nonce + target match (binding)
                    if axiom_core_logic::audit::verify_audit_nonce(
                        &audit.demand, confirmation,
                    ) {
                        // Step 2: Verify content — hash the raw DB fields Lambda sent
                        // back against the digest of the triggering execution, fixed
                        // at arming. Lambda does zero crypto; Core hashes. No ring
                        // lookup: the pulse audit resets the ring after every accepted
                        // tx, which is why the old lookup failed after any reset.
                        let content_valid = audit.self_expected_digest.as_ref()
                            .map(|stored| axiom_core_logic::audit::verify_audit_content(
                                confirmation, stored,
                            ))
                            .unwrap_or(false); // no digest = not a self demand we armed = fail

                        if content_valid {
                            // Audit completed successfully — clear pending
                            *pending = None;
                            self.self_audits_passed.fetch_add(1, Ordering::Relaxed);
                            return Ok(());
                        }
                        // Content mismatch — Lambda tampered with DB. Countdown continues.
                        eprintln!("§23.14: Audit content mismatch for trigger_tx_number={}", audit.trigger_tx_number);
                    } else {
                        // Wrong nonce/target — ignore, countdown continues. NAMED (RULE 3
                        // shape 2, 2026-09-24): this was silent, and a self-audit that
                        // received two confirmations and still expired could not be
                        // told from one that received none.
                        eprintln!("§23.14: Audit confirmation ignored — nonce/target do not match the pending demand (demand nonce={} target={} / confirmation nonce={} target={}); remaining={}",
                                  hex::encode(&audit.demand.challenge_nonce[..8]),
                                  hex::encode(&audit.demand.target_validator_pk[..core::cmp::min(8, audit.demand.target_validator_pk.len())]),
                                  hex::encode(&confirmation.challenge_nonce[..8]),
                                  hex::encode(&confirmation.target_validator_pk[..core::cmp::min(8, confirmation.target_validator_pk.len())]),
                                  audit.remaining);
                    }
                }
                // Peer-audit confirmations are NOT handled here — they come via
                // handle_peer_audit_response() which calls clear_peer_audit() or ban_validator().
            }

            // NAMED (RULE 3 shape 2, 2026-09-24): a SELF demand ticking down with NO
            // confirmation in this execution's inputs. Bounded to the 10-TX self
            // countdown, and the one line that separates "Lambda never threaded a
            // confirmation into this execution kind" from "it did and it mismatched".
            if !audit.is_peer && inputs.audit_confirmation.is_none() {
                eprintln!("§23.14: self-audit pending (target={} remaining={}) but this {:?} execution carries NO audit_confirmation",
                          hex::encode(&audit.demand.target_validator_pk[..core::cmp::min(8, audit.demand.target_validator_pk.len())]),
                          audit.remaining, inputs.mode);
            }

            // Peer-audit response deadline: PEER_AUDIT_TIMEOUT_TICKS past the
            // watermark at dispatch (tick-disciplined, §23.14.1). `dispatched_at_tick`
            // is only ever set by `mark_peer_audit_dispatched`, so this arm cannot
            // fire for a request that never left this node (see `dispatched`).
            if audit.is_peer && audit.dispatched {
                if let Some(at) = audit.dispatched_at_tick {
                    let now_tick = self.last_validated_tick.load(Ordering::Acquire);
                    if now_tick.saturating_sub(at) >= axiom_core_logic::types::PEER_AUDIT_TIMEOUT_TICKS {
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

            // No valid confirmation — decrement countdown.
            // §23.14.1 silence-handling ruling (the owner 2026-09-21, VERIFIED matches
            // 2026-09-21): NEVER ban on a single silence. Silence is an
            // unattributable A↔B condition and an immediate strike is a griefing
            // vector (forge B's silence → B banned). A peer is banned ONLY on an
            // ATTRIBUTABLE failure: a wrong hash (HashMismatch, in Lambda's
            // handle_peer_audit_response) or non-response past the FULL countdown
            // below (NonResponds). The `remaining` budget IS the grace window — do
            // not shorten it to 0 or ban before it drains, or this becomes the
            // single-silence ban the ruling forbids.
            if audit.remaining == 0 {
                if audit.is_peer && audit.dispatched {
                    // Peer-audit TX countdown expired AFTER the request was sent —
                    // B's non-response is attributable: ban target, don't self-terminate
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
                // Peer-audit NEVER DISPATCHED: also Lambda failing to comply (it
                // did not initiate the audit Core demanded) — the same penalty,
                // and NOT a ban of the peer that was never asked (`dispatched`).
                if audit.is_peer {
                    eprintln!("§23.14: peer-audit demand expired UNDISPATCHED — Lambda never sent the request to target {}; this is our non-compliance, the target is NOT banned",
                              hex::encode(&audit.demand.target_validator_pk[..core::cmp::min(8, audit.demand.target_validator_pk.len())]));
                }
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
        peer_audit_ban_window_secs()
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
    /// Adds to ban list (survives across TXs, clears on restart or after the ban window — 24 h real, 1 h dev).
    pub fn ban_validator(
        &self,
        validator_pk: Vec<u8>,
        reason: axiom_core_logic::types::PeerAuditBanReason,
    ) {
        // Tick discipline: stamp the ban with the validated-tick watermark.
        // A ban can only arise from TX processing (the audit demand is
        // generated during execute), so the watermark holds a real tick here.
        let now_tick = self.last_validated_tick.load(Ordering::Acquire);
        self.peer_audit_bans_issued.fetch_add(1, Ordering::Relaxed);

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

    /// §23.14: Lambda has handed the pending peer-audit request to the carrier.
    /// Starts B's response deadline (`dispatched_at_tick` = the watermark now)
    /// and makes the eventual `NonResponds` ban attributable (see
    /// `PendingAudit::dispatched`). Returns whether a pending PEER audit was
    /// marked. Idempotent: a second call does not restart the deadline.
    pub fn mark_peer_audit_dispatched(&self) -> bool {
        let mut pending = self.pending_audit.lock().unwrap();
        match pending.as_mut() {
            Some(a) if a.is_peer => {
                if !a.dispatched {
                    a.dispatched = true;
                    a.dispatched_at_tick = Some(self.last_validated_tick.load(Ordering::Acquire));
                }
                true
            }
            _ => false,
        }
    }

    /// §23.14.3: the carrier FAILED to send the request after hand-off (ANTIE's
    /// SMTP error, relayed to Lambda). The request never left this node, so B's
    /// deadline must not run: back to undispatched — the countdown continues and
    /// the next witness build retries the send; an expiry is then OUR
    /// non-compliance, never B's silence. Returns whether a pending PEER audit
    /// was un-marked. Closes the KI#211 residual (2026-09-24).
    pub fn unmark_peer_audit_dispatched(&self) -> bool {
        let mut pending = self.pending_audit.lock().unwrap();
        match pending.as_mut() {
            Some(a) if a.is_peer && a.dispatched => {
                a.dispatched = false;
                a.dispatched_at_tick = None;
                true
            }
            _ => false,
        }
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

    /// §23.14.6: Get the pending peer-audit request data (for Lambda to sign +
    /// send via ANTIE). KI#207: the request carries NO expected hash — B is not
    /// handed the answer. We only emit a request once A has its OWN expected
    /// value (`peer_expected_hash`, kept locally to judge the reply). KI#175:
    /// `requester_sig` is left empty here; Lambda signs it with the operational
    /// wallet at send time (Core holds no keys).
    pub fn pending_peer_audit_request(&self) -> Option<axiom_core_logic::types::PeerAuditRequest> {
        let pending = self.pending_audit.lock().unwrap();
        if let Some(ref audit) = *pending {
            if audit.is_peer && audit.peer_expected_hash.is_some() {
                let our_pk = self.validator_pk.lock().unwrap();
                return Some(axiom_core_logic::audit::generate_peer_audit_request(
                    &audit.demand.trigger_txid,
                    &audit.demand.challenge_nonce,
                    &our_pk.as_ref().cloned().unwrap_or_default(),
                ));
            }
        }
        None
    }

    /// §23.14.6: Get the pending peer-audit DEMAND (carries `target_validator_pk`).
    /// Both the volume trigger AND the time-bond arm the AVM `pending_audit` via
    /// `enforce_audit_post`; only the volume trigger also writes
    /// `outputs.audit_demand` (the time-bond stays host-only for re-execution
    /// safety). So Lambda reads this to learn a TIME-BOND demand's target and
    /// mirror it into its own `pending_audit` — without which a time-bond audit
    /// never sends a request and falsely bans the target for NonResponds
    /// (surfaced live 2026-09-22). Same guard as `pending_peer_audit_request`.
    pub fn pending_peer_audit_demand(&self) -> Option<axiom_core_logic::types::AuditDemand> {
        let pending = self.pending_audit.lock().unwrap();
        pending.as_ref()
            .filter(|a| a.is_peer && a.peer_expected_hash.is_some())
            .map(|a| a.demand.clone())
    }

    /// §23.14.1: The pending TIME-BOND demand regardless of self/peer, so Lambda
    /// can mirror a SELF-audit time-bond into its own `pending_audit`.
    ///
    /// `pending_peer_audit_demand` (above) returns ONLY peer demands, and the
    /// guest VOLUME trigger (`outputs.audit_demand`, the other mirror source) is
    /// `#[cfg(not(dev-mode))]`-gated OUT of dev builds — so on the dev fleet EVERY
    /// demand is a host time-bond, and a self-target was mirrored to Lambda by
    /// neither path. Lambda's `resolve_audit_confirmation` then found nothing to
    /// confirm and the AVM countdown SELF-TERMINATED the validator (KI#210/#207,
    /// live 2026-09-23: `AXIOM FATAL: §23.14 audit timeout` — the message text
    /// then said "peer audit" (corrected 2026-09-26), but `AuditTimeout` is only
    /// ever returned for a self-audit at `enforce_audit_pre`). ⚠ Since 537ca629
    /// (2026-09-26) the volume trigger is compiled into dev Cores too, so "EVERY
    /// dev demand is a time-bond" above is history. A corrupt DB still self-terminates
    /// (the confirmation Lambda builds is content-verified against the audit
    /// buffer), so this only unblocks the honest path. Returns the demand
    /// whenever the AVM holds a pending audit; the `!lambda_has_pending` guard at
    /// the call site keeps the mirror idempotent.
    pub fn pending_time_bond_demand(&self) -> Option<axiom_core_logic::types::AuditDemand> {
        let pending = self.pending_audit.lock().unwrap();
        pending.as_ref().map(|a| a.demand.clone())
    }

    /// §23.14 AS BUILT item 10: peer demands armed by (volume, time-bond).
    pub fn peer_audit_trigger_counts(&self) -> (u64, u64) {
        (self.peer_audits_armed_volume.load(Ordering::Relaxed),
         self.peer_audits_armed_time_bond.load(Ordering::Relaxed))
    }

    /// Dashboard counters: (self armed, self passed, bans issued — cumulative).
    pub fn audit_operator_counts(&self) -> (u64, u64, u64) {
        (self.self_audits_armed.load(Ordering::Relaxed),
         self.self_audits_passed.load(Ordering::Relaxed),
         self.peer_audit_bans_issued.load(Ordering::Relaxed))
    }

    /// OPERATIONAL DISPLAY: the unix-second wall clock when this AVM host was last
    /// (re)started, and the first attested tick observed after that restart (0
    /// until the first tx arrives). Surfaced on the dashboard audit-demand card.
    pub fn avm_restart_info(&self) -> (u64, u64) {
        (self.restart_wall_clock, self.restart_tick.load(Ordering::Acquire))
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

    /// §23.14.1 peer-audit TIME-BOND (host side). The guest volume trigger
    /// (`outputs.audit_demand`, `should_trigger_audit`, 1-in-`AUDIT_TRIGGER_RATE`)
    /// never fires for a low-traffic validator. This bonds a peer audit to the
    /// ATTESTED tick instead: on the first eligible witnessed Accept once the
    /// oods tick has advanced more than `AUDIT_MAX_TICK_GAP` past the last
    /// peer-audit demand, generate one host-side.
    ///
    /// # Re-execution safety (why this is host-side, not in the guest)
    /// The demand it returns is NEVER written back into `outputs.audit_demand`
    /// (that field is guest-produced, deterministic from txid, and rides the
    /// ELF/CoreID). It is consumed only to arm the host-local `pending_audit`
    /// countdown — exactly like the existing peer countdown and the pulse
    /// self-audit trigger, both of which already live in host memory and are
    /// NOT re-executed. Because it depends on `last_peer_audit_demand_tick`
    /// (per-executor host state), putting it into a re-executed output would
    /// make a fresh validator and a long-running one diverge on the same tx;
    /// keeping it host-side produces no re-executed output, so there is no
    /// divergence. The cost is that the time-bond carries only the host tamper
    /// model (patch the AVM → your DMAP trace / behaviour diverges from honest
    /// peers), NOT the ELF tamper-evidence the volume trigger has — the same
    /// trade the countdown, the ban list and the pulse trigger already make.
    ///
    /// Judged against `oods_attestation.tick` (Nabla-signed, KI#130 "now",
    /// verified in-place during the CL2/CL3 that just Accepted), NEVER tx.epoch
    /// (client-forgeable) or wall clock. Returns None when the subsystem cannot
    /// act: not a witnessed CL2/CL3 Accept, no attested tick, no peer to target,
    /// or the gap has not been crossed.
    #[cfg(not(feature = "disable-audit"))]
    fn time_bond_demand(
        &self,
        inputs: &PublicInputs,
        outputs: &PublicOutputs,
        attested_tick: Option<u64>,
    ) -> Option<axiom_core_logic::types::AuditDemand> {
        // Only a witnessed round that Accepted, with a verified attested tick.
        if outputs.result != ValidationResult::Accept {
            return None;
        }
        if !matches!(inputs.mode, axiom_core_logic::CoreLogicMode::CL2 | axiom_core_logic::CoreLogicMode::CL3) {
            return None;
        }
        // No attested tick ⇒ no tick to judge ⇒ silent (same rule as no-tx).
        let now = attested_tick?;
        let last = self.last_peer_audit_demand_tick.load(Ordering::Acquire);
        if now.saturating_sub(last) <= axiom_core_logic::types::AUDIT_MAX_TICK_GAP {
            return None;
        }
        // A txid to seed the demand, and the CURRENT tx's co-witnesses to target
        // (§23.14.2, KI#213 — the ONE selector shared with the guest volume
        // trigger, RULE 1). Was `prev_receipts[].witness_sigs`: the PREVIOUS tx's
        // witnesses, who never executed this tx and could only answer "unknown
        // txid" → banned NonResponds on the first delivered request (2026-09-24).
        let txid = outputs.txid.as_ref()?;
        let witness_pks: Vec<Vec<u8>> = axiom_core_logic::audit::audit_target_candidates(inputs);
        // generate_audit_demand is the SAME builder the guest volume trigger
        // uses (RULE 1) — deterministic target selection from the witness set;
        // None when there is no peer to audit.
        axiom_core_logic::audit::generate_audit_demand(txid, &witness_pks)
    }

    /// disable-audit builds (dev fleet lambda/antie) run no pulse subsystem, so
    /// the time-bond must not arm a peer audit whose expected hash can never be
    /// computed — it would count down to a spurious ban. Matches the gate on
    /// `pulse_post_execute`.
    #[cfg(feature = "disable-audit")]
    fn time_bond_demand(
        &self,
        _inputs: &PublicInputs,
        _outputs: &PublicOutputs,
        _attested_tick: Option<u64>,
    ) -> Option<axiom_core_logic::types::AuditDemand> {
        None
    }

    /// §23.14: After execution, arm the audit countdown if Core (volume trigger,
    /// guest) OR the host time-bond (§23.14.1) produced a demand.
    /// Self-audit: `AUDIT_COUNTDOWN_TXS`. Peer-audit: `PEER_AUDIT_COUNTDOWN_TXS`
    /// / `PEER_AUDIT_TIMEOUT_SECS`.
    fn enforce_audit_post(&self, inputs: &PublicInputs, outputs: &PublicOutputs, accumulate: bool) {
        // §23.14 (KI#210): a demand may arm ONLY on an AUDITED execution. The
        // trigger tx is accumulated into the audit buffer only when `accumulate`
        // (pulse_post_execute returns early otherwise), and a self-audit can be
        // confirmed ONLY against a buffer entry (enforce_audit_pre looks up
        // `trigger_tx_number`). Arming on a non-audited CL2 witness produced a
        // demand whose trigger tx was NEVER in this validator's buffer, so it could
        // never be confirmed and the countdown self-terminated the validator (tier
        // C residual: 10 of 15 self-terminates were demands armed on unaudited
        // witnesses). The volume trigger (`outputs.audit_demand`) obeys the same
        // rule — a demand about a tx that was not recorded is unanswerable.
        if !accumulate {
            return;
        }
        let mut pending = self.pending_audit.lock().unwrap();
        // Only arm if no pending audit (don't override an active countdown).
        // This also means the time-bond never fires while an audit is in flight.
        if pending.is_some() {
            return;
        }

        // The attested tick — the KI#130 "now": the Nabla-signed oods tick,
        // verified in-place during CL2/CL3 (this runs only when the tx Accepted,
        // so the attestation was already verified). NEVER tx.epoch or wall clock.
        let attested_tick: Option<u64> =
            inputs.oods_attestation.as_ref().map(|a| a.tick);

        // Volume trigger (guest, ELF/CoreID) first; else the host time-bond.
        let (demand, from_volume) = match outputs.audit_demand.clone() {
            Some(d) => (d, true),
            None => match self.time_bond_demand(inputs, outputs, attested_tick) {
                Some(d) => (d, false),
                None => return,
            },
        };

        // Get current tx_number from audit buffer
        let current_tx_number = {
            let buffer = self.audit_buffer.lock().unwrap();
            buffer.tx_counter
        };

        // Check if this is a peer-audit (target != our PK)
        let is_peer = {
            let our_pk = self.validator_pk.lock().unwrap();
            our_pk.as_ref()
                .map(|pk| pk.as_slice() != demand.target_validator_pk.as_slice())
                .unwrap_or(true) // if PK not set, treat as peer (conservative)
        };

        let countdown = if is_peer {
            axiom_core_logic::types::PEER_AUDIT_COUNTDOWN_TXS
        } else {
            axiom_core_logic::types::AUDIT_COUNTDOWN_TXS
        };

        // For peer-audit, A's expected hash = the digest of THIS execution — the
        // exact fields `pulse_post_execute` accumulates (sender_balance = the
        // consumed state's balance or 0, receiver_balance 0, produced state_id,
        // amount), computed HERE from inputs/outputs.
        //
        // ⚠ WRONG READING, live until 2026-09-24 (KI#214): this looked the
        // current tx up in the audit buffer by `tx_counter` — but this runs
        // BEFORE `pulse_post_execute` accumulates it, so it found the PREVIOUS
        // audited execution's digest (A then judged B's honest reply about the
        // current txid as HashMismatch), or nothing at all right after a buffer
        // reset (the pulse audit resets the ring after every accepted tx on the
        // dev fleet: "audit chain started" precedes nearly every execution) —
        // then `pending_peer_audit_request()` had no hash and the request was
        // never built. Measured: demands on delta/eta 04:03/04:10Z with 6 and 1
        // executions after them, 0 handed to ANTIE, `peer_audit_target_unresolved`
        // 0. Every §23.14 peer audit needs this hash; it cannot depend on a ring
        // that another subsystem resets.
        let peer_expected_hash = if is_peer {
            let sender_balance = inputs.current_state.as_ref().map(|s| s.balance).unwrap_or(0);
            let state_id = outputs.produced_state_id.unwrap_or([0u8; 32]);
            Some(axiom_core_logic::audit::compute_peer_audit_hash(
                &demand.trigger_txid,
                sender_balance,
                0,
                &state_id,
                inputs.transaction.amount,
            ))
        } else {
            None
        };

        // Reset the time-bond clock on ANY armed peer audit — volume OR
        // time-bond — so a busy validator's frequent volume audits also satisfy
        // the low-volume bond. Record the attested tick that judged this round;
        // if none was present, leave the clock (the time-bond simply gains no
        // anchor from this tx and may fire a touch sooner later — safe).
        if is_peer {
            if let Some(t) = attested_tick {
                self.last_peer_audit_demand_tick.store(t, Ordering::Release);
            }
            let counter = if from_volume { &self.peer_audits_armed_volume } else { &self.peer_audits_armed_time_bond };
            counter.fetch_add(1, Ordering::Relaxed);
        } else {
            self.self_audits_armed.fetch_add(1, Ordering::Relaxed);
        }

        *pending = Some(PendingAudit {
            demand,
            remaining: countdown,
            trigger_tx_number: current_tx_number,
            is_peer,
            // The response deadline starts at DISPATCH (mark_peer_audit_dispatched),
            // not here — B cannot be late answering a request A has not sent.
            dispatched_at_tick: None,
            peer_expected_hash,
            dispatched: false,
            self_expected_digest: if is_peer { None } else {
                Some(axiom_core_logic::types::TxDigest {
                    tx_number: current_tx_number,
                    sender_balance: inputs.current_state.as_ref().map(|s| s.balance).unwrap_or(0),
                    receiver_balance: 0,
                    state_id: outputs.produced_state_id.unwrap_or([0u8; 32]),
                    amount: inputs.transaction.amount,
                })
            },
        });
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
        accumulate: bool,
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

        // ⚠ ACCUMULATE ONLY WHAT LAMBDA RECORDS (2026-09-08, the day the audit
        // was switched on). The audit replays Lambda's TRANSACTION DB against
        // this chain (§4.4: Lambda answers from `get_transaction_record`). Only
        // two executions ever write that record — the FINALIZING CL3 (last hop)
        // and the CL5 redeem. Every other Accept that reaches this AVM —
        // non-final witness hops, CL2 pre-checks, CL8 issuance, console — has
        // no record, so one of them in the chain makes every audit fail
        // forever (Core answers a mismatch, keeps the entries, re-requests).
        // The caller says which it is via `execute_audited` /
        // `execute_with_dmap_audited`; the plain entry points still VERIFY
        // responses (steps 1–2 above) but add nothing to the chain.
        if !accumulate {
            return;
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
        // Observability (2026-09-08, the day the audit was switched on for the
        // dev fleet): the chain's first link and every emitted request print
        // ONE line each. Without these the only trace of a live audit was a
        // Lambda `info!` that never appeared, and nothing said whether the
        // buffer was even filling. eprintln — the AVM has no logger.
        if buffer.entries.len() == 1 {
            eprintln!("[YPX-009] audit chain started (first accepted TX since reset; argon2id/s={})",
                buffer.argon2id_per_sec);
        }

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
            eprintln!("[YPX-009] audit request emitted: {} of {} entries, epoch={}, tick={}",
                request.selected_indices.len(), buffer.entries.len(), epoch, current_tick);
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
        _accumulate: bool,
    ) {
        // Audit chain disabled — no Argon2id, no nonce challenges, no pulse proofs.
    }

    /// Execute core validation with given inputs (default mode)
    ///
    /// This is the main entry point for transaction validation.
    /// In default mode, calls core-logic's execute_core directly.
    pub fn execute(&self, inputs: PublicInputs) -> Result<PublicOutputs, AvmError> {
        self.execute_impl(inputs, false)
    }

    /// `execute` for an execution whose result the caller RECORDS in its
    /// transaction DB (Lambda: the CL5 redeem). Only these join the YPX-009
    /// audit chain — see `pulse_post_execute`.
    pub fn execute_audited(&self, inputs: PublicInputs) -> Result<PublicOutputs, AvmError> {
        self.execute_impl(inputs, true)
    }

    fn execute_impl(&self, inputs: PublicInputs, accumulate: bool) -> Result<PublicOutputs, AvmError> {
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
                self.enforce_audit_post(&inputs_ref, &result.outputs, accumulate);
                // YPX-009: Silicon Pulse post-execution (no DMAP trace in execute())
                let mut outputs = result.outputs;
                self.pulse_post_execute(&inputs_ref, &mut outputs, None, accumulate);
                return Ok(outputs);
            }
            // Fall through to native execution (Cargo feature unification case:
            // riscv-interpreter enabled but no real ELF loaded, e.g. axiom-core-bin)
        }

        // Direct native execution
        let _host = HostFunctions::new();
        let inputs_ref = inputs.clone(); // keep a copy for pulse processing
        let mut outputs = execute_core(inputs);
        // §23.14: Track new audit demands (post-execution)
        self.enforce_audit_post(&inputs_ref, &outputs, accumulate);
        // YPX-009: Silicon Pulse post-execution (no DMAP trace in native mode)
        self.pulse_post_execute(&inputs_ref, &mut outputs, None, accumulate);
        Ok(outputs)
    }

    /// Execute with DMAP trace collection
    ///
    /// Only available with `riscv-interpreter` feature. In default mode,
    /// returns outputs with no DMAP trace (native execution cannot produce
    /// memory checkpoints).
    pub fn execute_with_dmap(&self, inputs: PublicInputs) -> Result<AvmExecutionResult, AvmError> {
        self.execute_with_dmap_impl(inputs, false)
    }

    /// `execute_with_dmap` for the execution Lambda RECORDS — the FINALIZING
    /// CL3 (last hop). Non-final hops use the plain entry point.
    pub fn execute_with_dmap_audited(&self, inputs: PublicInputs) -> Result<AvmExecutionResult, AvmError> {
        self.execute_with_dmap_impl(inputs, true)
    }

    fn execute_with_dmap_impl(&self, inputs: PublicInputs, accumulate: bool) -> Result<AvmExecutionResult, AvmError> {
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
                self.enforce_audit_post(&inputs_ref, &result.outputs, accumulate);
                // YPX-009: Silicon Pulse with DMAP trace
                self.pulse_post_execute(&inputs_ref, &mut result.outputs, result.dmap_trace.as_ref(), accumulate);
                return Ok(result);
            }
            // Fall through to native (no DMAP trace without real ELF)
        }

        // Native execution — no DMAP trace available
        let _host = HostFunctions::new();
        let inputs_ref = inputs.clone();
        let mut outputs = execute_core(inputs);
        // §23.14: Track new audit demands (post-execution)
        self.enforce_audit_post(&inputs_ref, &outputs, accumulate);
        // YPX-009: Silicon Pulse post-execution (no DMAP trace in native mode)
        self.pulse_post_execute(&inputs_ref, &mut outputs, None, accumulate);
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
        let host = HostFunctions::new();
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
            zkq_request: None,
            fact_certificates: Vec::new(),
            fob_claim_attestation: None,
            receiver_witness: None,
            receiver_signing_key: None,
            oods_attestation: None,
            recall_attestation: None,
            // §5.2.2b/c — a plain CL1 fixture is not a subsidy claim: no
            // claimant certificate to present, and no stake lock held.
            claimant_vbc: None,
            receiver_current_wall_clock_lock: None,
            receiver_current_emission_claimed_epoch: None,
            receiver_current_stake_floor_until: None,
            receiver_current_wallet_format: None,
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
                wall_clock_lock: 0,
                emission_claimed_epoch: 0,
                stake_floor_until: 0, wallet_format: axiom_core_logic::types::WalletFormat::CURRENT,
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
            wallet_secret: None,
            fanout_message: None,
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
        /// Tries, in order:
        ///   1. Monorepo layout, relative to workspace root:
        ///      core/avm-guest/target/riscv32im-unknown-none-elf/release/axiom-avm-guest
        ///   2. Public-repo layout (core/* flattened to the repo root):
        ///      avm-guest/target/riscv32im-unknown-none-elf/release/axiom-avm-guest
        ///   3. `AXIOM_GUEST_ELF` env var — explicit override, full path to the
        ///      guest ELF (consulted only when neither layout has one, so a
        ///      committed checkout's own artifact stays authoritative).
        pub fn find_elf() -> Option<Vec<u8>> {
            // Walk up from CARGO_MANIFEST_DIR to find workspace root
            let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            // 1. Monorepo: core/avm/.. = core/, core/.. = src/ (workspace root)
            if let Some(workspace) = manifest_dir.parent().and_then(|p| p.parent()) {
                let elf_path = workspace
                    .join("core/avm-guest/target/riscv32im-unknown-none-elf/release/axiom-avm-guest");
                if elf_path.exists() {
                    return Some(std::fs::read(&elf_path).expect("Failed to read ELF"));
                }
            }
            // 2. Public repo: core/* is flattened, so avm/.. = repo root
            if let Some(repo_root) = manifest_dir.parent() {
                let elf_path = repo_root
                    .join("avm-guest/target/riscv32im-unknown-none-elf/release/axiom-avm-guest");
                if elf_path.exists() {
                    return Some(std::fs::read(&elf_path).expect("Failed to read ELF"));
                }
            }
            // 3. Explicit override for any other layout
            if let Ok(p) = std::env::var("AXIOM_GUEST_ELF") {
                let elf_path = std::path::PathBuf::from(p);
                if elf_path.exists() {
                    return Some(std::fs::read(&elf_path).expect("Failed to read ELF"));
                }
            }
            None
        }

        /// Skip-as-green canary. Every differential test in this file returns
        /// early (green) when the guest ELF is absent, so a checkout that never
        /// built the guest reports a passing suite while 16 differential tests
        /// silently do nothing. This test makes that skip a VISIBLE CHOICE:
        /// it passes when the ELF is found, or when the operator explicitly
        /// opts in with AXIOM_ALLOW_GUEST_SKIP=1 — and FAILS otherwise.
        #[test]
        fn differential_guest_elf_presence_canary() {
            if find_elf().is_some() {
                return; // guest ELF present — the differential tests really run
            }
            eprintln!("SKIP: axiom-core.elf not found — 16 differential tests in this file are skipping");
            if std::env::var("AXIOM_ALLOW_GUEST_SKIP").as_deref() == Ok("1") {
                eprintln!("AXIOM_ALLOW_GUEST_SKIP=1 — skip acknowledged, canary passes");
                return;
            }
            panic!(
                "16 differential tests are silently skipping — build the guest ELF \
                 (cd core/avm-guest && cargo build --release --target riscv32im-unknown-none-elf, \
                 or avm-guest/ on the public layout, or point AXIOM_GUEST_ELF at one) \
                 or set AXIOM_ALLOW_GUEST_SKIP=1"
            );
        }

        /// P3.7 guest/host discriminator — a CHARGE-shaped CL5 (k≥3 sender →
        /// k=0 receiver, no Nabla artifacts) must reject IDENTICALLY in the
        /// guest and natively. Built while chasing the live 938ae779 charge
        /// redeem rejecting `InvalidWalletId` in the SDK's guest CL5 run: if
        /// guest and native diverge here, the wallet_id checks behave
        /// differently in-guest.
        #[test]
        fn test_real_elf_cl5_charge_shape_guest_matches_native() {
            use axiom_core_logic::wallet_id::{
                generate_wallet_id_full, generate_all_wallet_ids, K_ARK, WALLET_IDENTITY_KEY,
            };
            let elf = match find_elf() {
                Some(e) => e,
                None => {
                    eprintln!("SKIP: axiom-core.elf not found");
                    eprintln!("      (this silent skip is policed by differential_guest_elf_presence_canary)");
                    return;
                }
            };
            use ed25519_dalek::{Signer, SigningKey};
            let sender_sk = SigningKey::from_bytes(&[0x61u8; 32]);
            let receiver_sk = SigningKey::from_bytes(&[0x62u8; 32]);
            let spk = sender_sk.verifying_key().to_bytes();
            let rpk = receiver_sk.verifying_key().to_bytes();
            let salt_r = hex::encode(blake3::hash(&rpk).as_bytes())[..2].to_string();
            let r_addr = generate_wallet_id_full(
                "chargepair@axiom", &salt_r, &WALLET_IDENTITY_KEY, &rpk, K_ARK,
                axiom_core_logic::wallet_id::PROOF_TYPE_ARK,
            ).unwrap();
            let s_addr = generate_all_wallet_ids("chargesender@axiom", "42", &spk).unwrap()
                .into_iter().find(|(_, k, _, _)| *k == 3).map(|(a, _, _, _)| a).unwrap();

            let mut tx = create_test_inputs().transaction;
            tx.sender_wallet_id = s_addr.clone();
            tx.receiver_wallet_id = r_addr.clone();
            tx.client_pk = spk.to_vec();
            tx.amount = 3_000_000_000;
            let mut cheque_tx = tx.clone();
            cheque_tx.receiver_wallet_id = r_addr.clone();
            let txid = axiom_core_logic::compute::compute_txid(&cheque_tx);
            let issuer = axiom_core_logic::cheque_build::ChequeIssuerContext {
                issuer_id: *blake3::hash(&spk).as_bytes(),
                issuer_pk: spk.to_vec(),
                vbc_bundle: None,
                carrier_type: "email".to_string(),
                carrier_address: String::new(),
                rate_bps: 0,
                created_at: 1000,
            };
            let mut cheque = axiom_core_logic::cheque_build::build_cheque_unsigned(
                &cheque_tx, txid, [0u8; 32], [1u8; 32], None,
                b"", None, 1, [0u8; 32], [0u8; 32], None, None, Vec::new(), &issuer,
            );
            let commitment = axiom_core_logic::compute::compute_cheque_commitment(
                &cheque.txid, &cheque.state_hash, &cheque.produced_state_id,
                // §5.2.2c — `sender_wallet_id` became SIGNED on 2026-09-05 and
                // sits BEFORE the receiver in the pre-image. Read both off the
                // cheque so this fixture cannot drift from the builder.
                &cheque.sender_wallet_id, &cheque.receiver_wallet_id,
                cheque.amount, cheque.epoch, cheque.created_at, cheque.rate_bps,
                &cheque.dmap_input_hash, &cheque.dmap_output_hash,
                cheque.oracle_claim.as_ref(), cheque.recall_target_tx_id.as_ref(),
            );
            cheque.signature = sender_sk.sign(&commitment).to_bytes().to_vec();
            // 3 cheques from "distinct validators" (charge required_k = 3).
            let mut cheques = Vec::new();
            for i in 0..3u8 {
                let mut c = cheque.clone();
                c.validator_id = [i + 1; 32];
                cheques.push(c);
            }
            let bundle = axiom_core_logic::types::ChequeBundle { cheques, fact_chain: None };
            let state_id = axiom_core_logic::genesis::compute_genesis_state_id(
                &rpk, 0, K_ARK, axiom_core_logic::wallet_id::PROOF_TYPE_ARK,
            );
            let inputs = axiom_core_logic::cl5_inputs::build_cl5_attestation_inputs(
                // (balance, seq, hibernation, wall_clock_lock, emission_claimed_epoch,
                // stake_floor_until) all 0, current format block — this fixture
                // exercises the interpreter, not the §5.2.2c / §6b.13 gates.
                &rpk, &bundle, 0, 0, 0, 0, 0, 0, axiom_core_logic::types::WalletFormat::CURRENT,
                state_id, Vec::new(), None, None, None, [0u8; 32],
            );

            let native = axiom_core_logic::execute_core(inputs.clone());
            let avm = AvmInterpreter::new(elf, [0u8; 32]);
            let guest = avm.execute(inputs).expect("guest execution failed");
            eprintln!("charge-shape CL5: native={:?} guest={:?}",
                native.rejection_reason, guest.rejection_reason);
            assert_eq!(guest.result, native.result);
            assert_eq!(guest.rejection_reason, native.rejection_reason,
                "guest and native CL5 must reject a charge-shaped bundle identically");
        }

        #[test]
        fn test_real_elf_cl1_execution() {
            let elf = match find_elf() {
                Some(e) => e,
                None => {
                    eprintln!("SKIP: axiom-core.elf not found — build with: cd core/avm-guest && cargo build --release");
                    eprintln!("      (this silent skip is policed by differential_guest_elf_presence_canary)");
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
                    eprintln!("      (this silent skip is policed by differential_guest_elf_presence_canary)");
                    return;
                }
            };

            let avm = AvmInterpreter::new(elf, [0u8; 32]);
            let mut inputs = create_test_inputs();
            inputs.mode = CoreLogicMode::CL2;

            // Add receipt with VBC bundle
            let receipt = Receipt {
                oods_flag: None,
                confidence_index: None,
                // §32.3 received-from lineage (38a8cdd6, 2026-08-11) — third
                // fixture that commit left behind, alongside the two in
                // core/ipc/src/codec.rs. Not a recall/redeem receipt here.
                sender_state: None,
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
                            // §5.3 — depth-0 fixtures: zero is the genesis /
                            // no-lineage sentinel, which is what a chain_depth 0
                            // certificate legitimately carries.
                            genesis_lineage: [0u8; 32],
                            nabla_registration: None,
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
                        candidacy_pulse: None,
                        renewal_work_receipt: None,
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
                    eprintln!("      (this silent skip is policed by differential_guest_elf_presence_canary)");
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
                None => {
                    eprintln!("SKIP: axiom-core.elf not found");
                    eprintln!("      (this silent skip is policed by differential_guest_elf_presence_canary)");
                    return;
                }
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
                    eprintln!("      (this silent skip is policed by differential_guest_elf_presence_canary)");
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
            // No calibration (test speed); the gate is bypassed. One assembly
            // path with `new()` — never a struct literal here (RULE 1).
            let avm = AvmInterpreter::new_uncalibrated(vec![0x00], [0u8; 32], true);
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
            assert_eq!(avm.audit_operator_counts().2, 1, "dashboard: bans issued is counted");
            avm.ban_validator(banned_pk.clone(), axiom_core_logic::types::PeerAuditBanReason::NonResponds);
            assert_eq!(avm.peer_audit_bans().len(), 1, "a re-ban updates the live entry");
            assert_eq!(avm.audit_operator_counts().2, 2, "…but bans ISSUED is cumulative (a ban lifts; the count stays)");

            // PEER_AUDIT_BAN_TICKS is a tick COUNT; the stamp window is the
            // count projected onto unix-second tick stamps: 24 h = 86 400 on a
            // real build, 1 h = 3 600 on a dev-mode build (peer_audit_ban_ticks_dev
            // = 720, YP §23.14 item 7, 2026-09-26).
            let window_stamp = axiom_core_logic::types::PEER_AUDIT_BAN_TICKS
                * axiom_core_logic::types::TICK_INTERVAL_SECS;
            // Which one applies is core-logic's `dev-mode`, pinned per build by
            // core/logic/tests/peer_audit_ban_dev_twin.rs; this crate's own
            // `dev-mode` need not match it, so accept exactly the two values.
            assert!(matches!(window_stamp, 3_600 | 86_400),
                    "ban window on the stamp scale must be 1 h (dev) or 24 h (real), got {window_stamp}");
            // The wording every ban message uses comes from the SAME window —
            // it said a hardcoded "24 hours" on dev builds (1 h) until 2026-09-26.
            assert_eq!(super::super::peer_audit_ban_window_secs(), window_stamp);
            let text = super::super::peer_audit_ban_duration_text();
            assert_eq!(text, if window_stamp == 3_600 { "1 h" } else { "24 h" });
            let msg = AvmError::ValidatorBanned {
                validator_pk: banned_pk.clone(),
                reason: axiom_core_logic::types::PeerAuditBanReason::HashMismatch,
            }.to_string();
            assert!(msg.contains(&format!("expires after {text}")), "rejection text states the real window: {msg}");

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

        // ── §23.14.1 peer-audit TIME-BOND ─────────────────────────────────

        use axiom_core_logic::types::{
            AuditDemand, NablaOodsAttestation, Receipt, WitnessSig, AUDIT_MAX_TICK_GAP,
        };

        /// A prev-receipt witnessed by `peer_pk` — the guest/host read only
        /// `witness_sigs[].validator_pk` for audit target selection.
        fn peer_receipt(peer_pk: Vec<u8>) -> Receipt {
            Receipt {
                oods_flag: None,
                confidence_index: None,
                sender_state: None,
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
                    validator_pk: peer_pk,
                    vbc_bundle: None,
                    carrier_type: "email".into(),
                    carrier_address: "test@axiom.local".into(),
                    signature: vec![6u8; 64],
                    execution_proof: vec![],
                    proof_type: 1,
                    availability_attestation: None,
                    validator_hints: vec![],
                    fact_signature: None,
                    checkpoint_sig: None,
                    receipt_signature: None,
                    receipt_commitment_sig: None,
                    rate_bps: 0,
                    slot_amount: 0,
                }],
            }
        }

        /// A minimal-but-real oods attestation carrying `tick` (only the tick is
        /// read by the time-bond; enforce_audit_post runs post-Accept so the
        /// signature was already verified upstream — the fixture is not re-verified).
        fn oods_at(tick: u64) -> NablaOodsAttestation {
            NablaOodsAttestation {
                oods_size: 1,
                tick,
                baseline_size: 0,
                baseline_tick: 0,
                nabla_node_pk: [0u8; 32],
                nabla_signature: vec![],
                nbc_issuer_pk: vec![],
                nbc_signature: vec![],
                nbc_commitment: vec![],
            }
        }

        /// A finalizing CL3 input at `attested_tick`, CO-witnessed by `peer_pk`
        /// (its signature in `overlapped_signatures` — the §23.14.2 target set since
        /// KI#213; it is also left in `prev_receipts` so a regression to the old
        /// previous-witness selection would still find a pk and the tests below
        /// judge WHICH set was read). `attested_tick = None` ⇒ no attestation.
        fn witnessed_inputs(attested_tick: Option<u64>, peer_pk: Vec<u8>) -> PublicInputs {
            let mut inputs = create_test_inputs();
            inputs.mode = CoreLogicMode::CL3;
            inputs.prev_receipts = vec![peer_receipt(vec![0xEEu8; 32])];
            inputs.overlapped_signatures = peer_receipt(peer_pk).witness_sigs;
            inputs.oods_attestation = attested_tick.map(oods_at);
            inputs
        }

        /// An Accept CL3 output carrying `txid`, with `audit_demand` (the guest
        /// volume trigger) set or not. Everything else empty.
        fn accept_outputs(txid: Option<[u8; 32]>, audit_demand: Option<AuditDemand>) -> PublicOutputs {
            PublicOutputs {
                zkp_qualification: None,
                result: ValidationResult::Accept,
                new_state_hash: None,
                produced_state_id: None,
                new_wallet_seq: None,
                rejection_reason: None,
                is_overlapped: None,
                commitment_hash: None,
                txid,
                fact_signature: None,
                new_balance: None,
                nbc_signature: None,
                zkp_nonce_hash: None,
                compressed_fact_chain: None,
                ark_send_fact_chain: None,
                receiver_fact_chain: None,
                required_k: 3,
                extracted_proof_type: 0,
                audit_demand,
                audit_request: None,
                nonce_challenge: None,
                pulse_proof: None,
                audit_failed: false,
                fanout_new_ttl: None,
                console_chain_hash: None,
                receipt_commitment: None,
                is_dev_class: None,
                oods_flag: None,
                confidence_index: None,
                sender_state: None,
                hibernation_until: 0,
                wall_clock_lock: 0,
                emission_claimed_epoch: 0,
                stake_floor_until: 0, wallet_format: axiom_core_logic::types::WalletFormat::CURRENT,
            }
        }

        /// The time-bond fires a peer audit after AUDIT_MAX_TICK_GAP ticks even
        /// with NO volume trigger, and stamps the clock with the attested tick.
        #[test]
        fn time_bond_fires_after_gap_with_no_volume_trigger() {
            let avm = make_avm(); // validator_pk = 0xAA…
            let peer = vec![0xBBu8; 32];
            // Just past the gap; last demand tick starts at 0.
            let tick = AUDIT_MAX_TICK_GAP + 1;
            let inputs = witnessed_inputs(Some(tick), peer.clone());
            let outputs = accept_outputs(Some([9u8; 32]), None); // no volume demand

            assert!(avm.pending_audit.lock().unwrap().is_none());
            avm.enforce_audit_post(&inputs, &outputs, true);

            let pending = avm.pending_audit.lock().unwrap();
            let audit = pending.as_ref().expect("time-bond must arm a peer audit");
            assert!(audit.is_peer, "witness is a different validator → peer audit");
            assert_eq!(audit.demand.target_validator_pk, peer, "target = the prev-receipt witness");
            assert_eq!(
                avm.last_peer_audit_demand_tick.load(Ordering::Acquire),
                tick,
                "the clock is stamped with the attested tick that fired it",
            );
            drop(pending);
            assert_eq!(avm.peer_audit_trigger_counts(), (0, 1),
                "YP §23.14 item 10: a time-bond demand counts as time_bond, never volume");
        }

        /// YP §23.14 item 10 (2026-09-26): a guest VOLUME demand counts as
        /// volume — so a run can tell which trigger armed each peer audit.
        #[test]
        fn volume_demand_counts_as_volume() {
            let avm = make_avm();
            let peer = vec![0xBBu8; 32];
            let inputs = witnessed_inputs(Some(1), peer.clone()); // far below the time-bond gap
            let demand = AuditDemand { challenge_nonce: [3u8; 32], target_validator_pk: peer, trigger_txid: [9u8; 32] };
            let outputs = accept_outputs(Some([9u8; 32]), Some(demand));
            avm.enforce_audit_post(&inputs, &outputs, true);
            assert!(avm.pending_audit.lock().unwrap().as_ref().is_some_and(|a| a.is_peer));
            assert_eq!(avm.peer_audit_trigger_counts(), (1, 0));
        }

        /// Not yet at the gap ⇒ no fire; the clock resets on a demand so it does
        /// not re-fire until a FULL gap has passed again.
        #[test]
        fn time_bond_respects_the_gap_and_resets() {
            let avm = make_avm();
            let peer = vec![0xBBu8; 32];

            // Well within the gap from tick 0 ⇒ silent.
            let inputs = witnessed_inputs(Some(AUDIT_MAX_TICK_GAP), peer.clone()); // == gap, not > gap
            avm.enforce_audit_post(&inputs, &accept_outputs(Some([1u8; 32]), None), true);
            assert!(avm.pending_audit.lock().unwrap().is_none(), "at exactly the gap, not past it → silent");

            // Past the gap ⇒ fires, clock = t1.
            let t1 = AUDIT_MAX_TICK_GAP + 1;
            avm.enforce_audit_post(&witnessed_inputs(Some(t1), peer.clone()),
                                   &accept_outputs(Some([2u8; 32]), None), true);
            assert!(avm.pending_audit.lock().unwrap().is_some(), "past the gap → fires");
            // Clear the countdown as a completed/expired audit would.
            *avm.pending_audit.lock().unwrap() = None;

            // t1 + gap is NOT past the gap from t1 ⇒ silent (reset worked).
            avm.enforce_audit_post(&witnessed_inputs(Some(t1 + AUDIT_MAX_TICK_GAP), peer.clone()),
                                   &accept_outputs(Some([3u8; 32]), None), true);
            assert!(avm.pending_audit.lock().unwrap().is_none(), "clock reset to t1 → no refire within a gap");

            // One tick further IS past the gap from t1 ⇒ fires again.
            avm.enforce_audit_post(&witnessed_inputs(Some(t1 + AUDIT_MAX_TICK_GAP + 1), peer.clone()),
                                   &accept_outputs(Some([4u8; 32]), None), true);
            assert!(avm.pending_audit.lock().unwrap().is_some(), "a full gap after the reset → fires again");
        }

        /// §23.14 (KI#210): a demand must NOT arm on a NON-audited execution. The
        /// trigger tx is accumulated into the audit buffer ONLY when `accumulate`
        /// (pulse_post_execute returns early otherwise), and a self-audit can be
        /// confirmed ONLY against a buffer entry — so a demand armed on a non-audited
        /// CL2 witness references a trigger tx that was never recorded, can never be
        /// confirmed, and self-terminates the validator (tier C: 10 of 15 residual
        /// self-terminates). This is red without the `if !accumulate { return }`
        /// gate — the first assert would arm.
        #[test]
        fn time_bond_never_arms_on_a_non_audited_execution() {
            let avm = make_avm();
            let peer = vec![0xBBu8; 32];
            let tick = AUDIT_MAX_TICK_GAP + 1; // well past the gap → would arm if audited
            avm.enforce_audit_post(&witnessed_inputs(Some(tick), peer.clone()),
                                   &accept_outputs(Some([5u8; 32]), None), false);
            assert!(avm.pending_audit.lock().unwrap().is_none(),
                    "a non-audited execution must NOT arm — its trigger tx is not in the buffer");
            // The SAME round on an AUDITED execution DOES arm — proving the gate,
            // not the tick logic, is what blocked it.
            avm.enforce_audit_post(&witnessed_inputs(Some(tick), peer.clone()),
                                   &accept_outputs(Some([5u8; 32]), None), true);
            assert!(avm.pending_audit.lock().unwrap().is_some(),
                    "the same round on an audited execution arms");
        }

        /// No attested tick on the round ⇒ the time-bond cannot judge elapsed
        /// protocol time ⇒ it stays silent (never wall clock, never tx.epoch).
        #[test]
        fn time_bond_silent_without_attested_tick() {
            let avm = make_avm();
            let peer = vec![0xBBu8; 32];
            // Huge tx.epoch but NO oods attestation → no attested tick.
            let mut inputs = witnessed_inputs(None, peer);
            inputs.transaction.epoch = AUDIT_MAX_TICK_GAP + 10_000;
            avm.enforce_audit_post(&inputs, &accept_outputs(Some([1u8; 32]), None), true);
            assert!(avm.pending_audit.lock().unwrap().is_none(), "no attested tick → no time-bond");
        }

        /// The AVM exposes the pending peer-audit DEMAND (with target) so Lambda can
        /// mirror a TIME-BOND demand into its own pending and actually SEND the request
        /// (else a time-bond audit falsely bans NonResponds with no request sent).
        #[test]
        fn pending_peer_audit_demand_exposes_the_target() {
            let avm = make_avm();
            let target = vec![0xBBu8; 32];
            // Arm a peer audit as enforce_audit_post would (peer + expected hash set).
            *avm.pending_audit.lock().unwrap() = Some(PendingAudit {
                demand: AuditDemand {
                    challenge_nonce: [1u8; 32],
                    target_validator_pk: target.clone(),
                    trigger_txid: [2u8; 32],
                },
                remaining: 100,
                trigger_tx_number: 0,
                is_peer: true,
                dispatched_at_tick: None,
                peer_expected_hash: Some([3u8; 32]),
                dispatched: false,
                self_expected_digest: None,
            });
            let d = avm.pending_peer_audit_demand().expect("peer demand present");
            assert_eq!(d.target_validator_pk, target, "Lambda reads the target from here to send");
            assert!(avm.pending_peer_audit_request().is_some(), "request also available");
            // The mirror accessor surfaces a PEER demand too (peer path unchanged).
            assert_eq!(
                avm.pending_time_bond_demand().expect("peer demand surfaces for the mirror")
                    .target_validator_pk,
                target,
            );
            // A self-audit (is_peer=false) must NOT surface as a peer demand.
            avm.pending_audit.lock().unwrap().as_mut().unwrap().is_peer = false;
            assert!(avm.pending_peer_audit_demand().is_none(), "self-audit is not a peer demand");
            // …but it MUST surface via pending_time_bond_demand, or a time-bond
            // SELF-audit is mirrored to Lambda by NEITHER path (the guest volume
            // trigger is dev-gated out), Lambda's resolve_audit_confirmation finds
            // nothing to confirm, and the AVM countdown SELF-TERMINATES the
            // validator (KI#210/#207, live 2026-09-23). This assertion is red
            // without pending_time_bond_demand.
            assert_eq!(
                avm.pending_time_bond_demand().expect("self-audit demand surfaces for the mirror")
                    .target_validator_pk,
                target, "the self-audit must be mirrorable so Lambda can build its confirmation",
            );
        }

        /// Arm a PEER audit on `target` exactly as `enforce_audit_post` would,
        /// with the given countdown / dispatch state.
        fn arm_peer_audit(avm: &AvmInterpreter, target: &[u8], remaining: u8,
                          dispatched: bool, dispatched_at_tick: Option<u64>) {
            *avm.pending_audit.lock().unwrap() = Some(PendingAudit {
                demand: AuditDemand {
                    challenge_nonce: [1u8; 32],
                    target_validator_pk: target.to_vec(),
                    trigger_txid: [2u8; 32],
                },
                remaining,
                trigger_tx_number: 0,
                is_peer: true,
                dispatched_at_tick,
                peer_expected_hash: Some([3u8; 32]),
                dispatched,
                self_expected_digest: None,
            });
        }

        /// §23.14 silence ruling, 2026-09-24: a peer-audit demand whose request
        /// Lambda NEVER DISPATCHED must not ban the target. Live (tier C on
        /// `ab98b539`) the target lookup could never match (KI#207), so every
        /// demand expired undispatched and 32 innocent co-witnesses were banned
        /// `NonResponds` in one run. Undispatched expiry is OUR non-compliance
        /// (§23.14: Lambda did not initiate the audit) → `AuditTimeout`; only a
        /// DISPATCHED request's expiry is B's attributable silence → ban.
        /// Red on the pre-fix code (which banned in both cases) — mutation-verified
        /// 2026-09-24: with the `dispatched` gate removed it fails "got Ok(())".
        #[test]
        fn undispatched_peer_audit_never_bans_the_target() {
            let avm = make_avm();
            let target = vec![0xBBu8; 32];
            let other = vec![0xCCu8; 32];   // the TX's witness — not the target

            // (1) countdown drained, request never sent → A's own penalty, B untouched.
            arm_peer_audit(&avm, &target, 0, false, None);
            let r = avm.enforce_audit_pre(&witnessed_inputs(Some(1), other.clone()));
            assert!(matches!(r, Err(AvmError::AuditTimeout { .. })),
                    "an undispatched peer demand expiring is Lambda's non-compliance, got {r:?}");
            assert!(!avm.is_validator_banned(&target),
                    "a peer that was never asked anything must not be banned NonResponds");

            // (2) the SAME expiry after dispatch is B's attributable silence → ban.
            arm_peer_audit(&avm, &target, 0, true, Some(1));
            assert!(avm.enforce_audit_pre(&witnessed_inputs(Some(1), other.clone())).is_ok(),
                    "a peer ban never self-terminates the innocent auditor");
            assert!(avm.is_validator_banned(&target), "dispatched + full budget drained → NonResponds");
            assert!(avm.pending_audit.lock().unwrap().is_none(), "the demand is cleared by the ban");
        }

        /// §23.14.3 (tick discipline, 2026-09-24): B's response deadline is
        /// `PEER_AUDIT_TIMEOUT_TICKS` past the validated-tick WATERMARK at dispatch —
        /// never wall clock. A stale `dispatched_at_tick` on an UNDISPATCHED audit is
        /// ignored, `mark_peer_audit_dispatched` stamps the watermark, the ban fires
        /// exactly at the deadline, and `unmark_peer_audit_dispatched` (the carrier
        /// failed after hand-off) puts the audit back to undispatched so an expiry
        /// is A's own `AuditTimeout`, never B's ban (closes the KI#211 residual).
        #[test]
        fn peer_audit_response_deadline_is_tick_disciplined_and_runs_from_dispatch() {
            use axiom_core_logic::types::PEER_AUDIT_TIMEOUT_TICKS as T;
            let avm = make_avm();
            let target = vec![0xBBu8; 32];
            let other = vec![0xCCu8; 32];
            let at = |tick: u64| { let mut i = witnessed_inputs(Some(1), other.clone()); i.transaction.epoch = tick; i };

            // Undispatched, with a stale stamp far in the past: no ban, countdown ticks.
            arm_peer_audit(&avm, &target, 5, false, Some(1));
            assert!(avm.enforce_audit_pre(&at(1_000 + T + 1)).is_ok());
            assert!(!avm.is_validator_banned(&target), "the deadline cannot run before dispatch");
            assert_eq!(avm.pending_audit.lock().unwrap().as_ref().unwrap().remaining, 4);

            // Dispatch stamps the CURRENT watermark, not the wall clock.
            assert!(avm.mark_peer_audit_dispatched());
            let d0 = 1_000 + T + 1;
            assert_eq!(avm.pending_audit.lock().unwrap().as_ref().unwrap().dispatched_at_tick, Some(d0));
            assert!(avm.mark_peer_audit_dispatched(), "idempotent");
            assert_eq!(avm.pending_audit.lock().unwrap().as_ref().unwrap().dispatched_at_tick, Some(d0), "not restarted");

            // T−1 ticks after dispatch: still waiting. T ticks: banned.
            assert!(avm.enforce_audit_pre(&at(d0 + T - 1)).is_ok());
            assert!(!avm.is_validator_banned(&target), "one tick short of the deadline");
            assert!(avm.enforce_audit_pre(&at(d0 + T)).is_ok());
            assert!(avm.is_validator_banned(&target), "deadline reached → NonResponds");
            assert!(avm.pending_audit.lock().unwrap().is_none());

            // Carrier failure after hand-off: back to undispatched; the countdown's
            // expiry is then OUR AuditTimeout, and the peer is never banned.
            let target2 = vec![0xDDu8; 32];
            arm_peer_audit(&avm, &target2, 0, true, Some(d0));
            assert!(avm.unmark_peer_audit_dispatched(), "a dispatched peer audit is un-marked");
            assert!(!avm.unmark_peer_audit_dispatched(), "already undispatched → false");
            let r = avm.enforce_audit_pre(&at(d0 + 10 * T));
            assert!(matches!(r, Err(AvmError::AuditTimeout { .. })), "expiry after a failed send is ours, got {r:?}");
            assert!(!avm.is_validator_banned(&target2), "the peer the carrier never reached is not banned");

            // A self-audit is never a dispatchable peer request.
            arm_peer_audit(&avm, &target, 5, false, None);
            avm.pending_audit.lock().unwrap().as_mut().unwrap().is_peer = false;
            assert!(!avm.mark_peer_audit_dispatched(), "self-audit: nothing to dispatch");
        }

        /// SELF-audit FIXED (2026-09-24): the confirmation is judged against the
        /// digest of the triggering execution, fixed at arming — with an EMPTY
        /// ring (the pulse audit resets it after every accepted tx). Red on the
        /// old ring lookup: with no entry the content check returned false and
        /// the countdown self-terminated. Also: a wrong-field confirmation is
        /// still refused (the check can fail).
        #[test]
        fn self_audit_confirmation_is_judged_against_this_executions_digest_after_a_ring_reset() {
            let avm = make_avm();                     // our pk = [0xAA; 32]
            let me = vec![0xAAu8; 32];
            let txid = [0x33u8; 32];
            let demand = AuditDemand { challenge_nonce: [4u8; 32], target_validator_pk: me.clone(), trigger_txid: txid };
            let mut inputs = witnessed_inputs(Some(42), vec![0xBBu8; 32]);
            inputs.transaction.amount = 250_000;
            let mut outputs = accept_outputs(Some(txid), Some(demand.clone()));
            outputs.produced_state_id = Some([0x44u8; 32]);
            assert!(avm.audit_buffer.lock().unwrap().entries.is_empty(), "precondition: ring empty (as after a reset)");
            avm.enforce_audit_post(&inputs, &outputs, true);
            {
                let p = avm.pending_audit.lock().unwrap();
                let a = p.as_ref().expect("self demand armed");
                assert!(!a.is_peer, "target == our pk ⇒ SELF audit");
                assert!(a.self_expected_digest.is_some(), "digest fixed at arming");
            }
            let balance = inputs.current_state.as_ref().map(|s| s.balance).unwrap_or(0);
            // Lambda's honest confirmation: the DB record for trigger_txid.
            let mut next = witnessed_inputs(Some(43), vec![0xBBu8; 32]);
            next.audit_confirmation = Some(axiom_core_logic::types::AuditConfirmation {
                challenge_nonce: [4u8; 32], target_validator_pk: me.clone(),
                sender_balance: balance, receiver_balance: 0, state_id: [0x44u8; 32], amount: 250_000,
            });
            // A WRONG confirmation first: must not clear (the check can fail).
            let mut wrong = next.clone();
            wrong.audit_confirmation.as_mut().unwrap().amount = 250_001;
            assert_eq!(avm.audit_operator_counts().0, 1, "dashboard: the self demand is counted when armed");
            assert!(avm.enforce_audit_pre(&wrong).is_ok());
            assert!(avm.pending_audit.lock().unwrap().is_some(), "tampered fields do not clear the self audit");
            assert_eq!(avm.audit_operator_counts().1, 0, "a tampered confirmation is not a pass");
            // The honest one clears it — with the ring still empty.
            assert!(avm.enforce_audit_pre(&next).is_ok());
            assert!(avm.pending_audit.lock().unwrap().is_none(), "honest confirmation verified against the arming digest");
            assert_eq!(avm.audit_operator_counts(), (1, 1, 0), "dashboard: one self audit armed, one passed, no ban");
        }

        /// KI#214 (2026-09-24): A's expected hash for a PEER audit is the digest
        /// of THIS execution, available the moment the demand arms — with an
        /// EMPTY audit buffer (the pulse audit resets the ring after every
        /// accepted tx on the dev fleet). Red on the pre-fix code, which looked
        /// the current tx up in the ring by `tx_counter` before it was
        /// accumulated: `None` after a reset (request never built), or the
        /// PREVIOUS tx's digest (honest reply judged HashMismatch).
        #[test]
        fn peer_audit_expected_hash_is_this_executions_digest_even_with_an_empty_buffer() {
            let avm = make_avm();
            let peer = vec![0xBBu8; 32];
            let txid = [9u8; 32];
            let demand = AuditDemand { challenge_nonce: [1u8; 32], target_validator_pk: peer.clone(), trigger_txid: txid };
            let mut inputs = witnessed_inputs(Some(42), peer.clone());
            inputs.transaction.amount = 1_000_000;
            let mut outputs = accept_outputs(Some(txid), Some(demand));
            outputs.produced_state_id = Some([0x5Au8; 32]);
            assert!(avm.audit_buffer.lock().unwrap().entries.is_empty(), "precondition: nothing accumulated yet");
            avm.enforce_audit_post(&inputs, &outputs, true);
            let expected = axiom_core_logic::audit::compute_peer_audit_hash(
                &txid,
                inputs.current_state.as_ref().map(|s| s.balance).unwrap_or(0),
                0, &[0x5Au8; 32], 1_000_000,
            );
            assert_eq!(avm.pending_peer_audit_hash(), Some(expected),
                       "the expected hash is THIS tx's digest, not a ring lookup");
            assert!(avm.pending_peer_audit_request().is_some(),
                    "and so the request can be built on the very next witness");
        }

        #[test]
        fn volume_trigger_arms_and_resets_time_bond_clock() {
            let avm = make_avm();
            let peer = vec![0xBBu8; 32];
            let txid = [7u8; 32];
            // A guest demand targeting the peer (as the guest would produce).
            let demand = AuditDemand {
                challenge_nonce: [1u8; 32],
                target_validator_pk: peer.clone(),
                trigger_txid: txid,
            };
            // Attested tick is small (well within a gap) — the volume trigger
            // fires regardless, and must still stamp the clock.
            let tick = 42u64;
            let inputs = witnessed_inputs(Some(tick), peer.clone());
            avm.enforce_audit_post(&inputs, &accept_outputs(Some(txid), Some(demand)), true);

            let pending = avm.pending_audit.lock().unwrap();
            let audit = pending.as_ref().expect("volume trigger must arm");
            assert!(audit.is_peer);
            assert_eq!(audit.demand.target_validator_pk, peer);
            assert_eq!(
                avm.last_peer_audit_demand_tick.load(Ordering::Acquire),
                tick,
                "a volume audit also resets the low-volume time-bond clock",
            );
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
            // Each entry does Argon2id(32MB) → BLAKE3 — intentionally heavier
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

            // Argon2id(32MB, t=1) should be under 2000ms/entry even in debug
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
            println!("  ║ Phase 1: Audit buffer (Argon2id(32MB) → BLAKE3 chain)    ║");
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
            AvmInterpreter::new_uncalibrated(vec![0x00], [0u8; 32], false)
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
        fn test_ignition_process_bypasses_gate_and_stays_blocked() {
            let avm = make_blocked_avm();
            assert!(!avm.is_pulse_ready());

            // Process ignition TX — bypasses pulse gate
            let inputs = create_test_inputs();
            let result = avm.process_ignition(inputs);
            assert!(result.is_ok(), "ignition TX must bypass pulse gate");

            // Core stays blocked until complete_ignition (no host timer — KI#125)
            assert!(!avm.is_pulse_ready(), "process_ignition alone must not unblock Core");
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

        // test_ignition_rejects_without_process DELETED 2026-10-03 (KI#125): the
        // ordering it tested was enforced by the deleted host `Instant`
        // (`ignition_t0`). Lambda's one caller always runs process → complete.

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

            // THE builders (KI#55 Pattern 1) — never a test-side copy of the preimage.
            let diffusion_id = axiom_core_logic::compute::fanout_diffusion_id(&content, pk.as_bytes());
            let signing_payload = axiom_core_logic::compute::fanout_signing_payload(
                &diffusion_id, content_type, &content, ttl_original, fanout, timestamp,
            );
            let sig = sk.sign(&signing_payload);

            let receiver_wallet_id = generate_wallet_id("test@test.com", "42", &[0u8; 32])
                .expect("wallet id");

            PublicInputs {
                zkq_request: None,
                fact_certificates: Vec::new(),
                claimant_vbc: None,
                receiver_current_wall_clock_lock: None,
                receiver_current_emission_claimed_epoch: None,
                receiver_current_stake_floor_until: None,
                receiver_current_wallet_format: None,
                fob_claim_attestation: None,
                receiver_witness: None,
                receiver_signing_key: None,
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
                        genesis_lineage: [0u8; 32],
                        nabla_registration: None,
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
                    candidacy_pulse: None,
                    renewal_work_receipt: None,
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
                None => {
                    eprintln!("SKIP: ELF not found");
                    eprintln!("      (this silent skip is policed by differential_guest_elf_presence_canary)");
                    return;
                }
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
                None => {
                    eprintln!("SKIP: ELF not found");
                    eprintln!("      (this silent skip is policed by differential_guest_elf_presence_canary)");
                    return;
                }
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
                None => {
                    eprintln!("SKIP: ELF not found");
                    eprintln!("      (this silent skip is policed by differential_guest_elf_presence_canary)");
                    return;
                }
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
                None => {
                    eprintln!("SKIP: ELF not found");
                    eprintln!("      (this silent skip is policed by differential_guest_elf_presence_canary)");
                    return;
                }
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

}

#[cfg(all(test, feature = "std"))]
mod self_audit_tests {
    //! §5.2.2e — the self-audit produces a proof Core's verifier accepts.
    use super::*;

    // ── KI#55 B2#2 (2026-10-02): ONE builder each for `AXIOM_AUDIT_SELECT` and
    // `AXIOM_AUDIT_VERIFY`. The constants below were computed in Python from the
    // YP Appendix layouts (`AXIOM_AUDIT_SELECT` = BLAKE3(tag ‖ accumulator ‖
    // validator_pk); `AXIOM_AUDIT_VERIFY` = BLAKE3(tag ‖ subset_acc ‖
    // argon2id_output); Fiat-Shamir = BLAKE3(seed ‖ round_le_u64) → u32le % total,
    // dedup, sort), NOT from this code — so a refactor that moves one byte goes red.

    #[test]
    fn audit_select_seed_kat() {
        assert_eq!(hex::encode(audit_select_seed(&[0x11; 32], &[0x22; 32])),
            "7900bd0130e3b6aedb7f89cf9ef8471e0fa86848cdacd062647de8b27d059f6a");
    }

    #[test]
    fn audit_chain_step_kat() {
        assert_eq!(hex::encode(audit_chain_step(&[0x33; 32], &[0x44; 32])),
            "6488f522e0902159a0d0bf80b9587c49f03f9cce12b0b162b3cf393205dbe6ba");
    }

    /// Step 0 — the PROVER's seed (`generate_request`) selects exactly the indices
    /// the Python layout predicts for accumulator `11×32`, pk `22×32`, 64 entries.
    #[test]
    fn audit_select_seed_matches_the_yp_layout_on_the_prover_path() {
        let mut buf = AuditBuffer::new();
        buf.accumulator = [0x11; 32];
        buf.entries = (0..64u64).map(|i| TxDigest {
            tx_number: i + 1, sender_balance: 0, receiver_balance: 0,
            state_id: [i as u8; 32], amount: 0,
        }).collect();
        let req = buf.generate_request(&[0x22; 32], 0);
        assert_eq!(req.selected_indices, vec![26, 39, 44, 47, 49, 55, 56],
            "AXIOM_AUDIT_SELECT seed drifted from the YP layout (KAT 7900bd01…)");
    }

    /// Step 0 — end-to-end prover/verifier agreement pinned to bytes produced by the
    /// PRE-consolidation code (captured 2026-10-02 before the refactor): the
    /// self-audit chain (seed + Argon2id→`AXIOM_AUDIT_VERIFY` chain) for a fixed
    /// key/tick, and the issuer's replay of it. Production Argon2id cost only.
    #[cfg(not(feature = "light-audit"))]
    #[test]
    fn audit_chain_is_byte_identical_to_the_pre_consolidation_code() {
        let pk = [0x22u8; 32];
        let p = self_audit_pulse(&pk, 1_000, 20);
        assert_eq!(p.sample_size, 2);
        assert_eq!(hex::encode(p.full_accumulator), "8e02d14fdcb38a4aeba0ef429438bc4fe1295cecf0328c0550371df25b47aefc");
        assert_eq!(hex::encode(p.audit_hash), "7501899f8d21324277c769b9c9e06689d23ebd215b3850e27e9acb98cf9cb087");
        assert_eq!(verify_self_audit_sample(&pk, 1_000, 20, 2, &p.full_accumulator, &p.audit_hash), Ok(()));
    }

    #[test]
    fn a_self_audit_verifies_under_core_and_carries_real_content() {
        use ed25519_dalek::Signer;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x71u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let entries = axiom_core_logic::pulse::PULSE_CANDIDACY_MIN_ENTRIES as u32;
        let tick = 1_000_000u64;
        let p = self_audit_pulse(&pk, tick, entries);
        assert_eq!(p.entry_count, entries);
        assert_eq!(p.epoch, axiom_core_logic::pulse::pulse_epoch_of_tick(tick));
        assert!(p.sample_size >= 1 && p.audit_hash != [0u8; 32] && p.argon2id_per_sec > 0);
        // Part iii: the issuer's native replay reproduces the sample from
        // (pk, tick) — and fails for another tick, another key, a tampered hash.
        assert_eq!(verify_self_audit_sample(&pk, tick, p.entry_count, p.sample_size, &p.full_accumulator, &p.audit_hash), Ok(()));
        assert!(verify_self_audit_sample(&pk, tick + 1, p.entry_count, p.sample_size, &p.full_accumulator, &p.audit_hash).is_err(), "another tick is another chain");
        assert!(verify_self_audit_sample(&[0x72u8; 32], tick, p.entry_count, p.sample_size, &p.full_accumulator, &p.audit_hash).is_err(), "another key is another chain");
        let mut bad = p.audit_hash; bad[0] ^= 1;
        assert!(verify_self_audit_sample(&pk, tick, p.entry_count, p.sample_size, &p.full_accumulator, &bad).is_err(), "a forged hash does not reproduce");
        let payload = axiom_core_logic::pulse::pulse_proof_sign_payload(&pk, p.epoch, &p.full_accumulator, &p.audit_hash, Some(tick));
        let proof = axiom_core_logic::wire_client::PulseProofRequest {
            validator_pk: pk, epoch: p.epoch, full_accumulator: p.full_accumulator, entry_count: p.entry_count,
            sample_size: p.sample_size, audit_hash: p.audit_hash, argon2id_per_sec: p.argon2id_per_sec,
            signature: sk.sign(&payload).to_bytes().to_vec(),
            attested_tick: Some(tick),
        };
        // A provisional bundle naming this key as its Ed25519 subject accepts the proof.
        let mut target = axiom_core_logic::types::VBC {
            genesis_lineage: [0u8; 32], network_size_baseline: 9, baseline_tick: tick, version: 0x09,
            validator_id: [1u8; 32], subject_pubkey_sphincs: vec![2u8; 32], subject_pubkey_dilithium: vec![0u8; 1952],
            subject_pubkey_ed25519: pk.to_vec(), pgp_fingerprint: Vec::new(), node_name: String::new(),
            proof_cap: String::new(), issued_at: tick, expires_at: tick + 3600, chain_depth: 1,
            issuer_set: vec![vec![3u8; 32], vec![4u8; 32], vec![5u8; 32]], signatures: Vec::new(),
            max_tx: 0, founding_vbc_hash: [0u8; 32], nabla_registration: None,
        };
        let _ = &mut target;
        let bundle = axiom_core_logic::types::VBCProofBundle { target_vbc: target, supporting_vbcs: Vec::new(), candidacy_pulse: Some(proof), renewal_work_receipt: None };
        assert_eq!(axiom_core_logic::pulse::verify_candidacy_pulse(&bundle, tick, tick), Ok(()));
    }
}

#[cfg(test)]
mod ban_wording_tests {
    #[test]
    fn duration_text_states_the_window_in_its_natural_unit() {
        assert_eq!(super::duration_text(3_600), "1 h");
        assert_eq!(super::duration_text(86_400), "24 h");
        assert_eq!(super::duration_text(5_400), "90 min");
        assert_eq!(super::duration_text(45), "45 s");
    }
}
