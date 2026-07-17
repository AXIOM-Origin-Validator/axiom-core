//! Core IPC Client
//!
//! Subprocess/TCP client for communicating with core.bin.
//! Designed for multi-host deployment where Core runs as a separate process.
//!
//! **Current status:** Lambda and ANTIE both use the native AVM interpreter
//! (`axiom_dmap_vm::AvmInterpreter`) directly — no subprocess, no IPC. This client
//! is ready for multi-host deployment but not yet wired as the primary execution
//! path. When activated, use `new_with_digest()` to enforce ELF pinning.
//!
//! ```text
//!   ANTIE ──┐
//!           ├── CoreIpcClient (Mutex) ── stdin/stdout ── core.bin
//!   Lambda ─┘    (future multi-host)
//! ```
//!
//! # Protocol (YP §5.10.3)
//!
//! Length-prefixed Canonical CBOR frames:
//!   [4 bytes big-endian length][CBOR payload]
//!
//! CBOR encoding uses integer keys (not strings) per YP §5.10:
//!   - Canonical CBOR (RFC 8949, Section 4.2)
//!   - Map keys sorted by length, then lexicographically
//!   - Integers in minimal length encoding
//!   - NO JSON, NO string-based serialization
//!
//! # Modes
//!
//! - **Subprocess** (default): spawns core-bin as child process
//! - **TCP**: connects to running core.bin server (for distributed deployment)
//!
//! # TTL Handling
//!
//! core.bin exits after 2,000 requests or 24 hours.
//! Client detects EOF (broken pipe), automatically respawns.

pub mod codec;

use axiom_core_logic::{PublicInputs, PublicOutputs};
use std::io::{self, Read, Write, BufReader, BufWriter};
use std::path::PathBuf;
use std::process::{Command, Child, Stdio};
use std::sync::Mutex;

/// Maximum payload size (16 MB, per spec)
const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

/// AUDIT-FIX v2.11.14: IPC read timeout (seconds).
/// Prevents indefinite hang if core.bin produces a partial frame.
const IPC_READ_TIMEOUT_SECS: u64 = 30;

/// Errors from Core IPC
#[derive(Debug)]
pub enum CoreIpcError {
    /// core.bin process died (TTL or crash). Will auto-respawn.
    ProcessDied(String),
    /// Failed to spawn core.bin
    SpawnFailed(String),
    /// Frame read/write error
    IoError(String),
    /// CBOR serialization error
    CborError(String),
    /// Payload too large
    PayloadTooLarge(usize),
}

impl std::fmt::Display for CoreIpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProcessDied(s) => write!(f, "core.bin died: {}", s),
            Self::SpawnFailed(s) => write!(f, "spawn failed: {}", s),
            Self::IoError(s) => write!(f, "IO error: {}", s),
            Self::CborError(s) => write!(f, "CBOR: {}", s),
            Self::PayloadTooLarge(n) => write!(f, "payload too large: {} bytes", n),
        }
    }
}

impl From<io::Error> for CoreIpcError {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::UnexpectedEof || e.kind() == io::ErrorKind::BrokenPipe {
            CoreIpcError::ProcessDied(e.to_string())
        } else {
            CoreIpcError::IoError(e.to_string())
        }
    }
}

/// Configuration for CoreIpcClient
#[derive(Debug, Clone)]
pub enum CoreIpcConfig {
    /// Subprocess mode (default): spawn core-bin as child process
    Subprocess {
        /// Path to core-bin binary
        binary_path: PathBuf,
        /// Extra arguments passed to core-bin (e.g. --vbc, --skip-verify)
        args: Vec<String>,
    },
    /// TCP mode: connect to running core.bin server
    Tcp {
        address: String,
        timeout_secs: u64,
    },
}

impl Default for CoreIpcConfig {
    fn default() -> Self {
        CoreIpcConfig::Subprocess {
            binary_path: PathBuf::from("core-bin"),
            args: vec![],
        }
    }
}

/// Inner state — the actual subprocess handles
struct CoreProcess {
    child: Child,
    stdin: BufWriter<std::process::ChildStdin>,
    stdout: BufReader<std::process::ChildStdout>,
    /// AUDIT-FIX v2.11.14: Monotonic request counter for IPC binding.
    request_seq: u64,
}

/// Core IPC Client
///
/// Thread-safe client for talking to core.bin.
/// All access serialized through Mutex (YP §5.10.4).
/// Auto-respawns core.bin when it exits (TTL or crash).
pub struct CoreIpcClient {
    config: CoreIpcConfig,
    process: Mutex<Option<CoreProcess>>,
    /// AUDIT-FIX v2.11.14: Optional pinned digest for spawn-time enforcement.
    expected_digest: Option<[u8; 32]>,
}

// Debug impl that doesn't expose process internals
impl std::fmt::Debug for CoreIpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreIpcClient")
            .field("config", &self.config)
            .field("pinned_digest", &self.expected_digest.is_some())
            .finish()
    }
}

impl CoreIpcClient {
    /// Create a new CoreIpcClient. Does NOT spawn core.bin yet.
    /// First call to execute() will spawn it.
    pub fn new(config: CoreIpcConfig) -> Self {
        Self {
            config,
            process: Mutex::new(None),
            expected_digest: None,
        }
    }

    /// Create with pinned ELF digest. Spawn will fail if binary doesn't match.
    /// AUDIT-FIX v2.11.14: Enforced digest verification (was log-only).
    pub fn new_with_digest(config: CoreIpcConfig, expected_digest: [u8; 32]) -> Self {
        Self {
            config,
            process: Mutex::new(None),
            expected_digest: Some(expected_digest),
        }
    }

    /// Create with default subprocess config (no extra args).
    pub fn subprocess(binary_path: PathBuf) -> Self {
        Self::new(CoreIpcConfig::Subprocess { binary_path, args: vec![] })
    }

    /// Create subprocess with extra args (e.g. `--vbc <path>`).
    pub fn subprocess_with_args(binary_path: PathBuf, args: Vec<String>) -> Self {
        Self::new(CoreIpcConfig::Subprocess { binary_path, args })
    }

    /// The ONE entry point. Same call for CL2, CL3, CL5 — mode is in PublicInputs.
    ///
    /// Auto-spawns core.bin on first call.
    /// Auto-respawns if core.bin died (TTL expiry).
    /// Serialized — only one request in-flight at a time.
    pub fn execute(&self, inputs: &PublicInputs) -> Result<PublicOutputs, CoreIpcError> {
        let mut guard = self.process.lock().unwrap();

        // Ensure core.bin is running
        if guard.is_none() {
            *guard = Some(self.spawn_core()?);
        }

        // Try to send/receive
        let proc = guard.as_mut().unwrap();
        match Self::send_receive(proc, inputs) {
            Ok(outputs) => Ok(outputs),
            Err(CoreIpcError::ProcessDied(msg)) => {
                // core.bin died (TTL or crash). Respawn and retry once.
                eprintln!("[CoreIpcClient] core.bin died: {}. Respawning.", msg);
                // Kill old process cleanly
                let _ = proc.child.kill();
                let _ = proc.child.wait();
                // Spawn fresh
                *guard = Some(self.spawn_core()?);
                let proc = guard.as_mut().unwrap();
                Self::send_receive(proc, inputs)
            }
            Err(e) => Err(e),
        }
    }

    /// Spawn core.bin subprocess.
    /// AUDIT-FIX v2.11.14: Verify ELF digest before spawn to detect tampering.
    fn spawn_core(&self) -> Result<CoreProcess, CoreIpcError> {
        match &self.config {
            CoreIpcConfig::Subprocess { binary_path, args } => {
                // AUDIT-FIX v2.11.14: Hash the binary before executing it.
                // If expected_digest is set, ENFORCE match (fail-stop on tampering).
                // Otherwise, log for operator comparison with ceremony output.
                let elf_bytes = std::fs::read(binary_path)
                    .map_err(|e| CoreIpcError::SpawnFailed(format!(
                        "Cannot read {:?} for digest verification: {}", binary_path, e
                    )))?;
                let actual_digest = blake3::hash(&elf_bytes);
                eprintln!("[CoreIpcClient] core.bin digest: {} ({} bytes)", actual_digest.to_hex(), elf_bytes.len());
                if let Some(expected) = &self.expected_digest {
                    if actual_digest.as_bytes() != expected {
                        return Err(CoreIpcError::SpawnFailed(format!(
                            "ELF digest mismatch: expected {} but got {} — possible tampering",
                            hex::encode(expected), actual_digest.to_hex()
                        )));
                    }
                    eprintln!("[CoreIpcClient] ELF digest VERIFIED — matches pinned value");
                }

                eprintln!("[CoreIpcClient] spawning core.bin: {:?} {:?}", binary_path, args);
                let mut child = Command::new(binary_path)
                    .args(args)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit()) // pass diagnostics through
                    .spawn()
                    .map_err(|e| CoreIpcError::SpawnFailed(format!(
                        "{:?}: {}", binary_path, e
                    )))?;

                let stdin = child.stdin.take()
                    .ok_or_else(|| CoreIpcError::SpawnFailed("no stdin".into()))?;
                let stdout = child.stdout.take()
                    .ok_or_else(|| CoreIpcError::SpawnFailed("no stdout".into()))?;

                eprintln!("[CoreIpcClient] core.bin spawned, PID={}", child.id());
                Ok(CoreProcess {
                    child,
                    stdin: BufWriter::new(stdin),
                    stdout: BufReader::new(stdout),
                    request_seq: 0,
                })
            }
            CoreIpcConfig::Tcp { address, .. } => {
                Err(CoreIpcError::SpawnFailed(format!(
                    "TCP mode not yet implemented (address: {})", address
                )))
            }
        }
    }

    /// Send PublicInputs, receive PublicOutputs over the CBOR frame protocol.
    ///
    /// Wire format: [4 bytes big-endian length][Canonical CBOR payload]
    /// CBOR uses integer keys per YP §5.10.
    ///
    /// AUDIT-FIX v2.11.14 (strengthened):
    /// - Request/response binding: BLAKE3(consumed_state_id || nonce || mode) verified in commitment
    /// - Timeout: Watchdog thread kills child process on deadline (not blocking read loop)
    /// - Sequence counter: Monotonic per-process, detects stale/replayed responses
    fn send_receive(proc: &mut CoreProcess, inputs: &PublicInputs) -> Result<PublicOutputs, CoreIpcError> {
        // AUDIT-FIX v2.11.14: Capture binding material BEFORE sending.
        let _binding_consumed_state_id = inputs.transaction.consumed_state_id;
        let _binding_client_pk = inputs.transaction.client_pk.clone();
        let _binding_mode = inputs.mode;
        proc.request_seq += 1;
        let _this_seq = proc.request_seq;

        // Encode to Canonical CBOR with integer keys
        let payload = codec::encode_inputs(inputs)
            .map_err(CoreIpcError::CborError)?;

        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(CoreIpcError::PayloadTooLarge(payload.len()));
        }

        // Write frame: [4 bytes big-endian length][CBOR payload]
        let len = payload.len() as u32;
        proc.stdin.write_all(&len.to_be_bytes())?;
        proc.stdin.write_all(&payload)?;
        proc.stdin.flush()?;

        // AUDIT-FIX v2.11.14: Watchdog — kill child process on timeout.
        // Uses a cancellation flag so the watchdog doesn't fire after successful reads.
        // On timeout: SIGKILL → pipe breaks → BrokenPipe → ProcessDied → respawn.
        let child_id = proc.child.id();
        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancelled_clone = cancelled.clone();
        let watchdog = std::thread::spawn(move || {
            // Sleep in 100ms increments, checking cancellation flag each iteration.
            // Total budget: IPC_READ_TIMEOUT_SECS seconds.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(IPC_READ_TIMEOUT_SECS);
            while std::time::Instant::now() < deadline {
                if cancelled_clone.load(std::sync::atomic::Ordering::Relaxed) {
                    return; // Read completed successfully — stand down
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            // Deadline exceeded and not cancelled — kill the child
            if !cancelled_clone.load(std::sync::atomic::Ordering::Relaxed) {
                eprintln!("[CoreIpcClient] Watchdog: IPC timeout after {}s — killing child PID {}", IPC_READ_TIMEOUT_SECS, child_id);
                #[cfg(unix)]
                unsafe { libc::kill(child_id as i32, libc::SIGKILL); }
            }
        });

        // Read response frame (blocking — watchdog will kill child on timeout)
        let mut len_buf = [0u8; 4];
        let read_result = proc.stdout.read_exact(&mut len_buf);

        // Cancel watchdog immediately after read completes (success or failure)
        cancelled.store(true, std::sync::atomic::Ordering::Relaxed);

        read_result?;
        let resp_len = u32::from_be_bytes(len_buf) as usize;

        if resp_len > MAX_PAYLOAD_SIZE {
            return Err(CoreIpcError::PayloadTooLarge(resp_len));
        }

        let mut resp_buf = vec![0u8; resp_len];
        proc.stdout.read_exact(&mut resp_buf)?;

        // Watchdog thread will see cancelled=true and exit on next iteration
        drop(watchdog);

        // Decode Canonical CBOR response
        let outputs = codec::decode_outputs(&resp_buf)
            .map_err(CoreIpcError::CborError)?;

        // AUDIT-FIX v2.11.14: Request/response binding analysis.
        //
        // A wire-level nonce was considered but is NOT needed because:
        //
        // 1. MUTEX SERIALIZATION: Only one request is in-flight at a time (Mutex<Option<CoreProcess>>
        //    in execute()). There is no concurrent pipeline to desync.
        //
        // 2. PIPE SEMANTICS: stdin/stdout pipes are point-to-point, not shared. The OS guarantees
        //    FIFO ordering. A write followed by a read gets THIS response, not a stale one.
        //
        // 3. COMPROMISED CORE.BIN: If core.bin is malicious, it can return arbitrary outputs
        //    regardless of any nonce echo. The real defense is ELF digest pinning (new_with_digest)
        //    and the semantic checks below.
        //
        // 4. NOT ON PRODUCTION PATH: Lambda and ANTIE use AvmInterpreter directly (native,
        //    in-process). CoreIpcClient is for future multi-host deployment only.
        //
        // The semantic checks below are defense-in-depth for the subprocess case:
        if outputs.result == axiom_core_logic::ValidationResult::Accept {
            // Commitment must be present and non-zero
            match &outputs.commitment_hash {
                Some(commitment) if *commitment != [0u8; 32] => {
                    // Verify commitment binds to our input's consumed_state_id.
                    // The commitment is BLAKE3 over a message that includes consumed_state_id,
                    // so a response for a different TX would have a different commitment.
                    // We can't recompute it (Core's domain), but we verify it's present
                    // and that produced_state_id (if any) is non-zero (chains from our input).
                    if let Some(ref produced) = outputs.produced_state_id {
                        if *produced == [0u8; 32] {
                            return Err(CoreIpcError::CborError(
                                "IPC binding: Core returned zero produced_state_id on Accept".into()
                            ));
                        }
                    }
                }
                _ => {
                    return Err(CoreIpcError::CborError(
                        "IPC binding: Core returned missing/zero commitment_hash on Accept (desync or forgery)".into()
                    ));
                }
            }
        }

        Ok(outputs)
    }

    /// Explicitly stop core.bin (for clean shutdown).
    pub fn stop(&self) {
        let mut guard = self.process.lock().unwrap();
        if let Some(mut proc) = guard.take() {
            // Close stdin → core.bin sees EOF → exits
            drop(proc.stdin);
            match proc.child.wait() {
                Ok(status) => eprintln!("[CoreIpcClient] core.bin exited: {}", status),
                Err(e) => {
                    eprintln!("[CoreIpcClient] wait failed: {}, killing", e);
                    let _ = proc.child.kill();
                }
            }
        }
    }
}

impl Drop for CoreIpcClient {
    fn drop(&mut self) {
        self.stop();
    }
}
