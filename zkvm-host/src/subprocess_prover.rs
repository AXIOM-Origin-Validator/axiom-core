//! Subprocess Prover — delegates STARK proof generation to a child process.
//!
//! Solves the Tokio/Rayon deadlock: RISC Zero's prover uses Rayon internally,
//! which can deadlock when called from within a Tokio async runtime (even in
//! a separate OS thread). By running the prover in a completely separate process,
//! the Rayon thread pool is isolated from Tokio.
//!
//! Protocol: length-prefixed serde_json over stdin/stdout of `prover-worker` binary.

use crate::{ZkvmError, ZkvmReceipt, ZkvmConfig};
use axiom_dmap_vm::{PublicInputs, PublicOutputs};
use axiom_core_logic::ZkpCheckpointOutputs;
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};

/// Request sent to prover-worker subprocess.
#[derive(serde::Serialize)]
struct CheckpointRequest {
    inputs: PublicInputs,
    native_outputs: Option<PublicOutputs>,
}

/// Result from the prover-worker subprocess.
#[derive(serde::Deserialize)]
struct ProverResult {
    success: bool,
    outputs_json: Option<String>,
    receipt_hex: Option<String>,
    error: Option<String>,
    #[serde(rename = "elapsed_ms")]
    _elapsed_ms: u64,
}

/// Subprocess-based prover. Spawns `prover-worker` and communicates via stdio.
pub struct SubprocessProver {
    child: Child,
    program_digest: [u8; 32],
}

impl SubprocessProver {
    /// Spawn the prover-worker subprocess.
    ///
    /// `worker_path` is the path to the `prover-worker` binary.
    /// If None, searches for it next to the current executable or in PATH.
    pub fn spawn(worker_path: Option<&str>) -> Result<Self, ZkvmError> {
        // Load IMAGE_ID for our reference (we don't do proving, but callers need it)
        let mut config = ZkvmConfig::from_env();
        if !config.is_available() {
            return Err(ZkvmError::ExecutionFailed(
                "zkVM artifacts not found — cannot start prover-worker".into(),
            ));
        }
        let program_digest = config.load_image_id()?;

        let worker = find_worker_binary(worker_path)?;

        let child = Command::new(&worker)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()) // prover-worker logs go to Lambda's stderr
            .spawn()
            .map_err(|e| {
                ZkvmError::ExecutionFailed(format!(
                    "Failed to spawn prover-worker at {:?}: {}",
                    worker, e
                ))
            })?;

        Ok(Self {
            child,
            program_digest,
        })
    }

    /// Generate a STARK proof via the subprocess (checkpoint mode).
    ///
    /// Sends PublicInputs + native PublicOutputs to prover-worker.
    /// Returns ZkpCheckpointOutputs (14 essential checks) + receipt.
    pub fn prove(
        &mut self,
        inputs: PublicInputs,
        native_outputs: Option<PublicOutputs>,
    ) -> Result<(ZkpCheckpointOutputs, ZkvmReceipt), ZkvmError> {
        let stdin = self.child.stdin.as_mut().ok_or_else(|| {
            ZkvmError::ProofGenerationFailed("prover-worker stdin not available".into())
        })?;
        let stdout = self.child.stdout.as_mut().ok_or_else(|| {
            ZkvmError::ProofGenerationFailed("prover-worker stdout not available".into())
        })?;

        // Serialize checkpoint request (inputs + native outputs)
        let request = CheckpointRequest { inputs, native_outputs };
        let input_bytes = serde_json::to_vec(&request).map_err(|e| {
            ZkvmError::ProofGenerationFailed(format!("Failed to serialize request: {}", e))
        })?;

        // Write request frame
        write_frame(stdin, &input_bytes).map_err(|e| {
            ZkvmError::ProofGenerationFailed(format!("Failed to write to prover-worker: {}", e))
        })?;

        // Read response frame
        let resp_bytes = read_frame(stdout).map_err(|e| {
            ZkvmError::ProofGenerationFailed(format!("Failed to read from prover-worker: {}", e))
        })?;

        // Deserialize result
        let result: ProverResult = serde_json::from_slice(&resp_bytes).map_err(|e| {
            ZkvmError::ProofGenerationFailed(format!("Failed to parse prover-worker response: {}", e))
        })?;

        if !result.success {
            return Err(ZkvmError::ProofGenerationFailed(
                result.error.unwrap_or_else(|| "Unknown error".into()),
            ));
        }

        // Parse checkpoint outputs
        let outputs_json = result.outputs_json.ok_or_else(|| {
            ZkvmError::ProofGenerationFailed("Missing outputs in success response".into())
        })?;
        let checkpoint: ZkpCheckpointOutputs = serde_json::from_str(&outputs_json).map_err(|e| {
            ZkvmError::ProofGenerationFailed(format!("Failed to parse checkpoint outputs: {}", e))
        })?;

        // Parse receipt
        let receipt_hex = result.receipt_hex.ok_or_else(|| {
            ZkvmError::ProofGenerationFailed("Missing receipt in success response".into())
        })?;
        let receipt_bytes = hex::decode(&receipt_hex).map_err(|e| {
            ZkvmError::ProofGenerationFailed(format!("Failed to decode receipt hex: {}", e))
        })?;
        let receipt = ZkvmReceipt::from_bytes(&receipt_bytes)?;

        Ok((checkpoint, receipt))
    }

    /// Get the program digest (IMAGE_ID).
    pub fn program_digest(&self) -> [u8; 32] {
        self.program_digest
    }
}

impl Drop for SubprocessProver {
    fn drop(&mut self) {
        // Close stdin to signal the worker to exit
        drop(self.child.stdin.take());
        // Give it a moment then kill if still running
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            _ => {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }
}

fn read_frame(reader: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 100 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Frame too large: {} bytes", len),
        ));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_frame(writer: &mut impl Write, data: &[u8]) -> std::io::Result<()> {
    writer.write_all(&(data.len() as u32).to_le_bytes())?;
    writer.write_all(data)?;
    writer.flush()?;
    Ok(())
}

/// Find the prover-worker binary.
fn find_worker_binary(explicit_path: Option<&str>) -> Result<String, ZkvmError> {
    if let Some(path) = explicit_path {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
        return Err(ZkvmError::ExecutionFailed(format!(
            "prover-worker not found at: {}", path
        )));
    }

    // Check AXIOM_PROVER_WORKER env var
    if let Ok(path) = std::env::var("AXIOM_PROVER_WORKER") {
        if std::path::Path::new(&path).exists() {
            return Ok(path);
        }
    }

    // Check next to the current executable (covers both debug and release)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("prover-worker");
            if candidate.exists() {
                return Ok(candidate.to_string_lossy().into_owned());
            }
        }
    }

    // Check common cargo target directories (workspace root)
    for relative in &[
        "target/release/prover-worker",
        "target/debug/prover-worker",
        "../target/release/prover-worker",
        "../target/debug/prover-worker",
    ] {
        let p = std::path::Path::new(relative);
        if p.exists() {
            return Ok(p.canonicalize()
                .unwrap_or_else(|_| p.to_path_buf())
                .to_string_lossy()
                .into_owned());
        }
    }

    // Check in PATH
    if let Ok(output) = std::process::Command::new("which")
        .arg("prover-worker")
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(path);
            }
        }
    }

    Err(ZkvmError::ExecutionFailed(
        "prover-worker binary not found. Build with: \
         cargo build --release -p axiom-zk-vm --features prove --bin prover-worker"
            .into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_worker_explicit_nonexistent() {
        let result = find_worker_binary(Some("/nonexistent/prover-worker"));
        assert!(result.is_err());
    }
}
