//! AXIOM Prover Worker — standalone subprocess for STARK proof generation.
//!
//! Reads a checkpoint proving request from stdin, generates a real RISC Zero
//! STARK proof using the minimal ZK boundary (14 essential checks), and writes
//! the result back to stdout. Runs outside Tokio to avoid Rayon deadlock.
//!
//! Protocol (stdin/stdout):
//!   Request:  4-byte LE length + serde_json bytes of CheckpointRequest
//!   Response: 4-byte LE length + serde_json bytes of ProverResult
//!
//! Usage:
//!   cargo build --release -p axiom-zk-vm --features prove --bin prover-worker
//!
//! Lambda spawns this as a child process and communicates via stdio.

use axiom_dmap_vm::{PublicInputs, PublicOutputs};
use axiom_zk_vm::ZkvmProver;
use std::io::{Read, Write};
use std::time::Instant;

/// Request from Lambda to prove a checkpoint.
#[derive(serde::Serialize, serde::Deserialize)]
struct CheckpointRequest {
    inputs: PublicInputs,
    native_outputs: Option<PublicOutputs>,
}

/// Result sent back to the caller over stdout.
#[derive(serde::Serialize, serde::Deserialize)]
struct ProverResult {
    success: bool,
    /// serde_json of PublicOutputs (only if success)
    outputs_json: Option<String>,
    /// ZkvmReceipt bytes via to_bytes() (hex-encoded, only if success)
    receipt_hex: Option<String>,
    /// Error message (only if !success)
    error: Option<String>,
    /// Proving time in milliseconds
    elapsed_ms: u64,
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

fn main() {
    eprintln!("[prover-worker] Starting...");

    // Initialize prover once (loads ELF + IMAGE_ID)
    let mut prover = match ZkvmProver::production() {
        Ok(p) => {
            eprintln!(
                "[prover-worker] Prover ready, IMAGE_ID={}",
                hex::encode(p.program_digest())
            );
            p
        }
        Err(e) => {
            eprintln!("[prover-worker] FATAL: {}", e);
            std::process::exit(1);
        }
    };

    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();

    // Process requests in a loop (one at a time)
    loop {
        // Read request
        let frame = match read_frame(&mut stdin) {
            Ok(f) => f,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    eprintln!("[prover-worker] Stdin closed, exiting.");
                    break;
                }
                eprintln!("[prover-worker] Read error: {}", e);
                break;
            }
        };

        // Deserialize checkpoint request
        let request: CheckpointRequest = match serde_json::from_slice(&frame) {
            Ok(r) => r,
            Err(e) => {
                let result = ProverResult {
                    success: false,
                    outputs_json: None,
                    receipt_hex: None,
                    error: Some(format!("Failed to deserialize request: {}", e)),
                    elapsed_ms: 0,
                };
                let resp = serde_json::to_vec(&result).unwrap();
                if write_frame(&mut stdout, &resp).is_err() {
                    break;
                }
                continue;
            }
        };

        eprintln!("[prover-worker] Proving checkpoint {:?}...", request.inputs.mode);
        let start = Instant::now();

        // Generate real STARK proof via minimal ZK boundary (checkpoint mode)
        let result = match prover.prove_checkpoint(request.inputs, request.native_outputs) {
            Ok((checkpoint, receipt)) => {
                let elapsed = start.elapsed();
                eprintln!(
                    "[prover-worker] Checkpoint proof in {:.2?} ({} byte seal)",
                    elapsed,
                    receipt.seal.len()
                );
                ProverResult {
                    success: true,
                    outputs_json: Some(serde_json::to_string(&checkpoint).unwrap()),
                    receipt_hex: Some(hex::encode(receipt.to_bytes())),
                    error: None,
                    elapsed_ms: elapsed.as_millis() as u64,
                }
            }
            Err(e) => {
                let elapsed = start.elapsed();
                eprintln!("[prover-worker] Prove failed in {:.2?}: {}", elapsed, e);
                ProverResult {
                    success: false,
                    outputs_json: None,
                    receipt_hex: None,
                    error: Some(format!("{}", e)),
                    elapsed_ms: elapsed.as_millis() as u64,
                }
            }
        };

        let resp = serde_json::to_vec(&result).unwrap();
        if write_frame(&mut stdout, &resp).is_err() {
            eprintln!("[prover-worker] Write error, exiting.");
            break;
        }
    }
}
