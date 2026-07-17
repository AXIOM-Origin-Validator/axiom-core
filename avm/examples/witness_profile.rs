//! AVM witness performance profile harness.
//!
//! Loads consensus_vectors.json, hex-decodes each vector's CBOR inputs,
//! runs them through AvmInterpreter::execute() with AVM_PROFILE=1, and
//! prints per-stage timing. Used to determine whether witness latency is
//! dominated by Dilithium math (hypothesis A) or CBOR deserialization of
//! large post-quantum payloads (hypothesis B).
//!
//! Usage:
//!   AVM_PROFILE=1 cargo run --example witness_profile -p axiom-dmap-vm --release \
//!       --features axiom-core-logic/dev-mode -- \
//!       ~/axiom/src/core/avm-guest/target/axiom-core.elf \
//!       ~/axiom/src/tests/consensus_vectors.json

use axiom_dmap_vm::AvmInterpreter;
use axiom_core_ipc::codec::decode_inputs;
use axiom_core_logic::execute_core;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <elf-path> <vectors.json>", args[0]);
        std::process::exit(1);
    }
    let elf_path = &args[1];
    let vectors_path = &args[2];

    eprintln!("[PROFILE] loading ELF: {}", elf_path);
    let elf_bytes = std::fs::read(elf_path).expect("read elf");
    eprintln!("[PROFILE] ELF size: {} bytes", elf_bytes.len());

    let avm = AvmInterpreter::new(elf_bytes, [0u8; 32]);

    eprintln!("[PROFILE] loading vectors: {}", vectors_path);
    let raw = std::fs::read_to_string(vectors_path).expect("read vectors");
    let json: serde_json::Value = serde_json::from_str(&raw).expect("parse json");
    let vectors = json.get("vectors").and_then(|v| v.as_array()).expect("vectors array");
    eprintln!("[PROFILE] vector count: {}", vectors.len());

    let mut total_calls = 0;
    let mut total_elapsed_ns: u128 = 0;

    for (i, v) in vectors.iter().enumerate() {
        let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("?");
        let mode = v.get("mode").and_then(|x| x.as_str()).unwrap_or("?");
        let hex = match v.get("inputs_cbor_hex").and_then(|x| x.as_str()) {
            Some(h) => h,
            None => continue,
        };
        let cbor_bytes = match hex::decode(hex) {
            Ok(b) => b,
            Err(e) => { eprintln!("[{}] hex decode error: {}", id, e); continue; }
        };
        let inputs = match decode_inputs(&cbor_bytes) {
            Ok(i) => i,
            Err(e) => { eprintln!("[{}] cbor decode error: {}", id, e); continue; }
        };

        eprintln!("\n[PROFILE] === vector {} ({}) mode={} cbor_size={} ===",
                  i, id, mode, cbor_bytes.len());

        // Run NATIVE first — directly through axiom-core-logic, no AVM, no
        // RISC-V interpretation. This bounds the actual algorithmic cost
        // (Dilithium verify, BLAKE3, struct validation, etc.) without any
        // interpretation overhead.
        let t_native = Instant::now();
        let _native_out = execute_core(inputs.clone());
        let native_elapsed = t_native.elapsed();
        eprintln!("[PROFILE] native:  {:?}", native_elapsed);

        // Then run through AVM with full RISC-V interpretation
        let t_avm = Instant::now();
        let result = avm.execute(inputs);
        let avm_elapsed = t_avm.elapsed();
        match result {
            Ok(_) => {
                eprintln!("[PROFILE] avm:     {:?} (Accept)", avm_elapsed);
                let ratio = avm_elapsed.as_nanos() as f64 / native_elapsed.as_nanos().max(1) as f64;
                eprintln!("[PROFILE] avm/native ratio: {:.1}x", ratio);
            },
            Err(e) => eprintln!("[PROFILE] avm:     {:?} (Error: {})", avm_elapsed, e),
        }
        total_calls += 1;
        total_elapsed_ns += avm_elapsed.as_nanos();
    }

    eprintln!("\n[PROFILE] === SUMMARY ===");
    eprintln!("[PROFILE] {} calls, total {:?}, avg {:?}",
              total_calls,
              std::time::Duration::from_nanos(total_elapsed_ns as u64),
              std::time::Duration::from_nanos((total_elapsed_ns / total_calls.max(1) as u128) as u64));
}
