//! Convert a raw RISC-V ELF into RISC Zero R0BF (ProgramBinary) format.
//!
//! Usage:
//!   cargo run -p axiom-zk-vm --features verify --bin bake-elf -- <input.elf> <output.r0bf>

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <input-elf> <output-r0bf>", args[0]);
        std::process::exit(1);
    }

    let user_elf = fs::read(&args[1]).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {}", args[1], e);
        std::process::exit(1);
    });

    // Find kernel ELF from risc0-zkos-v1compat (bundled in cargo registry)
    let kernel_elf = find_kernel_elf().unwrap_or_else(|e| {
        eprintln!("Failed to find kernel ELF: {}", e);
        std::process::exit(1);
    });

    let binary = risc0_binfmt::ProgramBinary::new(&user_elf, &kernel_elf);
    let encoded = binary.encode();

    fs::write(&args[2], &encoded).unwrap_or_else(|e| {
        eprintln!("Failed to write {}: {}", args[2], e);
        std::process::exit(1);
    });

    // Also compute and print the image ID
    let image_id = binary.compute_image_id().unwrap_or_else(|e| {
        eprintln!("Failed to compute image-id: {}", e);
        std::process::exit(1);
    });

    println!("Baked: {} ({} bytes) -> {} ({} bytes)",
        args[1], user_elf.len(), args[2], encoded.len());
    println!("Image-ID: {}", hex::encode(image_id.as_bytes()));
}

fn find_kernel_elf() -> Result<Vec<u8>, String> {
    let home = env::var("HOME").map_err(|_| "HOME not set")?;
    let cargo_dir = PathBuf::from(&home).join(".cargo/registry/src");

    // Search for the v1compat kernel ELF
    for entry in fs::read_dir(&cargo_dir).map_err(|e| format!("Cannot read {:?}: {}", cargo_dir, e))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let index_dir = entry.path();
        if !index_dir.is_dir() { continue; }
        // Look inside index dirs for risc0-zkos-v1compat
        for sub in fs::read_dir(&index_dir).map_err(|e| e.to_string())? {
            let sub = sub.map_err(|e| e.to_string())?;
            let name = sub.file_name().to_string_lossy().to_string();
            if name.starts_with("risc0-zkos-v1compat-") {
                let elf_path = sub.path().join("elfs/v1compat.elf");
                if elf_path.exists() {
                    return fs::read(&elf_path)
                        .map_err(|e| format!("Failed to read {:?}: {}", elf_path, e));
                }
            }
        }
    }
    Err("risc0-zkos-v1compat kernel ELF not found in cargo registry".to_string())
}
