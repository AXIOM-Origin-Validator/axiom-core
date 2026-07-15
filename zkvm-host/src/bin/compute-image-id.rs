//! Compute RISC Zero image-id from a raw ELF or R0BF binary.
//!
//! Usage:
//!   cargo run -p axiom-zk-vm --features verify --bin compute-image-id -- <path-to-elf>

use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <path-to-elf>", args[0]);
        std::process::exit(1);
    }

    let path = &args[1];
    let blob = fs::read(path).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {}", path, e);
        std::process::exit(1);
    });

    println!("File: {} ({} bytes)", path, blob.len());
    println!("Magic: {:?}", std::str::from_utf8(&blob[..4]).unwrap_or("???"));

    // Try R0BF format first, then raw ELF
    let image_id = risc0_binfmt::compute_image_id(&blob).unwrap_or_else(|_| {
        // Raw ELF: load as Program, build MemoryImage, get digest
        let program = risc0_binfmt::Program::load_elf(&blob, risc0_binfmt::KERNEL_START_ADDR.0)
            .unwrap_or_else(|e| {
                eprintln!("Failed to load ELF: {}", e);
                std::process::exit(1);
            });
        let mut image = risc0_binfmt::MemoryImage::new_kernel(program);
        image.image_id()
    });

    let hex_str = hex::encode(image_id.as_bytes());
    println!("Image-ID: {}", hex_str);
}
