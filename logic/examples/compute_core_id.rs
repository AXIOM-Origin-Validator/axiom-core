/// Compute CoreID (BLAKE3 hash) of an ELF file.
/// Usage: cargo run --example compute_core_id -- path/to/axiom-core.elf
fn main() {
    let path = std::env::args().nth(1).expect("Usage: compute_core_id <elf-path>");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        eprintln!("Cannot read {}: {}", path, e);
        std::process::exit(1);
    });
    let hash = blake3::hash(&bytes);
    print!("{}", hash.to_hex());
}
