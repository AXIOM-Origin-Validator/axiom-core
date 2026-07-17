//! Build script for axiom-zkvm-methods
//!
//! This script uses risc0-build to compile the guest program
//! into a RISC-V ELF binary and generate Rust code that embeds it.

fn main() {
    // Build the guest program and generate the methods
    risc0_build::embed_methods();
}
