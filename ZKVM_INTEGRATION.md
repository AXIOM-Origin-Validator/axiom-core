# AXIOM zkVM Integration

This document describes the RISC Zero zkVM integration for AXIOM axiom-core.elf.

## Architecture

```
axiom-core/
├── core/               # Core validation logic (no_std compatible)
├── zkvm-methods/       # RISC Zero methods crate (built separately)
│   ├── guest/          # Guest program (runs in zkVM)
│   │   └── src/main.rs # Entry point for zkVM execution
│   ├── build.rs        # Builds guest ELF via risc0-build
│   └── src/lib.rs      # Exports ELF and IMAGE_ID
├── zkvm-host/          # Host prover/verifier
│   ├── config.rs       # Configuration for ELF/IMAGE_ID paths
│   ├── prover.rs       # Generates proofs
│   └── verifier.rs     # Verifies proofs
└── avm/                # AVM sandbox (orchestration)
```

## Configuration

zkVM artifacts (ELF and IMAGE_ID) are loaded from disk at runtime, not compiled in.
This allows the main workspace to build without RISC Zero toolchain.

### Default Paths

```
~/.axiom/zkvm/
├── axiom-core.elf    # Compiled guest ELF binary
├── image-id.hex    # IMAGE_ID (32 bytes, hex encoded)
└── README.md       # Setup instructions
```

### Environment Variables

Override default paths with:

```bash
export AXIOM_ZKVM_ELF=/path/to/axiom-core.elf
export AXIOM_ZKVM_IMAGE_ID=/path/to/image-id.hex
```

### Programmatic Configuration

```rust
use axiom_zkvm_host::{ZkvmProver, ZkvmConfig};

// Use default paths (~/.axiom/zkvm/)
let prover = ZkvmProver::new();

// Use custom paths
let config = ZkvmConfig::new(
    "/custom/path/axiom-core.elf",
    "/custom/path/image-id.hex"
);
let prover = ZkvmProver::with_config(config);

// Check status
println!("{}", prover.config_status());
```

## How It Works

### Guest (Inside zkVM)

The guest program runs inside the RISC Zero zkVM and:
1. Reads `CoreLogicMode` and `PublicInputs` from the host
2. Executes Core.bin validation logic
3. Commits `PublicOutputs` to the journal

```rust
// zkvm-methods/guest/src/main.rs
use risc0_zkvm::guest::env;
use axiom_core::{PublicInputs, PublicOutputs, CoreLogicMode};

fn main() {
    let mode: CoreLogicMode = env::read();
    let inputs: PublicInputs = env::read();
    let outputs = execute_core_logic(mode, inputs)?;
    env::commit(&outputs);
}
```

### Host (Outside zkVM)

The host runs on the validator and:
1. Prepares inputs for the guest
2. Executes the guest in the zkVM
3. Generates a cryptographic proof (receipt)
4. Verifies receipts from other validators

```rust
// zkvm-host/prover.rs
use risc0_zkvm::{default_prover, ExecutorEnv};

let env = ExecutorEnv::builder()
    .write(&mode)?
    .write(&inputs)?
    .build()?;

let receipt = default_prover().prove(env, CORE_BIN_ELF)?.receipt;
let outputs: PublicOutputs = receipt.journal.decode()?;
```

## Production Mode (No Dev Mode)

As of v2.10.31, all dev-mode fallbacks have been removed. Only real RISC Zero STARK proofs are generated.

- Full RISC Zero proving (always)
- Requires `prove` feature
- Requires 16GB+ RAM for local proving

```rust
let prover = ZkvmProver::production()?;
let (outputs, receipt) = prover.prove(inputs)?;
```

```bash
# Build with proving support
cargo build --features prove
```

## Building the Guest

The guest program is built separately from the main workspace using `risc0-build`.

### Prerequisites

1. Install RISC Zero toolchain:
```bash
curl -L https://risczero.com/install | bash
rzup install
```

2. Install the RISC-V target:
```bash
rustup target add riscv32im-unknown-none-elf
```

### Building

```bash
# Navigate to zkvm-methods (outside main workspace)
cd axiom-core/zkvm-methods
cargo build --release
```

This generates:
- `target/riscv-guest/riscv32im-risc0-zkvm-elf/release/axiom-core-guest` - The ELF
- IMAGE_ID is printed during build

### Installing Artifacts

```bash
# Create the config directory
mkdir -p ~/.axiom/zkvm

# Copy the ELF
cp target/riscv-guest/riscv32im-risc0-zkvm-elf/release/axiom-core-guest \
   ~/.axiom/zkvm/axiom-core.elf

# Save the IMAGE_ID (replace with actual ID from build output)
echo "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" \
   > ~/.axiom/zkvm/image-id.hex
```

Or use a symlink for development:
```bash
ln -s /path/to/zkvm-methods/target/riscv-guest/.../axiom-core-guest \
      ~/.axiom/zkvm/axiom-core.elf
```

## IMAGE_ID Security

The IMAGE_ID is a cryptographic hash of the guest program. All validators MUST use the same IMAGE_ID to ensure they're running identical Core.bin logic.

```rust
// Validators verify receipts against expected IMAGE_ID
verifier.verify(&receipt)?;  // Checks IMAGE_ID matches
```

If a validator uses a modified Core.bin, their receipts will have a different IMAGE_ID and be rejected by other validators.

## Testing

### Unit Tests

```bash
# Test core logic
cargo test -p axiom-core

# Test host prover/verifier (dev mode)
cargo test -p axiom-zk-vm
```

### Integration Tests

```bash
# Test with real proving (slow, requires resources)
cargo test -p axiom-zk-vm --features prove
```

## Resource Requirements

| Mode | RAM | Time (simple tx) |
|------|-----|------------------|
| Dev | 1GB | <100ms |
| Production (local) | 16GB+ | 30-60s |
| Production (Boundless) | - | 5-10s |

## Future Work

1. **Boundless Integration** - Use RISC Zero's Boundless for remote proving
2. **Recursion** - Aggregate multiple proofs into one
3. **GPU Acceleration** - Use CUDA/Metal for faster proving
4. **Groth16 Snark** - Convert STARK proofs to compact Groth16
