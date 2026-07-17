# AXIOM Core Architecture

## The Correct Model

```
┌─────────────────────────────────────────────────────────────┐
│  zkVM (proof wrapper - RISC Zero)                           │
│  - Proves execution happened                                │
│  - Generates ZK proof                                       │
│  - We trust this (like we trust SHA-256)                    │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  AVM (actual VM - eBPF interpreter)                   │  │
│  │  - Interprets eBPF bytecode                           │  │
│  │  - Executes core.bin                                  │  │
│  │  - Can be rebuilt for any platform                    │  │
│  │                                                       │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │  core.bin (eBPF bytecode)                       │  │  │
│  │  │  - The actual validation logic                  │  │  │
│  │  │  - NEVER changes                                │  │  │
│  │  │  - ONE fingerprint forever                      │  │  │
│  │  │  - Contains RISC0_FINGERPRINT for verification  │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Key Principles

### 1. core.bin is IMMUTABLE
- Fixed bytecode binary
- ONE fingerprint forever
- Contains hardcoded RISC0_FINGERPRINT to verify zkVM
- If logic changes → new core.bin → new worldline

### 2. AVM is PORTABLE
- eBPF interpreter
- Can be rebuilt for any platform
- Can be reimplemented in any language
- Simple bytecode format (~100 opcodes)

### 3. zkVM is for PROOFS
- Not a real VM - a proof wrapper
- Proves AVM executed core.bin correctly
- We trust it like we trust cryptographic primitives
- core.bin verifies RISC0_FINGERPRINT to detect corruption

### 4. Portability Model
```
Platform X              Platform Y
──────────────────      ──────────────────
zkVM (x86)              zkVM (ARM)         ← Rebuild
AVM (in zkVM guest)     AVM (in zkVM guest)← Same code, recompiled
core.bin (eBPF)         core.bin (eBPF)    ← SAME BINARY

IMAGE_ID = hash(zkVM guest) = hash(AVM + core.bin)
```

If same zkVM version + same AVM + same core.bin → same IMAGE_ID

## Project Structure

```
axiom-core/
│
├── core-logic/                 # Validation logic source
│   ├── src/
│   │   ├── lib.rs              # Main logic
│   │   ├── validation.rs       # Transaction validation
│   │   ├── crypto.rs           # Signature verification  
│   │   ├── types.rs            # Data structures
│   │   └── ...
│   ├── Cargo.toml
│   └── build.rs                # Compiles to eBPF bytecode
│
├── core.bin                    # OUTPUT: eBPF bytecode artifact
│                               # This is THE immutable artifact
│
├── avm/                        # eBPF interpreter
│   ├── src/
│   │   ├── lib.rs
│   │   ├── interpreter.rs      # eBPF VM implementation
│   │   ├── memory.rs           # VM memory model
│   │   └── helpers.rs          # Host functions (crypto, etc.)
│   └── Cargo.toml
│
├── zkvm-guest/                 # RISC Zero guest program
│   ├── src/
│   │   └── main.rs             # Entry: load core.bin, run AVM
│   ├── Cargo.toml
│   └── core.bin                # Embedded copy of core.bin
│
├── zkvm-host/                  # RISC Zero host (prover/verifier)
│   ├── src/
│   │   ├── lib.rs
│   │   ├── prover.rs
│   │   └── verifier.rs
│   └── Cargo.toml
│
└── artifacts/                  # Published artifacts
    ├── core.bin                # eBPF bytecode (for audit)
    ├── guest.elf               # zkVM guest (for validators)
    └── IMAGE_ID                # Canonical fingerprint
```

## Build Process

```
Step 1: Get RISC Zero fingerprint
────────────────────────────────
- Download RISC Zero v1.2.0 (pinned version)
- Verify hash matches published fingerprint
- RISC0_FINGERPRINT = 0xabc123...

Step 2: Build core.bin (eBPF bytecode)
────────────────────────────────
- Write validation logic in Rust
- Hardcode RISC0_FINGERPRINT in the logic
- Compile to eBPF bytecode
- Output: core.bin
- CORE_FINGERPRINT = hash(core.bin) = 0xdef456...

Step 3: Build AVM (eBPF interpreter)
────────────────────────────────
- eBPF interpreter in Rust (no_std)
- Uses rbpf or custom implementation
- Embeds core.bin bytecode

Step 4: Build zkVM Guest
────────────────────────────────
- Contains AVM + embedded core.bin
- Compile to RISC-V ELF
- IMAGE_ID = hash(guest ELF)

Step 5: Publish artifacts
────────────────────────────────
- core.bin (for audit/portability)
- guest.elf (for validators)
- IMAGE_ID (for verification)
```

## Runtime Flow

```
1. Validator receives transaction

2. zkVM Host loads guest.elf
   - Verifies IMAGE_ID matches canonical

3. zkVM executes guest:
   a. Guest loads core.bin (embedded)
   b. Guest creates AVM (eBPF interpreter)
   c. AVM verifies RISC0_FINGERPRINT
   d. AVM executes core.bin with transaction
   e. core.bin returns Accept/Reject
   f. Guest commits result

4. zkVM produces proof:
   - proof.image_id = IMAGE_ID
   - proof.result = Accept/Reject
   - proof.zkp_data = cryptographic proof

5. Verifier checks:
   - proof.image_id == CANONICAL_IMAGE_ID?
   - proof.zkp_data valid?
   - Accept proof
```

## Verification

```rust
// In verifier
const CANONICAL_IMAGE_ID: [u8; 32] = [0x...];

fn verify_proof(proof: &Proof) -> bool {
    // 1. Check IMAGE_ID matches canonical
    if proof.image_id != CANONICAL_IMAGE_ID {
        return false;
    }
    
    // 2. Verify ZK proof cryptographically
    if !risc0_verify(proof) {
        return false;
    }
    
    true
}
```

```rust
// Inside core.bin (eBPF)
const RISC0_FINGERPRINT: [u8; 32] = [0x...];

fn verify_runtime(actual_fingerprint: &[u8; 32]) -> bool {
    actual_fingerprint == &RISC0_FINGERPRINT
}
```

## Security Model

| Threat | Protection |
|--------|------------|
| Corrupted RISC Zero library | core.bin checks RISC0_FINGERPRINT |
| Modified core.bin | IMAGE_ID changes, proofs rejected |
| Modified AVM | IMAGE_ID changes, proofs rejected |
| Bypassed execution | zkVM proof required, can't fake |
| Different worldline | Different IMAGE_ID, can't mix |

## 30-Year Portability

```
Today (2026):
- RISC Zero v1.2.0
- AVM v1.0 (eBPF interpreter)
- core.bin (eBPF bytecode)

In 30 years (2056):
- RISC Zero is dead
- New zkVM exists (e.g., "FutureProof")
- Rebuild AVM for FutureProof
- core.bin (eBPF) UNCHANGED
- New IMAGE_ID (because new zkVM)
- New worldline, but same logic

Audit process:
1. Verify old core.bin hash matches historical record
2. Verify new AVM correctly interprets eBPF
3. New worldline inherits trust from old logic
```

## eBPF Choice Rationale

Why eBPF over other bytecode formats:

| Format | Pros | Cons |
|--------|------|------|
| **eBPF** | Simple (~100 ops), well-documented, Linux kernel uses it | Less common outside Linux |
| WASM | Very common, browsers support | More complex, larger spec |
| RISC-V | Open standard, growing adoption | More complex than eBPF |
| Custom | Full control | No ecosystem, harder to audit |

eBPF wins because:
1. Simplest to reimplement
2. Well-documented specification
3. Easy to audit
4. Linux kernel dependency ensures long-term documentation
