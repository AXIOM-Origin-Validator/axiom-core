# axiom-core Implementation Plan

**Version:** 1.0  
**Date:** 2026-01-31  
**Status:** REVIEW BEFORE IMPLEMENTATION

---

## 1. Overview

This document describes the implementation plan for `axiom-core`, which contains:
- **Core.bin** - The validation logic
- **AVM** - AXIOM Virtual Machine (sandbox host)
- **zkVM** - Zero-Knowledge Virtual Machine (proof generation)

All three components work together. Core.bin runs inside zkVM, which runs inside AVM.

---

## 2. Directory Structure

```
axiom-core/
├── Cargo.toml                    # Workspace root
├── config.toml                   # Compile-time configuration
├── README.md
├── IMPLEMENTATION_PLAN.md        # This document
│
├── core/                         # Core.bin - validation logic
│   ├── Cargo.toml                # no_std, zkVM-compatible
│   └── src/
│       ├── lib.rs                # Main entry point
│       ├── types.rs              # Data structures
│       ├── canonical.rs          # Canonical JSON (RFC 8785)
│       ├── crypto.rs             # BLAKE3, SHA3-256, Ed25519, Dilithium
│       ├── validation.rs         # Transaction validation
│       ├── wallet_id.rs          # wallet_id checksum
│       ├── wallet_seq.rs         # wallet_seq enforcement
│       ├── vbc.rs                # VBC verification
│       ├── genesis.rs            # Genesis state handling
│       ├── modes.rs              # CL1, CL2, CL3, CL4 dispatch
│       └── errors.rs             # Error types
│
├── avm/                          # AXIOM Virtual Machine - sandbox host
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── host.rs               # Host runtime
│       ├── sandbox.rs            # Capability enforcement
│       ├── transcript.rs         # Audit logging
│       ├── policy.rs             # Role-based policies
│       └── providers.rs          # Time/random injection
│
├── zkvm-guest/                   # zkVM guest program (Core runs here)
│   ├── Cargo.toml                # RISC Zero guest
│   └── src/
│       └── main.rs               # Guest entry point
│
├── zkvm-host/                    # zkVM host (proof generation/verification)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── prover.rs             # Generate proofs
│       └── verifier.rs           # Verify proofs
│
└── tests/
    ├── canonical_test.rs         # Canonical JSON tests
    ├── crypto_test.rs            # Crypto primitive tests
    ├── wallet_id_test.rs         # wallet_id checksum tests
    ├── wallet_seq_test.rs        # wallet_seq tests
    ├── validation_test.rs        # Full validation tests
    ├── avm_test.rs               # AVM sandbox tests
    ├── zkvm_test.rs              # zkVM proof tests
    └── integration_test.rs       # Full stack: AVM → zkVM → Core
```

---

## 3. Component Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                         AVM HOST                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Sandbox Enforcement                                    │  │
│  │  - No network access                                    │  │
│  │  - No filesystem access                                 │  │
│  │  - No system clock                                      │  │
│  │  - Deterministic execution                              │  │
│  └────────────────────────────────────────────────────────┘  │
│                            │                                  │
│                            ▼                                  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Transcript Logger                                      │  │
│  │  - Records all inputs                                   │  │
│  │  - Records all outputs                                  │  │
│  │  - Enables replay/audit                                 │  │
│  └────────────────────────────────────────────────────────┘  │
│                            │                                  │
│                            ▼                                  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │                    zkVM HOST                            │  │
│  │  ┌──────────────────────────────────────────────────┐  │  │
│  │  │                 zkVM GUEST                        │  │  │
│  │  │  ┌────────────────────────────────────────────┐  │  │  │
│  │  │  │              CORE.BIN                      │  │  │  │
│  │  │  │                                            │  │  │  │
│  │  │  │  - Canonical JSON parsing                  │  │  │  │
│  │  │  │  - Signature verification                  │  │  │  │
│  │  │  │  - Balance checking                        │  │  │  │
│  │  │  │  - wallet_seq enforcement                  │  │  │  │
│  │  │  │  - wallet_id validation                    │  │  │  │
│  │  │  │  - State transitions                       │  │  │  │
│  │  │  │                                            │  │  │  │
│  │  │  └────────────────────────────────────────────┘  │  │  │
│  │  │                                                  │  │  │
│  │  │  Output: PublicOutputs + Proof                   │  │  │
│  │  └──────────────────────────────────────────────────┘  │  │
│  │                                                        │  │
│  │  Proof Verification                                    │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  Output: Verified Result + Transcript                        │
└──────────────────────────────────────────────────────────────┘
```

---

## 4. Implementation Phases

### Phase 1: Project Setup (Day 1)

**Goal:** Cargo workspace compiles, RISC Zero integrated

**Tasks:**
- [ ] Create Cargo.toml workspace
- [ ] Set up `core/` as `no_std` crate
- [ ] Set up RISC Zero zkVM (guest + host)
- [ ] Set up `avm/` crate
- [ ] Verify "hello world" flows through entire stack

**Test:** 
```bash
cd axiom-core
cargo build
# Core compiles for zkVM
# AVM can launch zkVM
# zkVM can run Core
```

---

### Phase 2: Core Data Types (Day 2-3)

**Goal:** All data structures defined, Canonical JSON working

**Files:**
- `core/src/types.rs` - Transaction, Receipt, State, VBC, etc.
- `core/src/canonical.rs` - RFC 8785 JCS encoder/decoder
- `core/src/errors.rs` - Error types

**Key Types:**
```rust
// types.rs

pub struct Transaction {
    pub consumed_state_id: [u8; 32],
    pub client_pk: [u8; 32],
    pub wallet_seq: u64,
    pub receiver_address: String,  // "email/wallet_id"
    pub amount: u64,
    pub reference: String,
    pub nonce: u64,
    pub epoch: u64,
    pub client_sig: Vec<u8>,
}

pub struct PublicInputs {
    pub mode: CoreLogicMode,
    pub transaction: Transaction,
    pub prev_receipts: Vec<Receipt>,
    pub current_state: Option<WalletState>,
    pub vbc_bundle: Option<VBCProofBundle>,
}

pub struct PublicOutputs {
    pub result: ValidationResult,
    pub new_state_hash: Option<[u8; 32]>,
    pub produced_state_id: Option<[u8; 32]>,
    pub new_wallet_seq: Option<u64>,
    pub rejection_reason: Option<ValidationError>,
}

pub enum CoreLogicMode {
    CL1,  // Client Core Out
    CL2,  // Validator Core In
    CL3,  // Validator Core Out
    CL4,  // Client Core In
}

pub enum ValidationResult {
    Accept,
    Reject,
}
```

**Canonical JSON Rules:**
- Keys sorted by Unicode codepoint
- No whitespace
- Integers only (no floats)
- Binary fields: `"b64u:<base64url_no_padding>"`
- NFC normalized strings

**Test:**
```rust
#[test]
fn test_canonical_json_key_order() {
    let json = canonical_encode(&obj);
    // {"a":1,"b":2,"z":3} - sorted
}

#[test]
fn test_canonical_json_binary() {
    // signature field becomes "b64u:..."
}
```

---

### Phase 3: Cryptography (Day 4-5)

**Goal:** All crypto primitives working in zkVM

**Files:**
- `core/src/crypto.rs`

**Functions:**
```rust
// crypto.rs

/// BLAKE3 hash - used for txid, wallet_id checksum
pub fn blake3_hash(data: &[u8]) -> [u8; 32]

/// SHA3-256 hash - used for state_hash, genesis_state_id
pub fn sha3_256_hash(data: &[u8]) -> [u8; 32]

/// CRC32C - used for CB corruption detection
pub fn crc32c(data: &[u8]) -> u32

/// Ed25519 signature verification
pub fn verify_ed25519(
    pk: &[u8; 32], 
    msg: &[u8], 
    sig: &[u8; 64]
) -> bool

/// Dilithium signature verification (for VBCs)
pub fn verify_dilithium(
    pk: &[u8], 
    msg: &[u8], 
    sig: &[u8]
) -> bool
```

**Dependencies (must work in zkVM/no_std):**
```toml
[dependencies]
blake3 = { version = "1.5", default-features = false }
sha3 = { version = "0.10", default-features = false }
ed25519-dalek = { version = "2.0", default-features = false }
pqcrypto-dilithium = { version = "0.5", default-features = false }
```

**Test:**
```rust
#[test]
fn test_blake3_known_vector() {
    let hash = blake3_hash(b"test");
    assert_eq!(hash, EXPECTED_HASH);
}

#[test]
fn test_ed25519_verify() {
    // Known good signature
}
```

---

### Phase 4: wallet_id Validation (Day 6)

**Goal:** wallet_id checksum verification working

**Files:**
- `core/src/wallet_id.rs`

**Functions:**
```rust
// wallet_id.rs

/// Master public key (embedded at compile time)
pub const WALLET_IDENTITY_KEY: [u8; 32] = [...];

/// Parse address into (email, wallet_id)
pub fn parse_address(address: &str) -> Result<(&str, &str), Error>

/// Validate wallet_id checksum
pub fn validate_wallet_id(
    email: &str,
    wallet_id: &str,
    master_pk: &[u8; 32]
) -> Result<(), Error> {
    // wallet_id = checksum (6 hex) + salt (2 hex)
    let checksum = &wallet_id[0..6];
    let salt = &wallet_id[6..8];
    
    // Recompute expected
    let data = format!("{}{}{}", email, hex::encode(master_pk), salt);
    let hash = blake3_hash(data.as_bytes());
    let expected = &hex::encode(&hash[0..3]); // first 6 hex chars
    
    if checksum != expected {
        return Err(Error::InvalidWalletId);
    }
    Ok(())
}
```

**Test:**
```rust
#[test]
fn test_valid_wallet_id() {
    let result = validate_wallet_id(
        "bob@example.com",
        "a3f7b232",
        &WALLET_IDENTITY_KEY
    );
    assert!(result.is_ok());
}

#[test]
fn test_invalid_wallet_id_typo() {
    let result = validate_wallet_id(
        "bob@example.com",
        "a3f7b233",  // wrong checksum
        &WALLET_IDENTITY_KEY
    );
    assert!(result.is_err());
}
```

---

### Phase 5: wallet_seq Enforcement (Day 7)

**Goal:** wallet_seq rules implemented

**Files:**
- `core/src/wallet_seq.rs`

**Rules:**
1. Genesis: wallet_seq = 0
2. First transaction: wallet_seq MUST be 1
3. Each subsequent: prev_wallet_seq + 1
4. Maximum: 2^48

```rust
// wallet_seq.rs

pub const MAX_WALLET_SEQ: u64 = 1 << 48;

pub fn verify_wallet_seq(
    seq: u64,
    prev_seq: u64,
    is_genesis_tx: bool
) -> Result<(), Error> {
    // Check overflow
    if seq >= MAX_WALLET_SEQ {
        return Err(Error::WalletSeqOverflow);
    }
    
    // Genesis transaction must be 1
    if is_genesis_tx {
        if seq != 1 {
            return Err(Error::InvalidWalletSeq);
        }
        return Ok(());
    }
    
    // Sequential increment
    if seq != prev_seq + 1 {
        return Err(Error::InvalidWalletSeq);
    }
    
    Ok(())
}
```

**Test:**
```rust
#[test]
fn test_genesis_wallet_seq() {
    assert!(verify_wallet_seq(1, 0, true).is_ok());
    assert!(verify_wallet_seq(0, 0, true).is_err());
    assert!(verify_wallet_seq(2, 0, true).is_err());
}

#[test]
fn test_sequential_wallet_seq() {
    assert!(verify_wallet_seq(6, 5, false).is_ok());
    assert!(verify_wallet_seq(7, 5, false).is_err());
}

#[test]
fn test_wallet_seq_overflow() {
    assert!(verify_wallet_seq(MAX_WALLET_SEQ, MAX_WALLET_SEQ - 1, false).is_err());
}
```

---

### Phase 6: Core Validation Logic (Day 8-10)

**Goal:** Complete transaction validation

**Files:**
- `core/src/validation.rs`
- `core/src/genesis.rs`

**Validation Order (NORMATIVE):**
```rust
// validation.rs

pub fn validate_transaction(
    inputs: &PublicInputs
) -> Result<PublicOutputs, Error> {
    let tx = &inputs.transaction;
    let state = &inputs.current_state;
    
    // 1. State ID check (FIRST - before epoch)
    verify_state_id_not_consumed(&tx.consumed_state_id)?;
    
    // 2. wallet_seq check
    let is_genesis = is_genesis_transaction(tx);
    let prev_seq = state.map(|s| s.wallet_seq).unwrap_or(0);
    verify_wallet_seq(tx.wallet_seq, prev_seq, is_genesis)?;
    
    // 3. Receiver wallet_id check
    validate_receiver_address(&tx.receiver_address)?;
    
    // 4. Client signature verification
    verify_client_signature(tx)?;
    
    // 5. Balance check
    verify_balance(tx, state)?;
    
    // 6. Conservation law (inputs = outputs)
    verify_conservation(tx)?;
    
    // 7. Compute outputs
    let new_state_hash = compute_new_state_hash(tx)?;
    let produced_state_id = compute_produced_state_id(tx)?;
    
    Ok(PublicOutputs {
        result: ValidationResult::Accept,
        new_state_hash: Some(new_state_hash),
        produced_state_id: Some(produced_state_id),
        new_wallet_seq: Some(tx.wallet_seq),
        rejection_reason: None,
    })
}
```

**Genesis State:**
```rust
// genesis.rs

pub fn compute_genesis_state_id(
    pk: &[u8; 32],
    balance: u64
) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(b"AXIOM_GENESIS");
    data.extend_from_slice(pk);
    data.extend_from_slice(&balance.to_le_bytes());
    sha3_256_hash(&data)
}

pub fn is_genesis_transaction(tx: &Transaction) -> bool {
    // First transaction from a genesis wallet
    // Has genesis_state_id as consumed_state_id
    // prev_receipts is empty
    tx.prev_receipts.is_empty()
}
```

---

### Phase 7: Core Logic Modes (Day 11-12)

**Goal:** CL1, CL2, CL3, CL4 dispatch working

**Files:**
- `core/src/modes.rs`
- `core/src/lib.rs`

```rust
// modes.rs

pub fn execute_core(inputs: PublicInputs) -> PublicOutputs {
    match inputs.mode {
        CoreLogicMode::CL1 => execute_cl1(inputs),
        CoreLogicMode::CL2 => execute_cl2(inputs),
        CoreLogicMode::CL3 => execute_cl3(inputs),
        CoreLogicMode::CL4 => execute_cl4(inputs),
    }
}

/// CL1: Client Core Out - validate outgoing tx
fn execute_cl1(inputs: PublicInputs) -> PublicOutputs {
    // Client validates their own transaction before sending
    validate_transaction(&inputs)
}

/// CL2: Validator Core In - verify incoming proof, validate tx
fn execute_cl2(inputs: PublicInputs) -> PublicOutputs {
    // Verify client's CL1 proof
    // Validate transaction
    // If overlap: prepare for Lambda to refill
    validate_transaction(&inputs)
}

/// CL3: Validator Core Out - verify Lambda's work
fn execute_cl3(inputs: PublicInputs) -> PublicOutputs {
    // Verify Lambda's processing is legal
    // Verify Hash_A == Hash_B (refilled matches original)
    // Produce witness proof
    validate_transaction(&inputs)
}

/// CL4: Client Core In - verify incoming receipt
fn execute_cl4(inputs: PublicInputs) -> PublicOutputs {
    // Verify receipt proofs from validators
    verify_receipt(&inputs)
}
```

---

### Phase 8: AVM Integration (Day 13-14)

**Goal:** AVM sandbox working with zkVM

**Files:**
- `avm/src/host.rs`
- `avm/src/sandbox.rs`
- `avm/src/transcript.rs`

```rust
// avm/src/host.rs

pub struct AvmHost {
    sandbox: Sandbox,
    transcript: TranscriptLogger,
    zkvm_host: ZkvmHost,
}

impl AvmHost {
    pub fn execute(&mut self, inputs: PublicInputs) -> AvmResult {
        // 1. Log inputs to transcript
        self.transcript.log_inputs(&inputs);
        
        // 2. Execute in zkVM (produces proof)
        let zkvm_result = self.zkvm_host.execute(inputs)?;
        
        // 3. Verify proof
        self.zkvm_host.verify(&zkvm_result.proof)?;
        
        // 4. Log outputs to transcript
        self.transcript.log_outputs(&zkvm_result.outputs);
        
        Ok(AvmResult {
            outputs: zkvm_result.outputs,
            proof: zkvm_result.proof,
            transcript: self.transcript.finalize(),
        })
    }
}
```

---

### Phase 9: zkVM Integration (Day 15-16)

**Goal:** RISC Zero proving/verifying

**Files:**
- `zkvm-guest/src/main.rs`
- `zkvm-host/src/prover.rs`
- `zkvm-host/src/verifier.rs`

```rust
// zkvm-guest/src/main.rs
// This runs inside RISC Zero zkVM

#![no_main]
#![no_std]

use risc0_zkvm::guest::env;
use axiom_core::{execute_core, PublicInputs, PublicOutputs};

risc0_zkvm::guest::entry!(main);

fn main() {
    // Read inputs from host
    let inputs: PublicInputs = env::read();
    
    // Execute Core.bin validation
    let outputs: PublicOutputs = execute_core(inputs);
    
    // Commit outputs (becomes part of proof)
    env::commit(&outputs);
}
```

```rust
// zkvm-host/src/prover.rs

use risc0_zkvm::{Prover, Receipt};

pub struct ZkvmHost {
    prover: Prover,
}

impl ZkvmHost {
    pub fn execute(&self, inputs: PublicInputs) -> ZkvmResult {
        // Run guest program, generate proof
        let receipt = self.prover.prove(inputs)?;
        
        let outputs: PublicOutputs = receipt.journal.decode()?;
        
        Ok(ZkvmResult {
            outputs,
            proof: receipt,
        })
    }
}
```

---

### Phase 10: Integration Tests (Day 17-18)

**Goal:** Full stack tested

**Test Cases:**
```rust
// tests/integration_test.rs

#[test]
fn test_full_stack_valid_transaction() {
    let avm = AvmHost::new();
    
    let inputs = PublicInputs {
        mode: CoreLogicMode::CL1,
        transaction: create_valid_transaction(),
        ..
    };
    
    let result = avm.execute(inputs);
    
    assert!(result.is_ok());
    assert_eq!(result.outputs.result, ValidationResult::Accept);
    assert!(result.proof.is_valid());
}

#[test]
fn test_full_stack_invalid_wallet_seq() {
    // wallet_seq = 5, but prev was 3 (should be 4)
    // Should reject
}

#[test]
fn test_full_stack_invalid_wallet_id() {
    // Typo in receiver address
    // Should reject
}

#[test]
fn test_full_stack_insufficient_balance() {
    // Trying to spend more than available
    // Should reject
}

#[test]
fn test_cl1_to_cl4_flow() {
    // Full transaction lifecycle
    // CL1 -> CL2 -> (Lambda) -> CL3 -> CL4
}
```

---

## 5. Dependencies

```toml
# core/Cargo.toml
[package]
name = "axiom-core"
version = "2.0.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[features]
default = ["std"]
std = []

[dependencies]
blake3 = { version = "1.5", default-features = false }
sha3 = { version = "0.10", default-features = false }
ed25519-dalek = { version = "2.0", default-features = false, features = ["alloc"] }
pqcrypto-dilithium = { version = "0.5", default-features = false }
serde = { version = "1.0", default-features = false, features = ["derive", "alloc"] }
serde_json = { version = "1.0", default-features = false, features = ["alloc"] }
base64 = { version = "0.21", default-features = false, features = ["alloc"] }
hex = { version = "0.4", default-features = false, features = ["alloc"] }
```

```toml
# zkvm-guest/Cargo.toml
[package]
name = "axiom-zkvm-guest"
version = "2.0.0"
edition = "2021"

[dependencies]
axiom-core = { path = "../core", default-features = false }
risc0-zkvm = { version = "1.0", default-features = false }
```

---

## 6. Compile-Time Configuration

```toml
# axiom-core/config.toml

[genesis]
# Master public key for wallet_id checksum
master_public_key = "b64u:..."

# Genesis validators (Dilithium public keys)
genesis_validators = [
    "b64u:...",
    "b64u:...",
    "b64u:...",
]

[limits]
max_wallet_seq = 281474976710656  # 2^48
max_transaction_size = 65536      # 64 KB
max_reference_length = 256

[crypto]
# Supported signature algorithms
algorithms = ["ed25519", "dilithium"]
```

---

## 7. Success Criteria

Before moving to Lambda development:

- [ ] All tests pass
- [ ] Full stack (AVM → zkVM → Core) produces valid proofs
- [ ] Canonical JSON matches test vectors
- [ ] wallet_id validation works
- [ ] wallet_seq enforcement works
- [ ] CL1-CL4 modes work
- [ ] No panics, all errors handled
- [ ] Code compiles with `no_std` for zkVM

---

## 8. Open Questions

1. **RISC Zero version:** Which version to use? (recommend latest stable)

2. **Dilithium in zkVM:** Does pqcrypto-dilithium work in RISC Zero? Need to verify.

3. **Transcript format:** JSON? Binary? (recommend Canonical JSON for consistency)

4. **AVM sandbox mechanism:** For development, can be permissive. For production, need proper sandboxing.

---

## 9. Next Steps

**After your review:**

1. Approve or request changes to this plan
2. I implement Phase 1 (project setup)
3. Show you working "hello world" through full stack
4. Continue phase by phase

---

**Please review this plan before I start implementation.**
