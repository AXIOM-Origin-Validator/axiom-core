# axiom-core Test Documentation

**Version:** 2.0.0  
**Last Updated:** 2026-01-31

This document describes all tests in axiom-core and what they verify.

---

## Overview

```
axiom-core/
├── core/src/           # 28 tests
│   ├── canonical.rs    # 6 tests - CB framing and binary encoding
│   ├── crypto.rs       # 4 tests - Hash and signature verification
│   ├── wallet_id.rs    # 6 tests - Address checksum validation
│   ├── wallet_seq.rs   # 7 tests - Sequence number enforcement
│   ├── genesis.rs      # 3 tests - Genesis state handling
│   ├── validation.rs   # 3 tests - Transaction validation
│   └── modes.rs        # 2 tests - CL1-CL4 mode dispatch
├── avm/src/            # 7 tests
│   ├── host.rs         # 2 tests - AVM execution
│   ├── sandbox.rs      # 4 tests - Sandbox enforcement
│   └── transcript.rs   # 3 tests - Audit logging
└── zkvm-host/src/      # 6 tests
    ├── lib.rs          # 1 test  - Receipt serialization
    ├── prover.rs       # 2 tests - Proof generation
    └── verifier.rs     # 4 tests - Proof verification
```

**Total: 41 tests**

---

## core/src/canonical.rs - Canonical Bytes Tests

### test_varint_encoding
**Purpose:** Verify LEB128 varint encoding produces correct bytes.

**Test Cases:**
- Single byte values: 0, 1, 127
- Two byte values: 128, 255
- Larger values: 300

**Expected:** Each value encodes to the correct byte sequence per LEB128 spec.

---

### test_varint_roundtrip
**Purpose:** Verify varint encode/decode is lossless.

**Test Cases:** 0, 1, 127, 128, 255, 256, 1000, 10000, u64::MAX

**Expected:** `decode(encode(x)) == x` for all test values.

---

### test_canonical_bytes_roundtrip
**Purpose:** Verify CB framing encode/decode is lossless.

**Test Cases:** Payload "Hello, AXIOM!"

**Expected:** `decode(encode(payload)) == payload`

---

### test_canonical_bytes_magic
**Purpose:** Verify CB framing starts with correct magic bytes.

**Test Cases:** Any payload

**Expected:** First 4 bytes are `LAMB` (0x4C 0x41 0x4D 0x42)

---

### test_canonical_bytes_crc_validation
**Purpose:** Verify CB framing detects corruption via CRC32C.

**Test Cases:** Valid CB with one byte corrupted

**Expected:** Decode fails with `InvalidCanonicalJson` error.

---

### test_binary_encoding
**Purpose:** Verify b64u prefix encoding/decoding.

**Test Cases:** Binary data [0x00, 0x01, 0x02, 0xFF]

**Expected:** 
- Encoded string starts with "b64u:"
- `decode(encode(data)) == data`

---

### test_binary_encoding_no_prefix
**Purpose:** Verify decoding fails without b64u prefix.

**Test Cases:** String "not_valid" (no b64u: prefix)

**Expected:** Returns error.

---

## core/src/crypto.rs - Cryptography Tests

### test_blake3_known_vector
**Purpose:** Verify BLAKE3 produces 32-byte output.

**Test Cases:** Input "AXIOM"

**Expected:** Output is exactly 32 bytes.

---

### test_sha3_256_known_vector
**Purpose:** Verify SHA3-256 produces 32-byte output.

**Test Cases:** Input "AXIOM"

**Expected:** Output is exactly 32 bytes.

---

### test_crc32c
**Purpose:** Verify CRC32C is consistent and sensitive to changes.

**Test Cases:** 
- "LAMB" (same input twice)
- "LAMBB" (different input)

**Expected:**
- Same input produces same CRC
- Different input produces different CRC

---

### test_algorithm_detection
**Purpose:** Verify signature algorithm detection from public key length.

**Test Cases:**
- 32 bytes → Ed25519
- 1952 bytes → Dilithium (ML-DSA-65)
- 100 bytes → Unknown

**Expected:** Correct algorithm detected or None for unknown.

---

## core/src/wallet_id.rs - Wallet ID Tests

### test_parse_address_valid
**Purpose:** Verify valid address parsing.

**Test Cases:** "bob@example.com/a3f7b232"

**Expected:** 
- email = "bob@example.com"
- wallet_id = "a3f7b232"

---

### test_parse_address_with_dashes
**Purpose:** Verify dashes in wallet_id are handled.

**Test Cases:** "bob@example.com/a3f-7b2-32"

**Expected:** Parses successfully (dashes stripped).

---

### test_parse_address_no_slash
**Purpose:** Verify missing slash is rejected.

**Test Cases:** "bob@example.com" (no slash)

**Expected:** Returns `MalformedAddress` error.

---

### test_parse_address_no_at
**Purpose:** Verify missing @ in email is rejected.

**Test Cases:** "bobexample.com/a3f7b232"

**Expected:** Returns `MalformedAddress` error.

---

### test_parse_address_wrong_length
**Purpose:** Verify wallet_id length is enforced.

**Test Cases:** "bob@example.com/a3f7b2" (only 6 chars)

**Expected:** Returns `MalformedAddress` error.

---

### test_generate_and_validate
**Purpose:** Verify generated wallet_id validates correctly.

**Test Cases:** 
- Generate wallet_id for "alice@test.com" with salt "42"
- Validate the generated address

**Expected:** Validation passes.

---

### test_invalid_checksum
**Purpose:** Verify corrupted checksum is detected.

**Test Cases:**
- Generate valid wallet_id
- Corrupt one character
- Validate

**Expected:** Returns `InvalidWalletId` error.

---

### test_different_salt_different_checksum
**Purpose:** Verify different salts produce different checksums.

**Test Cases:**
- Generate wallet_id with salt "00"
- Generate wallet_id with salt "01"

**Expected:** Checksums differ.

---

## core/src/wallet_seq.rs - Wallet Sequence Tests

### test_genesis_transaction
**Purpose:** Verify genesis transaction requires wallet_seq = 1.

**Test Cases:** wallet_seq=1, prev_seq=0, is_genesis=true

**Expected:** Validation passes.

---

### test_genesis_wrong_seq
**Purpose:** Verify genesis with wrong seq fails.

**Test Cases:**
- wallet_seq=0, is_genesis=true → Fail
- wallet_seq=2, is_genesis=true → Fail

**Expected:** Returns `InvalidWalletSeq` error.

---

### test_genesis_wrong_prev
**Purpose:** Verify genesis with prev_seq != 0 fails.

**Test Cases:** wallet_seq=1, prev_seq=1, is_genesis=true

**Expected:** Returns `InvalidWalletSeq` error.

---

### test_sequential_increment
**Purpose:** Verify normal transactions increment by exactly 1.

**Test Cases:**
- wallet_seq=2, prev_seq=1 → Pass
- wallet_seq=100, prev_seq=99 → Pass
- wallet_seq=1000000, prev_seq=999999 → Pass

**Expected:** All pass.

---

### test_sequential_wrong
**Purpose:** Verify non-sequential values are rejected.

**Test Cases:**
- wallet_seq=3, prev_seq=1 (skip) → Fail
- wallet_seq=1, prev_seq=2 (backward) → Fail
- wallet_seq=5, prev_seq=5 (same) → Fail

**Expected:** Returns `InvalidWalletSeq` error.

---

### test_overflow_protection
**Purpose:** Verify MAX_WALLET_SEQ is enforced.

**Test Cases:**
- wallet_seq=MAX_WALLET_SEQ → Fail
- wallet_seq=MAX_WALLET_SEQ+1 → Fail

**Expected:** Returns `WalletSeqOverflow` error.

---

### test_one_before_max
**Purpose:** Verify MAX-1 is still valid.

**Test Cases:** wallet_seq=MAX-1, prev_seq=MAX-2

**Expected:** Validation passes.

---

### test_approaching_overflow
**Purpose:** Verify overflow warning detection.

**Test Cases:**
- 0 → Not approaching
- 1,000,000 → Not approaching
- MAX-1 → Approaching
- MAX-999,999,999 → Approaching

**Expected:** Correct boolean for each.

---

### test_next_wallet_seq
**Purpose:** Verify next_wallet_seq computation.

**Test Cases:**
- 0 → Some(1)
- 100 → Some(101)
- MAX-2 → Some(MAX-1)
- MAX-1 → None
- MAX → None

**Expected:** Correct Option for each.

---

## core/src/genesis.rs - Genesis Tests

### test_compute_genesis_state_id
**Purpose:** Verify genesis_state_id computation.

**Test Cases:**
- Same pk + balance → Same state_id
- Same pk + different balance → Different state_id
- Different pk + same balance → Different state_id

**Expected:** Deterministic and collision-resistant.

---

### test_create_genesis_wallet
**Purpose:** Verify GenesisWallet creation.

**Test Cases:** pk=[0x42; 32], balance=1_000_000_000_000

**Expected:**
- wallet.public_key == pk
- wallet.balance == balance
- wallet.wallet_seq == 0
- wallet.genesis_state_id == computed value

---

### test_is_genesis_validator
**Purpose:** Verify genesis validator detection.

**Test Cases:**
- GENESIS_VALIDATORS[0,1,2] → true
- [0xFF; 32] → false
- [0x01; 16] (wrong length) → false

**Expected:** Correct boolean for each.

---

## core/src/validation.rs - Transaction Validation Tests

### test_validation_accepts_valid_genesis
**Purpose:** Verify valid genesis transaction structure is accepted.

**Note:** Will reject due to invalid test signature, but tests validation flow.

**Test Cases:** Genesis transaction with wallet_seq=1, balance=10000

**Expected:** Reaches signature check (validation structure works).

---

### test_validation_rejects_missing_prev_receipts
**Purpose:** Verify non-genesis without prev_receipts is rejected.

**Test Cases:** 
- wallet_seq=5 (not genesis)
- prev_receipts=empty
- current_state with wallet_seq=4

**Expected:** Returns `MissingPrevReceipts` error.

---

### test_validation_rejects_insufficient_balance
**Purpose:** Verify balance check works.

**Test Cases:**
- amount=100,000
- balance=1,000

**Expected:** Rejects (may hit signature first with test data).

---

## core/src/modes.rs - Core Logic Mode Tests

### test_mode_dispatch
**Purpose:** Verify all modes dispatch without panic.

**Test Cases:** CL1, CL2, CL3, CL4 modes

**Expected:** All return a result (accept or reject).

---

### test_cl4_minimum_witnesses
**Purpose:** Verify CL4 enforces minimum witness count.

**Test Cases:** Receipt with 0 witnesses (less than k=3)

**Expected:** Returns `InvalidVBCCount` error.

---

## avm/src/host.rs - AVM Host Tests

### test_avm_execution
**Purpose:** Verify AVM can execute Core.bin.

**Test Cases:** Valid test inputs

**Expected:** Execution completes without error.

---

### test_avm_produces_transcript
**Purpose:** Verify AVM produces non-empty transcript.

**Test Cases:** Any execution

**Expected:** `result.transcript` is not empty.

---

## avm/src/sandbox.rs - Sandbox Tests

### test_sandbox_active_by_default
**Purpose:** Verify sandbox starts active.

**Test Cases:** New Sandbox

**Expected:** `verify()` passes.

---

### test_sandbox_time_injection
**Purpose:** Verify time must be injected.

**Test Cases:**
- Without injection → Error
- After injection → Returns injected value

**Expected:** Correct behavior for each.

---

### test_sandbox_random_injection
**Purpose:** Verify randomness must be injected.

**Test Cases:**
- Without injection → Error
- After injection → Returns injected value

**Expected:** Correct behavior for each.

---

### test_strict_policy
**Purpose:** Verify strict sandbox policy.

**Test Cases:** SandboxPolicy::Strict

**Expected:** All capabilities denied:
- allow_network = false
- allow_filesystem = false
- allow_clock = false
- allow_random = false
- allow_process = false

---

## avm/src/transcript.rs - Transcript Tests

### test_transcript_logging
**Purpose:** Verify inputs/outputs are logged.

**Test Cases:** Log inputs and outputs

**Expected:** 
- 2 entries logged
- Finalized transcript is not empty

---

### test_transcript_replay
**Purpose:** Verify transcript can be replayed for verification.

**Test Cases:** 
- Log execution
- Replay and verify

**Expected:** Replay produces same outputs.

---

### test_transcript_markers
**Purpose:** Verify markers can be added.

**Test Cases:** Add "START" and "END" markers

**Expected:** 2 entries logged.

---

## zkvm-host/src/lib.rs - Receipt Tests

### test_receipt_roundtrip
**Purpose:** Verify receipt serialization is lossless.

**Test Cases:** Receipt with journal, seal, program_digest

**Expected:** `from_bytes(to_bytes(receipt))` matches original.

---

## zkvm-host/src/prover.rs - Prover Tests

### test_dev_mode_proving
**Purpose:** Verify dev mode produces valid receipts.

**Test Cases:** Prove with test inputs

**Expected:**
- Receipt has correct program_digest
- Journal is not empty
- Seal is "DEV_MODE_SEAL"

---

### test_production_mode_not_implemented
**Purpose:** Verify production mode fails gracefully.

**Test Cases:** Enable production mode, attempt prove

**Expected:** Returns error (not yet implemented).

---

## zkvm-host/src/verifier.rs - Verifier Tests

### test_verify_dev_mode
**Purpose:** Verify dev mode receipts can be verified.

**Test Cases:** 
- Prove with prover
- Verify with verifier

**Expected:** Outputs match.

---

### test_verify_wrong_digest
**Purpose:** Verify wrong program_digest is detected.

**Test Cases:** Receipt with wrong program_digest

**Expected:** Returns `ProgramDigestMismatch` error.

---

### test_verify_wrong_seal
**Purpose:** Verify wrong seal is detected.

**Test Cases:** Receipt with wrong seal (not "DEV_MODE_SEAL")

**Expected:** Returns `VerificationFailed` error.

---

### test_production_mode_not_implemented
**Purpose:** Verify production verification fails gracefully.

**Test Cases:** Enable production mode, attempt verify

**Expected:** Returns error (not yet implemented).

---

## Running Tests

```bash
# Run all tests
cargo test

# Run specific crate tests
cargo test -p axiom-core
cargo test -p axiom-dmap-vm
cargo test -p axiom-zk-vm

# Run specific test
cargo test test_wallet_seq

# Run with output
cargo test -- --nocapture

# Run ignored tests (if any)
cargo test -- --ignored
```

---

## Test Coverage Summary

| Module | Tests | Coverage Focus |
|--------|-------|----------------|
| canonical.rs | 7 | CB framing, binary encoding |
| crypto.rs | 4 | Hash functions, algorithm detection |
| wallet_id.rs | 8 | Address parsing, checksum validation |
| wallet_seq.rs | 8 | Sequence rules, overflow protection |
| genesis.rs | 3 | State ID computation, validator detection |
| validation.rs | 3 | Transaction validation flow |
| modes.rs | 2 | Mode dispatch, witness checks |
| host.rs | 2 | AVM execution |
| sandbox.rs | 4 | Capability enforcement |
| transcript.rs | 3 | Audit logging, replay |
| lib.rs (zkvm) | 1 | Receipt serialization |
| prover.rs | 2 | Proof generation |
| verifier.rs | 4 | Proof verification |

**Total: 51 tests** (includes additional test cases within test functions)

---

## Adding New Tests

When adding tests, follow this pattern:

```rust
#[test]
fn test_<module>_<what_it_tests>() {
    // Setup
    let input = create_test_data();
    
    // Execute
    let result = function_under_test(input);
    
    // Assert
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), expected_value);
}
```

Document new tests in this file with:
- Purpose
- Test cases
- Expected results
