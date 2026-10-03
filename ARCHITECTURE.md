# AXIOM Core Architecture

> Historical note: an earlier revision of this file described an eBPF-based
> core (`core.bin` bytecode + eBPF interpreter). That design was superseded;
> the shipped core is an RV32IM RISC-V ELF. `artifacts/core.bin` is a dead
> placeholder file from that era, not a build product.

## The Correct Model

```
┌──────────────────────────────┐   ┌──────────────────────────────────┐
│  DMAP-VM (axiom-dmap-vm)     │   │  zk-VM (axiom-zk-vm)             │
│  core/avm — PRODUCTION path  │   │  core/zkvm-host — proof wrapper  │
│  - RV32IM interpreter        │   │  - Wraps RISC Zero (risc0)       │
│  - Cranelift JIT (perf layer │   │  - Runs the zkvm-guest build     │
│    only, NOT attestation)    │   │  - Guest = MINIMAL CL3 ZK        │
│  - Emits DMAP attestation    │   │    CHECKPOINT, a strict subset   │
│    from the execution trace  │   │  - Not on any production hot     │
│                              │   │    path today                    │
│  ┌────────────────────────┐  │   │  ┌────────────────────────────┐  │
│  │ axiom-core.elf (RV32IM)│  │   │  │ zkvm-guest ELF (risc0)     │  │
│  │ - core/logic compiled  │  │   │  │ - core/logic compiled for  │  │
│  │   by core/avm-guest    │  │   │  │   the risc0 target         │  │
│  │ - CoreID = BLAKE3 of   │  │   │  │ - IMAGE_ID = risc0 image   │  │
│  │   the committed ELF    │  │   │  │   id of this guest         │  │
│  └────────────────────────┘  │   │  └────────────────────────────┘  │
└──────────────────────────────┘   └──────────────────────────────────┘
```

The validation logic lives ONCE, in `core/logic` (`axiom-core-logic`), and is
compiled TWICE into two different guests. The two ELFs share a logic crate but
are NOT the same binary and have independent identities (CoreID vs IMAGE_ID).

## Key Principles

### 1. axiom-core.elf is the identity artifact
- `core/artifacts/axiom-core.elf`, built from `core/avm-guest`
  (target `riscv32im-unknown-none-elf`)
- **CoreID = BLAKE3 of the committed ELF** (never SHA-256); pinned in
  `core/artifacts/CORE_ID.txt`, with the accept-set of prior worldlines in
  `core/artifacts/BLESSED_PRIOR_CORE_IDS.txt`
- If logic changes → new ELF → new CoreID → new worldline
- The riscv build is NOT reproducible: verify a CoreID by hashing the
  committed ELF, never by rebuilding

### 2. The DMAP-VM is PORTABLE
- RV32IM interpreter (`riscv-interpreter` feature) — the attestation-bearing
  execution: the DMAP attestation is derived from the execution trace
- Cranelift JIT (`cranelift-jit-backend`, on by default) is a PERFORMANCE
  layer only (~20-30x over the interpreter); it never carries attestation,
  and a JIT failure is alert-and-continue, not a validation outcome
- Embedded in-process by the SDK (CL1), Lambda, and ANTIE
  (`use_embedded_avm = true`)

### 3. The zk-VM is for PROOFS, and proves a SUBSET
- Wraps risc0; the live entry point is `prove_checkpoint()`
  (`ZkvmProver::prove()` is dead code — wrong journal type)
- The guest runs `execute_cl3_zkp_checkpoint` and commits
  `ZkpCheckpointOutputs` — a strict subset: client authorization (Ed25519),
  balance non-inflation, state-chain continuity, anti-replay, and a handful
  of protocol rules
- Dilithium FACT signing, FACT-chain verification, witness validation, txid
  and commitment_hash run NATIVELY on the host, outside the ZK boundary
- "Both VMs produce identical PublicOutputs" is architecturally impossible;
  the real invariant is that the independently-computed checkpoint fields
  (`result`, `produced_state_id`, `new_balance`, `new_wallet_seq`,
  `rejection_reason`) agree with the DMAP-VM

### 4. Portability Model
```
Platform X                  Platform Y
──────────────────────      ──────────────────────
DMAP-VM (x86)               DMAP-VM (ARM)          ← Rebuild
axiom-core.elf (RV32IM)     axiom-core.elf (RV32IM)← SAME BINARY, same CoreID
```

The host VM is rebuilt per platform; the RV32IM ELF — and therefore the
CoreID — is identical everywhere. The zk-VM side is independent: same zkvm
guest → same IMAGE_ID.

## Project Structure

```
core/
├── logic/                  # Validation logic (crate: axiom-core-logic)
│                           # The ONE source both guests compile
├── avm/                    # DMAP-VM (crate: axiom-dmap-vm)
│                           # RV32IM interpreter + Cranelift JIT
├── avm-guest/              # Builds logic → artifacts/axiom-core.elf
├── zkvm-guest/             # risc0 guest variant (CL3 ZK checkpoint)
├── zkvm-host/              # zk-VM (crate: axiom-zk-vm), risc0 wrapper
├── ipc/                    # CBOR-frame IPC codec (Core-as-subprocess path)
├── bin/                    # axiom-core-bin — CBOR-IPC conformance host
├── test-utils/             # Shared test helpers
└── artifacts/              # Committed artifacts
    ├── axiom-core.elf      # THE CoreID artifact
    ├── CORE_ID.txt         # Canonical CoreID (BLAKE3 of the ELF)
    ├── BLESSED_PRIOR_CORE_IDS.txt  # Accept-set of prior worldlines
    └── ZKVM_IMAGE_ID.txt   # Committed risc0 IMAGE_ID counterpart
```

## Build Process

```
Step 1: Build the DMAP guest (the CoreID artifact)
────────────────────────────────
- cd core/avm-guest && cargo build --release
    --target riscv32im-unknown-none-elf
- Output: core/artifacts/axiom-core.elf
- CoreID = BLAKE3(axiom-core.elf) → CORE_ID.txt

Step 2: Build the zkVM guest
────────────────────────────────
- core/build-zkvm.sh (risc0 toolchain)
- IMAGE_ID recorded in core/artifacts/ZKVM_IMAGE_ID.txt
- NOT rebuilt automatically — rebuild it whenever core/logic changes,
  or the two compilations drift

Step 3: Rotation
────────────────────────────────
- Commit ELF + CORE_ID.txt + ZKVM_IMAGE_ID.txt +
  BLESSED_PRIOR_CORE_IDS.txt together
- Validators pin the canonical CoreID and accept blessed priors
```

## Runtime Flow

```
Production (every validated transaction):
1. SDK runs CL1 in its embedded DMAP-VM → DMAP execution proof
2. Lambda rejects any request without a verified client Core proof
3. Lambda re-runs Core (CL2/CL3/CL5) in its embedded DMAP-VM
   against its own stored state
4. Core takes PublicInputs, returns PublicOutputs — no disk,
   no network, no other layers

zk path (off the hot path):
1. Host loads the zkvm guest, calls prove_checkpoint()
2. Guest re-derives the checkpoint fields, commits ZkpCheckpointOutputs
3. Verifier checks IMAGE_ID + the risc0 proof
4. Differential harness (core/zkvm-host/examples/
   differential_conformance.rs) asserts checkpoint ≡ DMAP-VM
```

## Verification

- **CoreID**: hash the committed ELF —
  `cargo run -p axiom-core-logic --features dev-mode --example
  compute_core_id -- core/artifacts/axiom-core.elf` — and compare against
  `CORE_ID.txt`. Validators enforce the pin at runtime.
- **IMAGE_ID**: risc0 verification ties a proof to the committed
  `ZKVM_IMAGE_ID.txt`.
- **Conformance**: `tests/run_conformance.py --core-bin` feeds the shared
  vector corpus to any Core over CBOR IPC; `tools/conform` checks the
  committed ELF against native `core/logic`.

## Security Model

| Threat | Protection |
|--------|------------|
| Modified core logic | CoreID changes; validators reject the unpinned ELF |
| Modified zkvm guest | IMAGE_ID changes, proofs rejected |
| Bypassed client execution | Lambda requires a verified Core execution proof |
| Two-compilation drift | differential conformance harness (checkpoint fields) |
| Different worldline | different CoreID, admitted only via the blessed-prior set |

## 30-Year Portability

```
Today (2026):
- risc0 (pinned) for the zk path
- DMAP-VM interprets/JITs the RV32IM ELF
- axiom-core.elf, one CoreID

Later:
- risc0 dead, some new zkVM exists
- Rebuild the zk guest for it → new IMAGE_ID
- Reimplement or rebuild the DMAP-VM host for new platforms
- The RV32IM ELF — and its CoreID lineage — is the durable identity

Audit process:
1. Verify the historical ELF hash (BLAKE3) matches the recorded CoreID
2. Verify the new host correctly interprets RV32IM
3. New worldline inherits trust from the old logic via the blessed-prior set
```

## RISC-V Choice Rationale

Why RV32IM over other bytecode formats:

| Format | Pros | Cons |
|--------|------|------|
| **RV32IM** | Open ISA, frozen base spec, rustc targets it directly, zkVMs speak it | Larger spec than eBPF |
| eBPF | Simple (~100 ops) | No mainstream Rust core-target; would need a custom toolchain |
| WASM | Very common | Larger spec, heavier runtime semantics |
| Custom | Full control | No ecosystem, harder to audit |

RV32IM wins because:
1. `core/logic` compiles to it with the stock Rust toolchain — no custom
   bytecode pipeline to trust
2. The same logic recompiles for the risc0 guest, keeping the two-VM
   differential meaningful
3. Frozen, well-documented ISA; independent reimplementation of the
   interpreter is tractable and auditable
