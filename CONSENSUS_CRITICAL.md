# Consensus-Critical Files

These 11 files define the deterministic validation logic that every AXIOM node
must execute identically. Any divergence produces a worldline split.

## Files

| # | Path | Purpose |
|---|------|---------|
| 1 | `core/logic/src/validation.rs` | Transaction validation (state ID, wallet_seq, balance, conservation) |
| 2 | `core/logic/src/modes.rs` | CL1-CL11 execution mode dispatch |
| 3 | `core/logic/src/fact.rs` | FACT chain verification (money provenance) |
| 4 | `core/logic/src/vbc.rs` | VBC/NBC certificate chain verification |
| 5 | `core/logic/src/wallet_id.rs` | wallet_id checksum + security level extraction |
| 6 | `core/logic/src/wallet_seq.rs` | wallet_seq monotonic enforcement |
| 7 | `core/logic/src/crypto.rs` | Cryptographic primitives (BLAKE3, SHA3-256, Ed25519, SPHINCS+, Dilithium) |
| 8 | `core/ipc/src/codec.rs` | Canonical CBOR codec (wire format for PublicInputs/PublicOutputs) |
| 9 | `core/avm/src/interpreter.rs` | AVM interpreter (executes Core ELF on every platform) |
| 10 | `core/logic/protocol.toml` | Protocol constants baked into Core ELF at compile time (atoms_per_axc, minimum_tx_atoms, deed_write_fee, max_votes_per_case_per_tick; `owner_proof_required_epoch` deleted 2026-09-25, KI#108). Changing any value = new worldline. |
| 11 | `core/logic/genesis_lockup_wallets.txt` | Genesis validator wallet IDs and lockup period. Changing wallet IDs or lockup_ticks produces a new worldline. Populate before mainnet build. |

## PR Rules

Any pull request that modifies one or more of these files **must** include the
following tag in its commit message:

```
CONSENSUS_CRITICAL_REVIEWED
```

This signals that the author has:

1. Verified the change produces identical `PublicOutputs` for identical `PublicInputs` across all platforms.
2. Confirmed no new non-determinism is introduced (no floats, no hash-map iteration, no system calls).
3. Checked that the change does not alter wire format without a corresponding protocol version bump.
4. Run the full test suite (`cargo test`) and all integration/chaos tests.

## Purpose of the Annotation

Each consensus-critical file carries a `// CONSENSUS_CRITICAL` comment near the
top. This annotation serves as a human-readable signal to reviewers that extra
scrutiny is required. It also enables automated tooling
(`scripts/check_consensus_boundary.sh`) to flag PRs that touch these files
without the required review tag.

## Conformance Vectors

**STATUS (2026-10-01):** **33** vectors, **31** executable — three CL3 FACT
signature vectors added (`CL3_FACT_BADSIG_001`, `CL3_FACT_BADCERT_001`,
`CL3_FACT_DUPWITNESS_001`). The corpus declares `executable_vector_count` and the
runner requires exactly that many to execute; on Accept it also compares the
produced state id and new balance.

**STATUS (2026-09-11, superseded above):** `tests/consensus_vectors.json` contains **30**
deterministic input/output pairs — CL1 (12), CL2 (1), **CL3 (9)**, CL5 (6),
CL11 (2); **28** are executable, the two oracle-VBC vectors
(`ORACLE_VBC_TOO_OLD_001`, `ORACLE_VBC_FRESH_001`, mode CL1) carry no
`inputs_cbor_hex` and are reported as skipped rather than passed (counts
measured by parsing the JSON; the three extra CL3 vectors are
`CL3_FACT_VALID_001`, `CL3_FACT_BROKEN_001`, `CL3_FACT_UNDERK_001`). The
previous sentence is kept struck:
~~`tests/consensus_vectors.json` contains 27 deterministic input/output pairs —
CL1 (12), CL2 (1), CL3 (6), CL5 (6), CL11 (2). Twenty-five are executable; the
two oracle-VBC vectors carry no CBOR inputs and are reported as skipped rather
than passed.~~ After any change to a CONSENSUS_CRITICAL file or to
`core/logic/protocol_core.toml`, regenerate the vectors and commit the updated
JSON alongside the code change with CONSENSUS_CRITICAL_REVIEWED in the commit
message. The diff in consensus_vectors.json is the evidence of exactly what the
consensus change did.

Third-party reimplementers: run `tests/run_conformance.py --core-bin <your-bin>`
against your implementation. The in-tree reference target is `axiom-core-bin`
(`core/bin`), the CBOR-IPC host:

```bash
cargo build --release -p axiom-core-bin --features axiom-core-logic/dev-mode
python3 tests/run_conformance.py --core-bin ./target/release/core-bin
```

**What that runner does and does not check.** It compares the `result` field
only (accept/reject). It does not compare `rejection_reason`, `new_balance` or
`produced_state_id`, even though the corpus records expectations for all three.
Passing it establishes wire conformance on the accept/reject decision for the
covered modes — not full output equivalence. Treat it as a floor, not a
certificate.

## Accepted Security Risks (v2.11.14 Audit)

These are documented, acknowledged limitations from the external AI audit rounds.
Each has a mitigation that prevents exploitation in the current state.

| ID | Risk | Mitigation | Status |
|----|------|------------|--------|
| GAP-O1-O4 | Oracle 4 design gaps | `OracleConfig.enabled=false` rejects all oracle claims | Gated off |
| P4-4 | CoreID pinning not activated | Requires ceremony digest — checklist in `webclient/static/index.html` | Deferred |
| RISK-3 | PGP plaintext fallback | Delivery log tracks `encrypted` flag. Cheques not protocol-secret. | Accepted |
| RISK-8 | CC score fabrication | Bounded by network score denominator. 1 claim/24h/NBC. | Accepted |
| RISK-9 | ClaimTracker in-memory | 1 extra claim per restart. Negligible economic impact. | Accepted |

Full details live in the project's private working tree (audit report + security invariants registers); the public summary of open items is `KNOWN_ISSUES.md`.
