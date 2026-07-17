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
| 10 | `core/logic/protocol.toml` | Protocol constants baked into Core ELF at compile time (atoms_per_axc, minimum_tx_atoms, deed_write_fee, owner_proof_required_epoch, max_votes_per_case_per_tick). Changing any value = new worldline. |
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

`tests/consensus_vectors.json` contains 20 deterministic input/output pairs
covering CL1 (8 vectors), CL2 (1 vector), CL5 (6 vectors), CL11 (2 vectors),
wallet_id (1 vector), and owner_proof (2 vectors). After any change to a CONSENSUS_CRITICAL file or to `core/logic/protocol.toml`, regenerate the
vectors and commit the updated JSON alongside the code change with
CONSENSUS_CRITICAL_REVIEWED in the commit message. The diff in
consensus_vectors.json is the evidence of exactly what the consensus change
did. Third-party reimplementers: run `tests/run_conformance.py --core-bin
./core.bin` against your implementation to verify protocol conformance.

## Accepted Security Risks (v2.11.14 Audit)

These are documented, acknowledged limitations from the external audit.
Each has a mitigation that prevents exploitation in the current state.

| ID | Risk | Mitigation | Status |
|----|------|------------|--------|
| GAP-O1-O4 | Oracle 4 design gaps | `OracleConfig.enabled=false` rejects all oracle claims | Gated off |
| P4-4 | CoreID pinning not activated | Requires ceremony digest — checklist in `webclient/static/index.html` | Deferred |
| RISK-3 | PGP plaintext fallback | Delivery log tracks `encrypted` flag. Cheques not protocol-secret. | Accepted |
| RISK-8 | CC score fabrication | Bounded by network score denominator. 1 claim/24h/NBC. | Accepted |
| RISK-9 | ClaimTracker in-memory | 1 extra claim per restart. Negligible economic impact. | Accepted |

Full details: `docs/EXTERNAL_AUDIT_REPORT.md` and `docs/AXIOM_SECURITY_INVARIANTS.md`.
