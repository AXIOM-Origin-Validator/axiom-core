# axiom-core

AXIOM Core — the deterministic protocol engine. The committed ELF is the artifact; verify its CoreID, don't rebuild.

Part of the AXIOM protocol family — specifications live in
[axiom-docs](https://github.com/AXIOM-Origin-Validator/axiom-docs), research in
[axiom-papers](https://github.com/AXIOM-Origin-Validator/axiom-papers), binaries in
[axiom-dist](https://github.com/AXIOM-Origin-Validator/axiom-dist).

## Contents

`logic/` `avm/` `ipc/` `zkvm-host/` `test-utils/` — plus `avm-guest/` and `zkvm-guest/` (RISC-V guest sources, built separately) and `artifacts/` holding the **committed Core ELF and its CoreID**.

## Verify, don't build

Nobody is expected to build this repo to trust it. The consensus artifact is
`artifacts/axiom-core.elf`; its identity is the BLAKE3 CoreID in
`artifacts/CORE_ID.txt` (this snapshot: `5ada2f19…`). See `VERIFYING.md` for
the full verification flow, and `CONSENSUS_CRITICAL.md` for the files every
node must execute identically. Git tags on this repo are protocol versions,
keyed by CoreID.

## Releases

This repository receives one snapshot commit per AXIOM release, exported from
the project's working tree (3.3.0 at export). Its git log is the release
history. License: GPL-3.0.

> AXIOM is pre-mainnet software. Do not use it to custody real value.
