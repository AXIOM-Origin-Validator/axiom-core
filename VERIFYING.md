# Verifying AXIOM

You do not have to trust the maintainers about AXIOM's consensus rules. Core — the
single RISC-V ELF that is the sole cryptographic authority — is deterministic, its
identity is a hash anyone can check, and its behavior is pinned by a public
conformance suite. This document shows how.

Paths below are as laid out in the public
[`axiom-core`](https://github.com/AXIOM-Origin-Validator/axiom-core) repository.
(In the development monorepo the same directories live under `core/` and the
verification kit under `tests/` and `tools/`.)

See also [`SECURITY.md`](SECURITY.md) and [`THREAT_MODEL.md`](THREAT_MODEL.md).

---

## 0. The fastest check: the committed ELF's identity

The consensus artifact is `artifacts/axiom-core.elf`. Its `CoreID` is the BLAKE3
hash of that file:

```bash
b3sum artifacts/axiom-core.elf
cat artifacts/CORE_ID.txt
```

The two values must match — and must match the CoreID published for the release
you checked out (the git tag, e.g. `core-d0900069`). Every honest participant
runs the same ELF; a divergent Core produces a different CoreID and is
rejected by the CoreID accept-set check at registration and consensus (the
DMAP attestation and the zkVM checkpoint proof additionally attest execution
of the canonical ELF — DMAP is attestation-by-re-execution, not a proof
system, and the zkVM guest covers a checkpoint subset of Core).

**Paper readers:** the release
[`core-42285e6b`](https://github.com/AXIOM-Origin-Validator/axiom-core/releases/tag/core-42285e6b)
carries the exact ELF cited by *Continuity Without Consensus*
(DOI [10.5281/zenodo.21295772](https://doi.org/10.5281/zenodo.21295772)) — verify
it the same way.

## 1. Build and test the consensus logic

`axiom-core-logic` contains the deterministic validation rules. It has no zk-VM
dependency and builds everywhere:

```bash
cargo test -p axiom-core-logic --lib --features dev-mode
```

> `dev-mode` is a development build feature. It must **not** be used in
> production (see `SECURITY.md`).

The full node crates live in their own repositories —
[`axiom-lambda`](https://github.com/AXIOM-Origin-Validator/axiom-lambda),
[`axiom-nabla`](https://github.com/AXIOM-Origin-Validator/axiom-nabla) — each
buildable standalone with its protocol dependencies git-pinned to this repo's
tags. (Linux recommended for those; the zk-VM prover dependency does not build
its GPU kernels on macOS.)

## 2. Rebuild the Core identity (`CoreID`)

Core compiles to one canonical RISC-V ELF from `avm-guest/`:

```bash
rustup target add riscv32im-unknown-none-elf
bash scripts/build-core-elf.sh
```

The script prints the resulting `CoreID`. On the same Linux toolchain, two
independent builds of the same source produce the same `CoreID`; if yours
matches the released value, your Core is byte-identical to the network's.

> Toolchain differences (and macOS) can produce a different `CoreID` for
> identical sources. When that happens, verification falls back to §0: the
> committed ELF *is* the canonical artifact, and its hash is what the network
> enforces — reproduction is a stronger check when your toolchain matches, not
> a prerequisite for trust.

## 3. Run the conformance vectors

`tests/consensus_vectors.json` is a set of deterministic input/output pairs
covering the CL1/CL2/CL3/CL5/CL11 execution modes and owner-proof.

Regenerate the vectors from the source you're auditing and diff:

```bash
cargo run -p axiom-core-logic --example generate_vectors --features dev-mode > /tmp/vectors.json
diff <(python3 -m json.tool tests/consensus_vectors.json) <(python3 -m json.tool /tmp/vectors.json)
```

**Expected (updated 2026-10-01):** the generator is fully deterministic — two
runs are byte-identical. ~~The only differences are 3 FACT-chain vectors whose
witness signatures are non-deterministic~~ (that was an unseeded keygen, fixed
2026-08-01). One limit: the CL3 FACT vectors carry certificates signed by the
network's root keys, and their witness keys are derived from the root SECRETS
(so that no published vector is a usable credential). Without the root secrets
the generator stops at those vectors — an auditor cannot regenerate them, only
replay them with the runner below. To check that a corpus carries no usable
credential, run the artifact gate:

```bash
cargo run --release -p axiom-core-logic --features dev-mode --example corpus_credential_gate -- tests/consensus_vectors.json
```

**Building a reimplementation?** `tests/run_conformance.py` feeds the same
vectors to *any* binary that speaks the Core IPC protocol (CBOR frames over
stdin/stdout):

```bash
python3 tests/run_conformance.py --core-bin ./your-core-implementation

# The in-tree reference target to compare against:
cargo build --release -p axiom-core-bin --features axiom-core-logic/dev-mode
python3 tests/run_conformance.py --core-bin ./target/release/core-bin
```

**Read the runner's limits before you rely on it.** It compares the `result`
field only — accept vs reject. It does not compare `rejection_reason`,
`new_balance` or `produced_state_id`, though the corpus records expectations for
all three, and it reports vectors without CBOR inputs as skipped rather than
passed. A reimplementation that passes it agrees with the reference on the
accept/reject decision for the covered modes; that is a necessary condition for
conformance, not a sufficient one. The stronger check is the byte-level vector
diff above.

(Pre-mainnet note: release-profile builds of this repo
deliberately fail while `WALLET_IDENTITY_KEY` is the dev key — a compile guard
so nobody ships a release binary before the mainnet key ceremony. Use debug
builds or `--features dev-mode` until then.)

## 4. Consensus-critical surface

[`CONSENSUS_CRITICAL.md`](CONSENSUS_CRITICAL.md) lists the files every node must
execute identically. Any change to them is a protocol version — it rotates the
CoreID and appears as a new tag on this repository. In the development monorepo,
layer- and consensus-boundary lint scripts additionally enforce that no crypto
lives outside Core and no consensus-critical change lands without a review tag.

---

## What verification does and does not prove

- **Proves:** your Core is byte-identical to the network's (CoreID), and it
  produces the protocol's expected outputs for the conformance inputs
  (determinism + rule conformance).
- **Does not prove:** the absence of all bugs, or the soundness of the parts of
  the system outside Core (validators, gossip). Those are covered by the threat
  model and the open-issues register, not by these vectors. See
  [`KNOWN_ISSUES.md`](KNOWN_ISSUES.md).

If you find a place where the implementation does not match the documented
rules, that is exactly the kind of report we want — see [`SECURITY.md`](SECURITY.md).
