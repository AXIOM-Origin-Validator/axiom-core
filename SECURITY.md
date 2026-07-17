# Security Policy

## Project status

**AXIOM is pre-mainnet software. Do not use it to custody real value.**

The protocol has been developed and reviewed in-house with an emphasis on
cryptographic correctness, deterministic consensus, and adversarial soak
testing. It has **not** undergone an independent third-party security audit.
The trust model, known limitations, and accepted risks are documented openly
in [`THREAT_MODEL.md`](THREAT_MODEL.md) — including the gaps we have found in
our own design. We would rather you know exactly where the edges are than
discover them in production.

If you are evaluating AXIOM, read the threat model first. It tells you what the
protocol cryptographically guarantees, what it only guarantees economically or
socially, and where the model is currently weakest.

## Supported versions

AXIOM is pre-1.0 and pre-mainnet. Only the current `master` is supported;
there is no backported-fix policy yet. Any on-disk or wire format may change
without migration until the first mainnet release (see the "no backward-compat
bandaids pre-mainnet" policy in `CLAUDE.md`).

| Version | Supported |
|---------|-----------|
| `master` (latest) | ✅ |
| Tagged pre-releases | ⚠️ best-effort, no guarantees |
| Anything older | ❌ |

## Reporting a vulnerability

**Please report security issues privately. Do not open a public issue for a
suspected vulnerability.**

Contact the maintainers privately by email:

- **AXIOM-Origin-Validator@protonmail.com**
- **axiom@onionmail.org**

For sensitive reports, encrypt to the maintainer PGP key (the same key that
signs the whitepaper):

```
029E 9BE8 569B 748A 1E75  8B38 86EF 3679 E216 16D8
```

(GitHub Private Vulnerability Reporting — the "Report a vulnerability" button
under this repository's *Security* tab — will also be available once enabled;
until then, please use email.)

When you report, please include:

- A clear description of the issue and the security property it breaks
  (theft, double-spend, inflation, denial-of-service, deanonymization, etc.).
- The layer(s) involved (Core / Lambda / Nabla / ANTIE / SDK).
- A proof-of-concept or the exact inputs that trigger it, if you have one.
- Your assessment of severity and the assumptions it relies on (e.g. "requires
  a malicious validator", "requires 2 of 3 overlapped validators to collude").

### What to expect

This is a small project without a dedicated security team, so response times
are best-effort, but we will:

1. Acknowledge your report as soon as we can.
2. Confirm or dispute the finding, with reasoning.
3. Agree a coordinated-disclosure timeline with you for anything material.
4. Credit you (with your consent) in the advisory and changelog.

We practice coordinated disclosure: please give us a reasonable window to fix
a confirmed issue before publishing details.

## Scope

### In scope

- **Core** (`core/`) — the canonical RISC-V ELF and its validation logic. Core
  is the sole cryptographic authority; any way to make Core accept an invalid
  transaction, mint or destroy value incorrectly, or produce divergent outputs
  across honest validators for the same inputs is the **highest-severity** class
  of finding.
- **Lambda** (`lambda/`) — consensus, stored state, the AXC mint path. Any way a
  single malicious validator can forge, double-spend, inflate, or corrupt state
  that honest validators would not catch.
- **Nabla** (`nabla/`) — citizen/gossip infrastructure. Any way a malicious
  Nabla node can influence consensus, supply accounting, or minting beyond its
  intended advisory role.
- **SDK / client** (`sdk/`, `apps/`) — note that the SDK is **untrusted by
  design** (see threat model). A finding here only matters if it lets an
  adversary break a property that Core/Lambda are supposed to enforce
  independently. "The SDK doesn't check X" is only a vulnerability if X is also
  not enforced server-side.
- Cryptographic primitives, canonical encoding, signature verification,
  determinism (non-determinism in consensus code is in scope).

### Out of scope

- A compromised end-user device (key theft from the user's own machine).
- Network-level attacks (BGP, DNS, ISP-level censorship).
- Denial-of-service that requires resources disproportionate to the impact.
- Findings that require **more colluding validators than the honest-quorum
  assumption allows** — these are documented as a known limitation, not a bug
  (see `THREAT_MODEL.md` §"Known open issues"). Reports that *reduce* the number
  of colluders required, or that achieve impact under the stated assumption, are
  in scope.
- Anything that depends on running a build with `disable-audit` or `dev-mode`
  features (these are development-only and must not be used in production).
- Theoretical quantum attacks on Ed25519 (operational signatures); note that
  the certificate and FACT-provenance layers already use post-quantum schemes
  (SPHINCS+ / ML-DSA).

## Known limitations and accepted risks

We disclose these proactively. Full detail and severities are in
[`THREAT_MODEL.md`](THREAT_MODEL.md):

- **Stateless Core trusts validator-supplied state.** Core has no memory of its
  own; it computes on the state Lambda provides. This is safe under the honest-
  quorum assumption but is the structural root of the colluding-validator
  inflation concern below.
- **Colluding overlapped validators (inflation).** If the overlapped validators
  for a transaction collude *and* the client cooperates, they can feed Core a
  consistent fabricated balance. This is an acknowledged, currently-unmitigated
  vector that violates the protocol's monetary integrity when the honest-quorum
  assumption fails. Tracked; mitigation under design.
- **Aggregate supply cap is not enforced at the mint.** The fixed-supply ceiling
  is currently tracked by Nabla bookkeeping rather than enforced inside Core at
  mint time. Tracked; a Core-enforced pool attestation is the planned fix.
- **Experimental subsystems are not security-reviewed and are gated off**
  (e.g. the oracle path runs only with `OracleConfig.enabled = false`; the
  runner-pool / contribution-credit reward path is not wired). Do not enable
  these in production.

## Verifying the protocol yourself

You do not have to trust us about determinism. The protocol ships conformance
vectors and a reproducible Core identity:

```bash
# Regenerate the deterministic input/output conformance vectors:
cargo run -p axiom-core-logic --example generate_vectors > tests/consensus_vectors.json

# Run the conformance suite against a compiled Core:
python3 tests/run_conformance.py --core-bin ./core.bin

# Check the consensus boundary before any change to Core:
bash scripts/check_consensus_boundary.sh
```

Every Core execution is bound to a `CoreID` (a BLAKE3 hash of the canonical
ELF). All honest participants run the *same* ELF; a divergent Core is rejected
by the DMAP/zkVM gate. Reproducing the `CoreID` and passing the conformance
vectors is sufficient to verify that an implementation matches consensus.

## Acknowledgements

Security researchers who responsibly disclose confirmed issues will be credited
here and in the changelog, with their consent.

<!-- Hall of thanks:
- (your name could be here)
-->
