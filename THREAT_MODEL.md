# AXIOM Threat Model

This document states what AXIOM defends against, what it does not, and exactly
where the model is weakest. It is deliberately candid: we would rather a reader
understand the real boundary than trust a marketing claim. For how to report a
vulnerability, see [`SECURITY.md`](SECURITY.md).

**Status:** pre-mainnet, not independently audited. Treat every guarantee below
as "intended and tested in-house," not "externally certified."

---

## 1. System overview

AXIOM is a fixed-supply digital cash protocol. Rather than global consensus, it
uses a small per-transaction witness quorum plus a single canonical validation
authority. The layers and their one-line jobs:

| Layer | Role |
|-------|------|
| **Core** | The canonical RISC-V ELF. Validates transactions; owns *all* cryptography. Stateless: takes `PublicInputs`, returns `PublicOutputs`. The single source of truth. |
| **Lambda** | Validators. Hold stored wallet state, run the k=3 witness quorum, collect signatures, run the mint path. Coordinate; do not judge legality. |
| **Nabla** | Citizen/gossip infrastructure: txid registration, pool accounting, certificate issuance, contribution tracking. Advisory; push-inward only. |
| **ANTIE** | Transport/gateway (email, HTTP, carriers). Moves bytes; never interprets or synthesizes transaction state. |
| **SDK / client** | Holds user keys, runs Core locally to produce execution proofs, stores what validators return. |

The design principle: **one cryptographic chokepoint (Core), everything else
untrusted around it.**

---

## 2. Trust boundaries

This is the heart of the model. Each layer is trusted to do *only* its job.

### Core — fully trusted, sole authority
The one component we trust completely. It is a deterministic state machine
compiled to a single RISC-V ELF, run identically by every participant via a
DMAP-attesting VM or a zero-knowledge VM. Its determinism is externally
verifiable (conformance vectors + reproducible `CoreID`). Core **cannot** touch
disk, network, or other layers; it can only compute over the inputs handed to
it. Posture: *"can crash, must not lie"* — any uncertainty fails closed.

The critical consequence: **Core is stateless and trusts the state it is
given.** It is the perfect judge of *whether inputs are internally consistent
and properly signed*, but it has no independent view of history. This is the
single most important fact in this document; several limitations in §6 follow
from it directly.

### Lambda / validators — NOT trusted; honest-quorum assumption
Individual validators may be fully malicious. We assume only that **at least one
validator per witness quorum is honest** (see §5 for the exact, weaker
operative requirement and its limits). Validators are "sandwiched": Core
validates the inputs *to* a validator (CL2) and the outputs *from* a validator
(CL3), so an honest quorum detects and outvotes a single liar. Validators are
**not** trusted to do cryptography, compute state identifiers, or reach quorum
alone.

### Nabla — assumed potentially hostile
**Any Nabla node may be malicious.** Nabla provides advisory, push-inward
artifacts (registrations, pool counters, certificates) that Lambda re-verifies
through Core. Lambda and ANTIE must never *query Nabla as an authority* — a
compromised node could stall, lie, or selectively delay to influence consensus.
Degraded mode (more scars, fewer confirmations) is safe; a hard dependency on a
Nabla answer is not.

### ANTIE / gateway — NOT trusted; pure transport
Receives, parses, forwards, responds. It runs Core pre-filters with *no* stored
state (state checks are no-ops there). It must never synthesize a wallet state,
fabricate a sequence number, or strip/interpret transaction fields. Any logic in
ANTIE that reconstructs state Lambda should verify is a bug.

### SDK / client — NOT trusted; assumed adversarial
**Assume an attacker bypasses every SDK-side check and submits arbitrary crafted
bytes directly to validators.** Therefore any security property that lives only
in the SDK is worthless. The SDK's checks (balance, dust, double-redeem guards,
pre-accept verification) exist for honest-client UX and defense-in-depth — every
one of them that *matters for safety* is independently re-enforced by Core or
Lambda. The SDK is also forbidden from constructing cryptographic artifacts
(FACT links, signatures) or adopting network-supplied state — recovery happens
only through a key-signed, validator-witnessed self-send ("HEAL"), never by
pulling state from the network (which would be a replay vector).

---

## 3. Adversary capabilities

We design against, in increasing order of power:

1. **Malicious client / crafted bytes.** Can submit any payload, forge any
   field the SDK would normally set, run a patched or hostile wallet. Cannot
   produce valid signatures without the corresponding private keys, and cannot
   make Core accept internally-inconsistent inputs.
2. **Single malicious validator.** Everything above, plus: can feed Core chosen
   `PublicInputs`, sign chosen commitments, withhold or delay, and craft
   `prev_receipt` sets. Contained by Core's input/output validation + the honest
   quorum.
3. **Malicious Nabla node.** Can lie in gossip, register false artifacts, delay
   or partition. Contained by Lambda re-verifying through Core and by the
   advisory-only boundary — with documented exceptions in §6.
4. **Colluding validators.** The honest-quorum assumption is what bounds this.
   The point at which it breaks is stated explicitly in §5 and §6.

---

## 4. Security goals

We distinguish goals the protocol enforces **cryptographically** (a
mathematical MUST) from goals it pursues **economically or socially** (a
best-effort SHOULD that can degrade).

### MUST — cryptographically enforced by Core
- **No theft.** Value moves only with a valid owner signature over every
  security-critical field.
- **No double-spend** (under the honest-quorum assumption). Concurrent spends of
  the same state are caught by witness-set intersection.
- **No inflation / no counterfeiting** (under the honest-quorum assumption).
  Supply is conserved; every atom traces to genesis.
- **No replay.** State is consumed once; stale-state transactions are rejected.
- **Deterministic consensus.** Honest validators compute bit-identical outputs
  for identical inputs.

### SHOULD — economic / social, can degrade
- **Anonymity and unlinkability** of participants.
- **Coercion resistance** (anti-coercion rules, decoy witnessing).
- **Censorship resistance.**

These depend on validators running the full stack and on economic incentives;
they weaken if participants run minimal implementations. The protocol *cannot
force a validator to protect a user's privacy* — only the user's own correctness
is cryptographically guaranteed.

---

## 5. The witness-quorum (k=3) argument and its limit

AXIOM does not use global consensus. Each transaction is witnessed by a small
quorum (k ∈ {3,4,5}; k=3 is the floor). The double-spend defense is
**combinatorial, not probabilistic**: consecutive transactions from the same
wallet must share a minimum overlap of witnesses (`floor(k/2)+1`), so any two
concurrent spends of the same state are guaranteed to share at least one
validator, who marks the state consumed and rejects the second.

**Documented trust assumption:** at least `ceil(k/2)` of the k witnesses are
honest (for k=3, that is 2 of 3).

**Operative requirement for double-spend safety:** at least **one honest
overlapped validator with real history**. An honest validator that holds the
wallet's true prior state will reject a fabricated spend.

**Where it breaks — stated plainly.** If *all* overlapped validators for a
transaction collude **and** the client cooperates, they can feed Core a
consistent fabricated balance. Both colluders "refill" the same lie, so the
cross-validator state hashes agree, and an honest non-overlapped validator signs
in good faith. Every layer of the witness-overlap defense is bypassed because
the fabricated state was never real. This is an **inflation** vector, not merely
a local double-spend, and it is currently **unmitigated** (see §6, SEC-01).

Why k=3 and not k=2: "two is a coincidence, three is a conspiracy." k=3 is the
smallest quorum where forgery requires deliberate multi-party collusion rather
than a single correlated failure. It is explicitly *not* a claim of absolute
security — it is a calibrated cost-to-attack.

---

## 6. Known open issues

We track these openly with severities. (Identifiers map to the internal security
review; the most current status lives in the project's known-issues docs.)

| ID | Issue | Severity | Status |
|----|-------|----------|--------|
| **SEC-01** | **Colluding overlapped validators can mint.** Stateless Core trusts the balance validators refill; colluding overlap + cooperating client fabricates supply. Violates monetary integrity when the honest-quorum assumption fails. | High–Critical | Acknowledged; mitigation under design (history commitment consumed by Core is the leading candidate). |
| **SEC-02** | **Aggregate supply cap not enforced at the mint.** The fixed-supply / genesis-pool ceiling is tracked by Nabla bookkeeping that runs *after* the mint; a patched client can skip it. Per-wallet replay *is* enforced by Core. | High | Acknowledged; planned fix is a k-witnessed pool attestation consumed by Core at redeem. |
| **SEC-03** | **Pool-accounting gossip** can be processed on a soft-auth path and merges an unbounded counter; one node can grief mesh-wide claim funding. | High | Acknowledged; fix is to remove the soft path and bound the merge. |
| **SEC-04** | **Certificate chain-of-trust verified only on the last witness** of a prior-receipt set (a performance optimization), weaker than full verification under a malicious-validator model. | Medium–High | Under review; reachability being confirmed before hardening. |
| **SEC-05/06/09** | **Experimental subsystems** (contribution-credit reward path, a signature-skipping certificate helper, oracle stake adoption) are not security-reviewed. They are unwired or gated off and **must not be enabled in production**. | Latent | Gated/fenced; to be hardened before activation. |

For the full set, see the project's security review and known-issues
documentation. Issues that require *more* colluders than the honest-quorum
assumption allows are limitations, not bugs; reports that lower that bar or
achieve impact within the assumption are in scope (see `SECURITY.md`).

---

## 7. Explicit assumptions

The model holds only if these hold. We list them so they can be challenged:

1. **Honest quorum.** At least one honest overlapped validator with real history
   participates in each transaction (see §5 for the failure when this is false).
2. **Canonical Core.** All honest participants run the same canonical ELF;
   `CoreID` divergence is detected and rejected.
3. **Sound cryptography.** Ed25519 (operational), SPHINCS+ / ML-DSA
   (certificates, FACT provenance), BLAKE3 / SHA3 (hashing) are not broken.
4. **Trusted local device and keys.** The user's own machine and private keys
   are not compromised.
5. **Genesis integrity.** Genesis validator keys and the genesis distribution
   are honestly established (a compromised genesis key is a catastrophic,
   out-of-band failure).
6. **Production configuration.** No `disable-audit` / `dev-mode` features; no
   experimental subsystems enabled.

---

## 8. In scope vs out of scope (summary)

**In scope:** any break of a §4 MUST goal under the §7 assumptions; any way a
single malicious validator or Nabla node exceeds its intended authority; any
non-determinism in consensus code; any reduction in the number of colluders
required for an attack.

**Out of scope:** compromised user devices; network-level attacks; resource-
disproportionate DoS; attacks requiring more collusion than the honest-quorum
assumption permits (documented as limitations); anything depending on
development-only build features.

---

## 9. Verifying these claims

Determinism and Core identity are externally checkable — see the "Verifying the
protocol yourself" section of [`SECURITY.md`](SECURITY.md). If you find a place
where the implementation does not match this model, that is exactly the kind of
report we want.
