# Known Issues

This is the public, plain-language register of AXIOM's known security and
correctness limitations. It exists because we would rather you read our own
honest account of the edges than discover them yourself in production.

It complements [`SECURITY.md`](SECURITY.md) (how to report) and
[`THREAT_MODEL.md`](THREAT_MODEL.md) (what the protocol does and does not
defend against). **AXIOM is pre-mainnet and has not had an independent
third-party audit** — read every entry in that light.

> **Canonical register:** this file is the public, plain-language summary. The
> authoritative engineering register — per-issue blast radius, fix sketches,
> commit anchors, the numbered `KI#…` items, and the mainnet-blocking items from
> the 2026-06-12 trust-boundary security review (KI#30 soft supply cap, KI#31
> Silicon Pulse) — lives at
> [`docs/AXIOM_REPORT_KnownIssues.md`](docs/AXIOM_REPORT_KnownIssues.md). Where
> the two differ on detail or severity, the engineering register is canonical;
> this file links to it rather than duplicating severities.

If you find something not listed here, or you can lower the assumptions an entry
relies on, please report it (see `SECURITY.md`). That is exactly the kind of
contribution we want.

---

## How to read this

**Severity** — worst-case impact if the issue is realized:

- **Critical** — incorrect minting/destruction of value, or theft, under the
  protocol's stated assumptions.
- **High** — monetary-integrity or consensus impact that requires an additional
  condition (a malicious validator, a malicious gossip node, a patched client).
- **Medium** — weakens a defense, enables griefing/denial, or trusts the wrong
  layer, without directly moving value.
- **Low / Latent** — no current exploit; a hazard that becomes real only if a
  currently-dead or gated code path is wired up.

**Status:**

- **Open (design)** — a real gap whose fix is a design decision, not yet made.
- **Open (fix planned)** — understood, with a concrete planned fix.
- **Gated** — lives in an experimental subsystem that is disabled / unwired and
  must not be enabled in production until hardened.
- **Accepted** — a deliberate trade-off with a documented mitigation.
- **Resolved** — fixed; listed for transparency.

The `SEC-NN` identifiers map to the project's internal security review.

---

## Open — consensus & monetary integrity

### SEC-01 — Colluding overlapped validators can mint value
**Severity: High–Critical · Status: Open (design)**

Core is stateless: it validates the *consistency* of the inputs it is given but
has no independent memory of a wallet's history. The witness quorum relies on at
least one honest *overlapped* validator holding the wallet's true prior state. If
all overlapped validators for a transaction collude **and** the client
cooperates, they can present Core with a consistent fabricated balance; because
every colluder "refills" the same lie, the cross-validator state hashes agree and
an honest non-overlapped validator signs in good faith. The result is fabricated
supply (inflation), not merely a local double-spend.

This is the deepest structural tension in the protocol and it is currently
**unmitigated**. It only fires when the honest-quorum assumption fails for the
*overlapped* set specifically. The leading planned mitigation is a per-wallet
history commitment that Core verifies, so a fabricated prior balance would
require forging committed history rather than colluding on a single round. See
`THREAT_MODEL.md` §5 for the full argument and its limit.

### SEC-02 — Aggregate supply cap is not enforced at the mint
**Severity: High · Status: Open (fix planned)**

The fixed-supply ceiling (the genesis pool caps) is currently tracked by the
Nabla accounting layer rather than enforced inside Core at the moment value is
minted. Core *does* enforce the per-wallet one-shot rule (a wallet cannot claim
genesis twice), but the *aggregate* ceiling is bookkeeping that runs after the
witness round that produces the claimable value — so a patched client can ignore
it. Each distinct claim still requires a real witness round and a distinct
wallet identity, so this is not free unlimited minting, but the hard ceiling is
advisory rather than cryptographically enforced at the mint.

Planned fix: a quorum-signed pool-state attestation that Core consumes at redeem,
making the mint itself depend on the pool having admitted the claim.

### SEC-03 — Pool-accounting gossip: soft-auth path and unbounded counter
**Severity: High · Status: Open (fix planned)**

Pool-accounting gossip between Nabla nodes can be processed on a path that skips
signature verification when the sender's certificate is not yet known, and one of
the merged counters is combined with no magnitude bound. A single malicious or
unauthenticated node can therefore inflate that counter and cause honest nodes to
stop funding legitimate genesis claims mesh-wide (a griefing / availability
attack), and poison the very counter the supply cap depends on. It cannot
directly raise a balance (balances merge monotonically downward).

Planned fix: remove the unauthenticated path and bound the counter merge to a
per-tick maximum.

### SEC-04 — Certificate chain-of-trust verified only on the last witness
**Severity: Medium–High · Status: Open (under review)**

For performance, Core fully verifies the validator birth-certificate chain only
on the *last* witness in a prior-receipt set, relying on the assumption that the
other witnesses' certificates were verified by the validators that signed after
them. Under a model where a malicious validator can craft the prior-receipt set
directly, this is weaker than full verification. The live transaction path
re-verifies overlapping witnesses through a separate gate, so reachability of an
actual exploit is being confirmed before the optimization is removed or
re-scoped.

### SEC-07 — Post-compression provenance rests on fewer signatures
**Severity: Medium · Status: Open (review)**

Once a wallet's provenance chain is compressed to a checkpoint, the discarded
links cannot be re-verified by design (lossy compression). The remaining tie to
reality is the checkpoint signature(s). We are reviewing whether the checkpoint
must carry the full witness quorum rather than fewer signatures, so that no
single validator can unilaterally emit an accepted checkpoint.

### SEC-08 — Judicial-freeze propagation is not quorum-adjudicated
**Severity: Medium · Status: Open (fix planned)**

The administrative freeze mechanism is enforced locally by Core, but its
propagation across the network currently uses an unauthenticated path rather than
a quorum-signed authority verdict. The freeze action itself is gated behind an
operator-authenticated admin endpoint (not reachable by an external client), so
the gap is that a single operator — or a compromised admin credential — can
propagate a freeze without quorum. Planned fix: a quorum-witnessed verdict that
the network requires before accepting the freeze.

### SEC-10 — Certificate expiry/maturity checked outside the sole authority
**Severity: Medium · Status: Open (fix planned)**

Two time/identity checks on the certificate chain-of-trust — issuer-certificate
expiry and issuer maturity — are currently enforced by the validator layer rather
than inside Core. Since Core is meant to be the backstop, a malicious validator
presenting an expired or immature issuer chain is a gap. Planned fix: move both
checks into Core's chain walk, using Core's trusted launch-time clock (taking
care that the time input remains consensus-safe across validators).

---

## Gated — experimental subsystems (must not be enabled in production)

These are not security-reviewed and are disabled or unwired. They are listed so
nobody mistakes "present in the tree" for "production-ready."

### SEC-05 — Contribution-credit scores are self-reported
**Severity: Latent (Critical if wired) · Status: Gated**

The contribution-credit score that would drive a future reward pool is currently
self-reported and self-signed by each node, with no peer attestation. It is
harmless today because the reward path is not wired (the pool balance is zero and
the distribution code has no production caller). It **must not** be connected to
any payout until the counts are quorum-attested. The reward path should fail
closed until then.

### SEC-06 — A signature-skipping certificate helper exists
**Severity: Latent · Status: Gated (test-only)**

A helper that validates a certificate chain *structurally* without verifying
signatures exists for testing. Because the root keys are public constants, this
helper would accept a forged chain if it were ever called on untrusted input. It
currently has no production caller. It is being renamed/type-gated so it cannot
be wired onto an untrusted path by accident.

### SEC-09 — Oracle stake adoption is unverified
**Severity: Medium (bounded) · Status: Gated**

The oracle transaction path adopts some node-supplied role/state fields without
full re-verification and hard-codes one input. This is bounded because the oracle
subsystem is disabled (`OracleConfig.enabled = false`) and the path concerns a
validator's own attestation. It must be hardened — and the related oracle design
gaps closed — before the oracle is enabled.

### SEC-16 — Sparse-merkle-tree proofs need hardening before any trust role
**Severity: Latent · Status: Gated (advisory)**

The Nabla sparse-merkle-tree has construction issues (no leaf/internal domain
separation, proof depth taken from untrusted input, inclusion not distinguished
from non-inclusion). This is harmless today because no trust-bearing decision
consumes these proofs. They must be reworked before the tree is ever promoted to
a trust anchor.

---

## Accepted risks & inherent limitations

These are deliberate trade-offs or properties of the design, with mitigations.

- **Genesis-key compromise is catastrophic.** A compromised genesis/root key
  could create a divergent valid worldline; honest nodes fail closed (halt)
  rather than accept an ambiguous reality. This is an out-of-band trust
  assumption, not a runtime defense. *(Severity: Critical if it occurs; mitigated
  only by genesis ceremony integrity.)*
- **PGP plaintext fallback.** Cheque-bearing emails are encrypted to recipients
  with published OpenPGP keys, with a plaintext fallback for those without. The
  cheque content is then visible to the mail provider. Cheques are not
  protocol-secret, and delivery tracks an `encrypted` flag. *(Accepted.)*
- **In-memory claim tracking.** Some anti-replay claim tracking is in memory; a
  restart can permit a small, bounded number of extra claims. *(Accepted —
  negligible economic impact; durable pool state is persisted separately.)*
- **Core-ID pinning not yet activated.** Pinning the canonical Core identity in
  clients requires the genesis ceremony digest; deferred until that is fixed.
  *(Deferred.)*
- **Anonymity / coercion-resistance are best-effort.** These properties depend on
  validators running the full stack and on economic incentives; they degrade if
  participants run minimal implementations. Only transaction *correctness* (no
  theft / double-spend / inflation) is cryptographically guaranteed. See
  `THREAT_MODEL.md` §4.
- **Development build features are unsafe.** Builds using `disable-audit` or
  `dev-mode` skip protections and must never be used in production.

---

## Latent hardening items

Low-risk items with no current exploit, tracked for cleanliness:

- **SEC-11 — A checkpoint amount field is not bound into its commitment and uses
  unchecked addition.** Currently never read for any economic decision; will be
  bound + overflow-checked, or removed.
- **Signature-hygiene items** — switching to strict signature verification and
  forcing explicit algorithms at certain verification sites (defense-in-depth;
  currently defended by context).
- **Dead-code removal** — a few unused validation/fallback helpers that could
  mislead a reader about where a check actually lives.

---

## Resolved (selected)

Listed for transparency — issues found and fixed during development:

- **Transaction-field signature binding.** All security-critical fields
  (including sender identity, amount, and protocol version) are now bound into
  the client signature, preventing field-substitution and cross-network replay.
- **Redeem-path signature verification.** The redeem path now verifies every
  cheque signature and rejects mixed-class bundles.
- **State-anchoring gate.** Validators reject any transaction whose claimed state
  does not re-derive to the previously quorum-signed receipt, and the redeem path
  no longer falls back to zero-state on missing data — closing a class of
  cross-validator divergence.
- **Underflow handling.** Balance arithmetic uses checked operations; a prior
  saturating-subtraction that could swallow an underflow was removed.
- **Genesis double-claim.** A wallet cannot claim genesis value twice (one-shot
  replay check enforced inside Core).

---

*This register is maintained on a best-effort basis and reflects the project's
current understanding. It is not a guarantee of completeness.*
