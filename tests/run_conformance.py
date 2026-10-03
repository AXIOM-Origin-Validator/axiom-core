#!/usr/bin/env python3
"""
AXIOM Conformance Runner

Feeds consensus_vectors.json to any Core implementation that speaks the
CBOR stdin/stdout IPC protocol. A correct implementation produces
identical outputs for all vectors.

CL1-CL5 vectors test the full validation pipeline.
FACT vectors test money provenance.

See CONSENSUS_CRITICAL.md (repo root) for protocol boundary documentation.

Usage:
  python3 tests/run_conformance.py --core-bin ./core.bin
  python3 tests/run_conformance.py --core-bin ./core.bin --verbose
  python3 tests/run_conformance.py --vectors tests/consensus_vectors.json --core-bin ./core.bin
"""

import argparse
import json
import struct
import subprocess
import sys
from pathlib import Path


EXECUTABLE_MODES = {"CL1", "CL2", "CL3", "CL4", "CL5", "CL6", "CL7", "CL8", "CL10", "CL11"}
RESULT_MAP = {0: "Accept", 1: "Reject", 2: "Fatal"}


def run_vector(core_bin, inputs_hex, timeout=30):
    """Send CBOR inputs to core binary, return (result_int, rejection_code, raw_hex, output_map)."""
    input_bytes = bytes.fromhex(inputs_hex)
    frame = struct.pack(">I", len(input_bytes)) + input_bytes

    try:
        proc = subprocess.run(
            [core_bin],
            input=frame,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None, None, "TIMEOUT", None
    except Exception as e:
        return None, None, f"ERROR: {e}", None

    stdout = proc.stdout
    if len(stdout) < 4:
        return None, None, f"SHORT_OUTPUT({len(stdout)})", None

    resp_len = struct.unpack(">I", stdout[:4])[0]
    resp_bytes = stdout[4:4 + resp_len]

    # Parse CBOR output — minimal: read result field (key 0)
    try:
        import cbor2
        output = cbor2.loads(resp_bytes)
        result = output.get(0, -1)  # key 0 = result
        # PO_REJECT = 4 (core/ipc/src/codec.rs:247). This read key 15 until
        # 2026-08-01 — a key the outputs frame does not contain — so it was
        # always None; and main() unpacked the value and never compared it. The
        # rejection reason had therefore NEVER been checked by this runner.
        rejection = output.get(4, None)
        return result, rejection, resp_bytes.hex(), output
    except ImportError:
        # Fallback without cbor2 — return raw hex
        return None, None, resp_bytes.hex(), None


def accept_output_mismatches(vector, output):
    """KI#49 (b), 2026-10-01: an ACCEPT is judged by the state transition it
    produces, not by the word "Accept". Until this date the runner read only
    `result` and the rejection code, so an implementation that accepted with the
    WRONG produced_state_id or new_balance passed every Accept vector. Compares
    PO_PROD_SID (key 2) and PO_NEW_BAL (key 9) — `core/ipc/src/codec.rs` PO_* —
    against the values the generator pinned. Returns a list of mismatch notes."""
    notes = []
    exp_sid = vector.get("expected_produced_state_id_hex")
    got_sid = output.get(2)
    got_sid = got_sid.hex() if isinstance(got_sid, (bytes, bytearray)) else got_sid
    if exp_sid != got_sid:
        notes.append(f"produced_state_id expected {exp_sid} got {got_sid}")
    exp_bal = vector.get("expected_new_balance")
    got_bal = output.get(9)
    if exp_bal != got_bal:
        notes.append(f"new_balance expected {exp_bal} got {got_bal}")
    return notes


def main():
    parser = argparse.ArgumentParser(
        description="AXIOM conformance runner. Feeds consensus_vectors.json to any Core implementation.",
    )
    parser.add_argument("--vectors", default="tests/consensus_vectors.json",
                        help="Path to consensus_vectors.json")
    parser.add_argument("--core-bin", required=True,
                        help="Path to Core binary (CBOR stdin/stdout IPC)")
    parser.add_argument("--verbose", action="store_true",
                        help="Print raw CBOR hex on failure")
    parser.add_argument("--min-vectors", type=int, default=0,
                        help="Optional extra floor. The binding count is the corpus's own "
                             "`executable_vector_count` (always enforced, exact match); "
                             "the ceremony and dcheck pass no number of their own.")
    args = parser.parse_args()

    vectors_path = Path(args.vectors)
    if not vectors_path.exists():
        print(f"ERROR: {vectors_path} not found")
        sys.exit(1)

    with open(vectors_path) as f:
        suite = json.load(f)

    # KI#49 (e), 2026-10-01 — THE count floor is the corpus's own declaration.
    # The generator writes `executable_vector_count` (and refuses to emit a
    # corpus below its MIN_EXECUTABLE_VECTORS ratchet); the runner fails unless
    # EXACTLY that many execute. The ceremony and the D-check read this one value
    # instead of each carrying a number (theirs had drifted: 30 vs 28).
    declared = suite.get("executable_vector_count")
    if not isinstance(declared, int) or declared <= 0:
        print("ERROR: the corpus does not declare `executable_vector_count` — regenerate it")
        print("       (cargo run -p axiom-core-logic --example generate_vectors).")
        sys.exit(1)

    print(f"AXIOM Conformance Runner")
    print(f"  Vectors: {suite['vector_count']} ({suite['axiom_version']}), {declared} declared executable")
    print(f"  Core:    {args.core_bin}")
    print()

    passed = 0
    failed = 0
    skipped = 0

    for v in suite["vectors"]:
        vid = v["id"]
        mode = v["mode"]
        expected = v["expected_result"]

        if mode not in EXECUTABLE_MODES:
            print(f"  {vid:<40} skip ({mode} — verify manually)")
            skipped += 1
            continue

        inputs_hex = v.get("inputs_cbor_hex")
        if not inputs_hex:
            print(f"  {vid:<40} skip (no CBOR inputs)")
            skipped += 1
            continue

        result_int, rejection_code, raw_hex, output = run_vector(args.core_bin, inputs_hex)

        if result_int is None:
            print(f"  {vid:<40} ERROR: {raw_hex}")
            failed += 1
            continue

        result_str = RESULT_MAP.get(result_int, f"Unknown({result_int})")

        # Compare the REASON as well as the verdict. Two vectors that differ
        # only in why they were rejected are otherwise the same test — which is
        # how five vectors collapsed onto ChequeClaimProofMissing unnoticed
        # (KI#49). `expected_rejection_code` is the numeric wire discriminant,
        # emitted by the generator from the codec's own `ve_to_u64` so there is
        # no parallel name-to-code table here to drift.
        expected_code = v.get("expected_rejection_code")
        reason_ok = True
        reason_note = ""
        if expected_code is not None:
            reason_ok = (rejection_code == expected_code)
            if not reason_ok:
                reason_note = (f" [reason mismatch: expected {expected_code}"
                               f" ({v.get('expected_rejection_reason')})"
                               f" got {rejection_code}]")

        if result_str == expected == "Accept" and output is not None:
            mism = accept_output_mismatches(v, output)
            if mism:
                reason_ok = False
                reason_note = " [" + "; ".join(mism) + "]"

        if result_str == expected and reason_ok:
            print(f"  {vid:<40} PASS {result_str}")
            passed += 1
        else:
            if result_str != expected:
                print(f"  {vid:<40} FAIL expected {expected} got {result_str}{reason_note}")
            else:
                print(f"  {vid:<40} FAIL {result_str}{reason_note}")
            failed += 1
            if args.verbose:
                print(f"    inputs:  {inputs_hex[:80]}...")
                print(f"    outputs: {raw_hex[:80]}...")

    executed = passed + failed
    print()
    print(f"{passed}/{executed} executed vectors passed  ({skipped} skipped, {len(suite['vectors'])} total)")

    # FAIL CLOSED on a vacuous run. Skips never incremented `failed`, so a corpus
    # that stopped carrying `inputs_cbor_hex` — or a vectors file regenerated with
    # only non-executable modes — used to print "0/N passed (N skipped)" and exit 0.
    # A conformance gate that verifies nothing must not report success.
    if executed == 0:
        print()
        print("ERROR: 0 vectors were actually executed — every vector was skipped.")
        print("       This is a vacuous pass, not a conformance result. Check that")
        print("       consensus_vectors.json carries `inputs_cbor_hex` for executable")
        print("       modes (regenerate: cargo run -p axiom-core-logic --example generate_vectors).")
        sys.exit(1)

    if executed != declared:
        print()
        print(f"ERROR: {executed} vectors executed, the corpus declares {declared} executable.")
        print("       Fewer = vectors were skipped (a vacuous pass for them); more = the")
        print("       declaration is stale. Either way this is not a conformance result.")
        sys.exit(1)

    if args.min_vectors and executed < args.min_vectors:
        print()
        print(f"ERROR: only {executed} vectors executed, expected at least {args.min_vectors}.")
        print("       The corpus shrank — that is a regression in coverage, not a pass.")
        sys.exit(1)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
