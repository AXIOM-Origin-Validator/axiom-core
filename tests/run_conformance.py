#!/usr/bin/env python3
"""
AXIOM Conformance Runner

Feeds consensus_vectors.json to any Core implementation that speaks the
CBOR stdin/stdout IPC protocol. A correct implementation produces
identical outputs for all vectors.

CL1-CL5 vectors test the full validation pipeline.
FACT vectors test money provenance.
owner_proof vectors test the Ed25519 wallet protection mechanism.

See src/CONSENSUS_CRITICAL.md for protocol boundary documentation.

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


EXECUTABLE_MODES = {"CL1", "CL2", "CL3", "CL4", "CL5", "CL6", "CL7", "CL8", "CL9", "CL10", "CL11"}
RESULT_MAP = {0: "Accept", 1: "Reject", 2: "Fatal"}


def run_vector(core_bin, inputs_hex, timeout=30):
    """Send CBOR inputs to core binary, return (result_int, rejection_code, raw_hex)."""
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
        return None, None, "TIMEOUT"
    except Exception as e:
        return None, None, f"ERROR: {e}"

    stdout = proc.stdout
    if len(stdout) < 4:
        return None, None, f"SHORT_OUTPUT({len(stdout)})"

    resp_len = struct.unpack(">I", stdout[:4])[0]
    resp_bytes = stdout[4:4 + resp_len]

    # Parse CBOR output — minimal: read result field (key 0)
    try:
        import cbor2
        output = cbor2.loads(resp_bytes)
        result = output.get(0, -1)  # key 0 = result
        rejection = output.get(15, None)  # key 15 = rejection_reason (if present)
        return result, rejection, resp_bytes.hex()
    except ImportError:
        # Fallback without cbor2 — return raw hex
        return None, None, resp_bytes.hex()


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
    args = parser.parse_args()

    vectors_path = Path(args.vectors)
    if not vectors_path.exists():
        print(f"ERROR: {vectors_path} not found")
        sys.exit(1)

    with open(vectors_path) as f:
        suite = json.load(f)

    print(f"AXIOM Conformance Runner")
    print(f"  Vectors: {suite['vector_count']} ({suite['axiom_version']})")
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

        result_int, rejection_code, raw_hex = run_vector(args.core_bin, inputs_hex)

        if result_int is None:
            print(f"  {vid:<40} ERROR: {raw_hex}")
            failed += 1
            continue

        result_str = RESULT_MAP.get(result_int, f"Unknown({result_int})")

        if result_str == expected:
            print(f"  {vid:<40} PASS {result_str}")
            passed += 1
        else:
            print(f"  {vid:<40} FAIL expected {expected} got {result_str}")
            failed += 1
            if args.verbose:
                print(f"    inputs:  {inputs_hex[:80]}...")
                print(f"    outputs: {raw_hex[:80]}...")

    print()
    print(f"{passed}/{passed+failed+skipped} passed ({skipped} skipped)")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
