#!/usr/bin/env bash
# Build axiom-core.elf (RISC-V RV32IM) and compute its CoreID.
#
# Requires: Rust with riscv32im-unknown-none-elf target
#   rustup target add riscv32im-unknown-none-elf
#
# Usage:
#   scripts/build-core-elf.sh                    # build to artifacts/
#   scripts/build-core-elf.sh --output /path/    # build to custom path
#   scripts/build-core-elf.sh --verify <coreid>  # build and verify CoreID matches

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
GUEST_DIR="$SRC_DIR/avm-guest"
TARGET="riscv32im-unknown-none-elf"
OUTPUT_DIR="$SRC_DIR/artifacts"
VERIFY_ID=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --verify)
            VERIFY_ID="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--output <dir>] [--verify <coreid>]"
            echo ""
            echo "Build axiom-core.elf and compute CoreID (BLAKE3 hash)."
            echo ""
            echo "Options:"
            echo "  --output <dir>     Output directory (default: artifacts/)"
            echo "  --verify <coreid>  Verify CoreID matches after build"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check target is installed
if ! rustup target list --installed | grep -q "$TARGET"; then
    echo "ERROR: Rust target $TARGET not installed."
    echo "Install with: rustup target add $TARGET"
    exit 1
fi

# Detect dev/testnet WALLET_IDENTITY_KEY (0xb0, 0xf7 prefix). Release builds
# of axiom-core-logic fail-compile while the dev key is in place; the
# `dev-mode` feature disables that compile guard. Auto-pass it for dev builds
# so the script DTRT on testnet without requiring a manual flag, and skip it
# on a post-ceremony tree so mainnet builds stay strict.
WALLET_KEY_FILE="$SRC_DIR/core/logic/src/wallet_id.rs"
EXTRA_FEATURES=""
BUILD_MODE="mainnet"
if grep -qE '^\s*0xb0,\s*0xf7,' "$WALLET_KEY_FILE"; then
    EXTRA_FEATURES="--features axiom-core-logic/dev-mode"
    BUILD_MODE="dev (WALLET_IDENTITY_KEY still 0xb0,0xf7 — pre-ceremony)"
fi

echo "Building axiom-core.elf..."
echo "  Guest: $GUEST_DIR"
echo "  Target: $TARGET"
echo "  Mode:   $BUILD_MODE"

# Build the RISC-V guest
cd "$GUEST_DIR"
cargo build --target "$TARGET" --release $EXTRA_FEATURES 2>&1

# Find the built binary
BUILT="$GUEST_DIR/target/$TARGET/release/axiom-avm-guest"
if [ ! -f "$BUILT" ]; then
    echo "ERROR: Build succeeded but ELF not found at $BUILT"
    exit 1
fi

# Compute CoreID of the just-built binary BEFORE publishing anywhere.
# Bug fix 2026-06-07: previously the script wrote artifacts/{elf,
# CORE_ID.txt} AND the runtime copy BEFORE verifying, so a failed
# `--verify` clobbered the canonical artifact and required
# `git checkout -- artifacts/` to recover. Now: build → compute →
# verify → publish, so a verify mismatch leaves on-disk state
# unchanged.
SIZE=$(du -h "$BUILT" | cut -f1)
echo "Built (staging): $BUILT ($SIZE)"

# Compute CoreID = BLAKE3(elf_bytes)
# Use a small inline Rust program since b3sum may not be installed
CORE_ID=$(cd "$SRC_DIR" && cargo run -q --example compute_core_id -- "$BUILT" 2>/dev/null || true)

# Fallback: if the example doesn't exist, use b3sum if available
if [ -z "$CORE_ID" ]; then
    if command -v b3sum &>/dev/null; then
        CORE_ID=$(b3sum --no-names "$BUILT")
    else
        # Last resort: compute via Python with blake3 or just hash the file
        echo "ERROR: Cannot compute CoreID (no b3sum or compute_core_id example)."
        echo "Install b3sum: cargo install b3sum"
        echo "Or run: cargo run --example compute_core_id -- $BUILT"
        exit 1
    fi
fi

# Strip any whitespace/newlines the computers may have appended so the
# string equality below isn't tripped by a trailing \n.
CORE_ID="${CORE_ID//[[:space:]]/}"
echo "CoreID: $CORE_ID"

# Verify BEFORE writing anywhere. Mismatch → hard exit nonzero, no
# committed artifact disturbed.
if [ -n "$VERIFY_ID" ]; then
    VERIFY_ID="${VERIFY_ID//[[:space:]]/}"
    if [ "$CORE_ID" != "$VERIFY_ID" ]; then
        echo "" >&2
        echo "CoreID MISMATCH! Refusing to publish." >&2
        echo "  Expected: $VERIFY_ID" >&2
        echo "  Got:      $CORE_ID"  >&2
        echo "" >&2
        echo "Common causes:" >&2
        echo "  - Cross-host build non-determinism (e.g. panic_handler" >&2
        echo "    file!() absolute paths differ between machines)." >&2
        echo "  - Toolchain delta (rustc / LLVM / target version)." >&2
        echo "  - Source not pulled to canonical commit before rebuild." >&2
        echo "" >&2
        echo "artifacts/ was NOT modified — your committed canonical" >&2
        echo "ELF is intact. Ship the canonical bytes directly if you" >&2
        echo "cannot reproduce them locally." >&2
        exit 1
    fi
    echo "CoreID matches canonical"
fi

# Verification passed (or none requested) — publish artifacts.
mkdir -p "$OUTPUT_DIR"
ELF_OUT="$OUTPUT_DIR/axiom-core.elf"
cp "$BUILT" "$ELF_OUT"
echo "Published: $ELF_OUT"

# Also publish to the runtime path that scripts/axiom-env.py loads first
# (ELF_PATH = avm-guest/target/axiom-core.elf). Without this
# copy a freshly-built ELF goes to artifacts/ but the env keeps loading
# the stale runtime copy — exactly the trap behind the "ALWAYS rebuild
# ELF after core-logic changes" invariant.
RUNTIME_ELF="$GUEST_DIR/target/axiom-core.elf"
cp "$BUILT" "$RUNTIME_ELF"
echo "Published runtime: $RUNTIME_ELF"

# Write CORE_ID.txt (no trailing whitespace).
printf '%s\n' "$CORE_ID" > "$OUTPUT_DIR/CORE_ID.txt"
echo "Written: $OUTPUT_DIR/CORE_ID.txt"

echo ""
echo "To set as canonical for release builds:"
echo "  export AXIOM_CANONICAL_CORE_ID=$CORE_ID"
