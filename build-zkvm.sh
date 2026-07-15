#!/bin/bash
#
# Build AXIOM zkVM Guest for RISC Zero
#
# This script:
# 1. Builds the zkvm-guest crate targeting RISC-V (RISC Zero guest)
# 2. Extracts the IMAGE_ID (program digest)
# 3. Places artifacts in ~/.axiom/zkvm/
#
# Prerequisites:
#   - RISC Zero toolchain: curl -L https://risczero.com/install | bash && rzup install
#   - Docker (for reproducible builds) OR --local flag for local toolchain
#
# Usage:
#   ./build-zkvm.sh              # Build with Docker (reproducible)
#   ./build-zkvm.sh --local      # Build with local toolchain (no Docker)
#   ./build-zkvm.sh --check      # Just check if toolchain is installed
#   ./build-zkvm.sh --debug      # Show extra debug info
#

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GUEST_DIR="$SCRIPT_DIR/zkvm-guest/guest"
OUTPUT_DIR="${HOME}/.axiom/zkvm"
DEBUG_MODE=false
LOCAL_BUILD=false
DEV_MODE=false
# When --dev is passed, enable axiom-core-logic/dev-mode so the build does NOT
# trip the G1 mainnet-ceremony compile guard (WALLET_IDENTITY_KEY assert). This
# produces a DEV-KEY zkVM, consistent with a dev env's dev Core — NEVER for
# production (a real release must build against the ceremony key, no dev-mode).
DEV_FEAT=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse args
for arg in "$@"; do
    case $arg in
        --debug)
            DEBUG_MODE=true
            ;;
        --local)
            LOCAL_BUILD=true
            ;;
        --dev|--dev-mode)
            DEV_MODE=true
            DEV_FEAT="--features axiom-core-logic/dev-mode"
            ;;
        --check)
            # Will be handled in main
            ;;
    esac
done

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║           AXIOM zkVM Guest Builder                            ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
if [ "$DEV_MODE" = true ]; then
    echo -e "${YELLOW}⚠  --dev: building with axiom-core-logic/dev-mode (DEV-KEY zkVM).${NC}"
    echo -e "${YELLOW}   Bypasses the G1 ceremony guard. For a dev env only — NEVER a production release.${NC}"
    echo ""
fi

# Check for RISC Zero toolchain
check_toolchain() {
    echo "Checking RISC Zero toolchain..."
    
    # Check cargo-risczero
    if ! command -v cargo-risczero &> /dev/null; then
        echo -e "${RED}✗ cargo-risczero not found${NC}"
        echo ""
        echo "Install RISC Zero toolchain:"
        echo "  curl -L https://risczero.com/install | bash"
        echo "  rzup install"
        return 1
    fi
    
    RISC0_VERSION=$(cargo risczero --version 2>/dev/null || echo "unknown")
    echo -e "${GREEN}✓ cargo-risczero found: $RISC0_VERSION${NC}"
    
    # Check Docker unless --local
    if [ "$LOCAL_BUILD" = false ]; then
        if command -v docker &> /dev/null && docker info &> /dev/null 2>&1; then
            echo -e "${GREEN}✓ Docker available and running${NC}"
        else
            echo -e "${YELLOW}! Docker not available or not running${NC}"
            echo ""
            echo "  RISC Zero requires Docker for reproducible builds."
            echo ""
            echo "  Options:"
            echo "    1. Install Docker Desktop: brew install --cask docker"
            echo "       Then start Docker Desktop and run this script again"
            echo ""
            echo "    2. Use local build (may have different IMAGE_ID):"
            echo "       ./build-zkvm.sh --local"
            echo ""
            return 1
        fi
    fi
    
    # For local builds, check RISC-V target
    if [ "$LOCAL_BUILD" = true ]; then
        echo "  Using local toolchain (no Docker)"
        if ! rustup target list --installed | grep -q "riscv32im"; then
            echo -e "${YELLOW}! RISC-V target not installed, installing...${NC}"
            rustup target add riscv32im-unknown-none-elf || {
                echo -e "${RED}✗ Failed to add RISC-V target${NC}"
                return 1
            }
        fi
        echo -e "${GREEN}✓ RISC-V target available${NC}"
    fi
    
    return 0
}

# Build the guest
build_guest() {
    echo ""
    echo "Building zkVM guest..."
    echo "  Source: $GUEST_DIR"
    echo "  Mode: $([ "$LOCAL_BUILD" = true ] && echo "Local toolchain" || echo "Docker")"
    
    cd "$GUEST_DIR"
    
    # Show help for reference
    if [ "$DEBUG_MODE" = true ]; then
        echo -e "${BLUE}cargo risczero build --help:${NC}"
        cargo risczero build --help 2>&1 || true
        echo ""
    fi
    
    # Build based on mode
    if [ "$LOCAL_BUILD" = true ]; then
        # Local build without Docker
        echo "  Attempting local build..."
        
        # For risc0 3.x, we need to use the r0vm toolchain
        # First check if rzup installed the proper toolchain
        echo "  Checking for risc0 toolchain..."

        # Build with real RISC Zero toolchain — no dev mode, no mock proofs
        echo "  Running: RUSTFLAGS='--cfg getrandom_backend=\"custom\"' cargo +risc0 build --release --target riscv32im-risc0-zkvm-elf"
        echo "  (This may take several minutes on first run...)"
        echo ""

        # Run with verbose output — getrandom_backend="custom" required for risc0-zkvm-platform
        RUSTFLAGS='--cfg getrandom_backend="custom"' cargo +risc0 build --release --target riscv32im-risc0-zkvm-elf $DEV_FEAT 2>&1 | tee /tmp/zkvm-build.log
        BUILD_RESULT=${PIPESTATUS[0]}
        
        echo ""
        echo "  Build exit code: $BUILD_RESULT"
        
        # Check if log is empty
        if [ ! -s /tmp/zkvm-build.log ]; then
            echo "  (No build output captured)"
        fi
        
        if [ $BUILD_RESULT -ne 0 ]; then
            echo -e "${YELLOW}! cargo risczero build failed (exit code $BUILD_RESULT)${NC}"
            echo ""
            echo "Build log:"
            cat /tmp/zkvm-build.log
            echo ""
            
            # Fallback: Try cargo risczero build (Docker-based)
            if command -v cargo-risczero &> /dev/null; then
                echo "  Trying: cargo risczero build (may use Docker)..."
                cargo risczero build > /tmp/zkvm-build.log 2>&1
                BUILD_RESULT=$?
            fi
            
            if [ $BUILD_RESULT -ne 0 ]; then
                echo -e "${RED}✗ Local build failed${NC}"
                echo ""
                echo "Build output:"
                cat /tmp/zkvm-build.log
                echo ""
                echo "Options:"
                echo "  1. Install Docker and run without --local flag (recommended)"
                echo "  2. Check if risc0 toolchain is properly installed: rzup --version"
                echo ""
                return 1
            fi
        fi
        echo -e "${GREEN}✓ Build completed (local)${NC}"
    else
        # Docker build (default, reproducible)
        echo "  Running: cargo risczero build"
        
        # Capture output and exit code separately
        cargo risczero build > /tmp/zkvm-build.log 2>&1
        BUILD_RESULT=$?
        
        if [ $BUILD_RESULT -ne 0 ]; then
            echo -e "${RED}✗ Build failed (exit code: $BUILD_RESULT)${NC}"
            echo ""
            cat /tmp/zkvm-build.log
            
            # Check for specific errors
            if grep -qi "docker" /tmp/zkvm-build.log; then
                echo ""
                echo -e "${YELLOW}Docker appears to be required but not working.${NC}"
                echo ""
                echo "To fix:"
                echo "  1. Install Docker Desktop: brew install --cask docker"
                echo "  2. Start Docker Desktop application"
                echo "  3. Wait for Docker to fully start (whale icon stops animating)"
                echo "  4. Run this script again"
                echo ""
                echo "Or try: ./build-zkvm.sh --local"
            fi
            return 1
        fi
        echo -e "${GREEN}✓ Build completed (Docker)${NC}"
    fi
    
    # Show build output if debug
    if [ "$DEBUG_MODE" = true ]; then
        echo -e "${BLUE}Build output:${NC}"
        cat /tmp/zkvm-build.log
        echo ""
    fi
    
    # Debug: show target directory structure
    echo "  Searching for ELF file..."
    
    if [ "$DEBUG_MODE" = true ]; then
        echo -e "${BLUE}Target directory structure:${NC}"
        find "$GUEST_DIR/target" -type f 2>/dev/null | grep -v "\.d$" | grep -v "\.rlib$" | grep -v "\.rmeta$" | head -30 || echo "  (no files found)"
        echo ""
    fi
    
    # Find the ELF file - check multiple possible locations
    # Try common paths for risc0 output
    POSSIBLE_PATHS=(
        # Docker build paths
        "$GUEST_DIR/target/riscv-guest/riscv32im-risc0-zkvm-elf/docker/axiom-zkvm-guest"
        "$GUEST_DIR/target/riscv-guest/riscv32im-risc0-zkvm-elf/docker/axiom_zkvm_guest"
        # Release build paths  
        "$GUEST_DIR/target/riscv-guest/riscv32im-risc0-zkvm-elf/release/axiom-zkvm-guest"
        "$GUEST_DIR/target/riscv-guest/riscv32im-risc0-zkvm-elf/release/axiom_zkvm_guest"
        # risc0 3.x paths
        "$GUEST_DIR/target/riscv32im-risc0-zkvm-elf/docker/axiom-zkvm-guest"
        "$GUEST_DIR/target/riscv32im-risc0-zkvm-elf/docker/axiom_zkvm_guest"
        "$GUEST_DIR/target/riscv32im-risc0-zkvm-elf/release/axiom-zkvm-guest"
        "$GUEST_DIR/target/riscv32im-risc0-zkvm-elf/release/axiom_zkvm_guest"
        # Standard RISC-V paths (fallback)
        "$GUEST_DIR/target/riscv32im-unknown-none-elf/release/axiom-zkvm-guest"
        "$GUEST_DIR/target/riscv32im-unknown-none-elf/release/axiom_zkvm_guest"
        # risc0 method crate output
        "$GUEST_DIR/target/release/axiom-zkvm-guest"
    )
    
    ELF_PATH=""
    for path in "${POSSIBLE_PATHS[@]}"; do
        if [ -f "$path" ]; then
            ELF_PATH="$path"
            echo "  Found at: $path"
            break
        fi
    done
    
    # If not found in known paths, search for it
    if [ -z "$ELF_PATH" ]; then
        echo "  Searching target directory..."
        ELF_PATH=$(find "$GUEST_DIR/target" -type f \( -name "axiom-zkvm-guest" -o -name "axiom_zkvm_guest" \) 2>/dev/null | grep -v "\.d$" | grep -v "\.rlib$" | head -1)
    fi
    
    # Try looking for any ELF file in riscv paths
    if [ -z "$ELF_PATH" ]; then
        echo "  Looking for any RISC-V ELF..."
        ELF_PATH=$(find "$GUEST_DIR/target" -path "*riscv*" -type f ! -name "*.d" ! -name "*.rlib" ! -name "*.rmeta" ! -name "*.o" ! -name "*.json" 2>/dev/null | head -1)
    fi
    
    # Last resort: look for any binary that might be the guest
    if [ -z "$ELF_PATH" ]; then
        echo "  Last resort: searching all binaries..."
        ELF_PATH=$(find "$GUEST_DIR/target" -type f -executable ! -name "*.d" ! -name "*.rlib" 2>/dev/null | xargs file 2>/dev/null | grep -i "elf\|risc" | head -1 | cut -d: -f1)
    fi
    
    if [ -z "$ELF_PATH" ]; then
        echo -e "${RED}✗ Could not find built ELF file${NC}"
        echo ""
        echo "Build appeared to succeed but no ELF found."
        echo ""
        echo "Target directory contents:"
        ls -laR "$GUEST_DIR/target/" 2>/dev/null | head -50 || echo "  (target dir doesn't exist)"
        echo ""
        echo "This might mean:"
        echo "  1. The risc0 toolchain didn't produce an ELF (dev mode?)"
        echo "  2. The build output went somewhere unexpected"
        echo ""
        echo "Try running with --debug for more info"
        return 1
    fi
    
    echo -e "${GREEN}✓ Guest built: $ELF_PATH${NC}"
    
    # Verify it's an ELF file
    FILE_TYPE=$(file "$ELF_PATH" 2>/dev/null || echo "unknown")
    if echo "$FILE_TYPE" | grep -qi "ELF"; then
        echo -e "${GREEN}✓ Verified as ELF binary${NC}"
        if [ "$DEBUG_MODE" = true ]; then
            echo "  $FILE_TYPE"
        fi
    else
        echo -e "${YELLOW}! File type: $FILE_TYPE${NC}"
    fi
    
    # Store for later
    BUILT_ELF="$ELF_PATH"
}

# Extract IMAGE_ID
# Install artifacts
install_artifacts() {
    echo ""
    echo "Installing artifacts to $OUTPUT_DIR..."
    
    mkdir -p "$OUTPUT_DIR"
    
    # Bake raw ELF into R0BF format (required by RISC Zero prover)
    # The bake-elf tool bundles user ELF + kernel ELF and computes IMAGE_ID
    echo "  Baking raw ELF into R0BF format..."

    BAKE_ELF_BIN="$SCRIPT_DIR/../target/release/bake-elf"
    if [ ! -f "$BAKE_ELF_BIN" ]; then
        echo "  Building bake-elf tool..."
        cargo build --release -p axiom-zk-vm --features verify $DEV_FEAT --bin bake-elf \
            --manifest-path "$SCRIPT_DIR/../Cargo.toml" 2>&1 | tee -a /tmp/zkvm-build.log
        if [ $? -ne 0 ]; then
            echo -e "${RED}✗ Failed to build bake-elf tool${NC}"
            return 1
        fi
    fi

    "$BAKE_ELF_BIN" "$BUILT_ELF" "$OUTPUT_DIR/axiom-core.elf" 2>&1 | tee -a /tmp/zkvm-build.log
    if [ $? -ne 0 ]; then
        echo -e "${RED}✗ Failed to bake ELF into R0BF format${NC}"
        return 1
    fi
    echo -e "${GREEN}✓ Installed axiom-core.elf (R0BF format)${NC}"

    # Compute IMAGE_ID from baked R0BF
    echo "  Computing IMAGE_ID..."
    COMPUTE_ID_BIN="$SCRIPT_DIR/../target/release/compute-image-id"
    if [ ! -f "$COMPUTE_ID_BIN" ]; then
        echo "  Building compute-image-id tool..."
        cargo build --release -p axiom-zk-vm --features verify $DEV_FEAT --bin compute-image-id \
            --manifest-path "$SCRIPT_DIR/../Cargo.toml" 2>&1 | tee -a /tmp/zkvm-build.log
    fi

    IMAGE_ID=$("$COMPUTE_ID_BIN" "$OUTPUT_DIR/axiom-core.elf" 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1)
    if [ -z "$IMAGE_ID" ]; then
        echo -e "${RED}✗ Failed to compute IMAGE_ID from R0BF${NC}"
        return 1
    fi

    # Write IMAGE_ID
    echo "$IMAGE_ID" > "$OUTPUT_DIR/image-id.hex"
    echo -e "${GREEN}✓ Installed image-id.hex${NC}"
    echo -e "${GREEN}✓ IMAGE_ID: $IMAGE_ID${NC}"

    # Create README
    cat > "$OUTPUT_DIR/README.md" << 'EOF'
# AXIOM zkVM Artifacts

These files are required for Lambda to start. No dev mode — all proofs are real STARK proofs.

## Files

- `axiom-core.elf` - The compiled zkVM guest (R0BF format: user ELF + kernel ELF)
- `image-id.hex` - The program digest (32 bytes, hex encoded)

## Usage

Lambda loads these at startup and fails hard if they are missing:

```bash
lambda --config config.toml
```

## Rebuilding

```bash
cd axiom/src/core
./build-zkvm.sh --local
```

## Environment Variables

Custom paths:

```bash
export AXIOM_ZKVM_ELF=/path/to/axiom-core.elf
export AXIOM_ZKVM_IMAGE_ID=/path/to/image-id.hex
```
EOF
    echo -e "${GREEN}✓ Created README.md${NC}"
}

# Main
main() {
    if [ "$1" == "--check" ]; then
        check_toolchain
        exit $?
    fi
    
    if ! check_toolchain; then
        exit 1
    fi
    
    build_guest
    install_artifacts

    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                    BUILD COMPLETE                             ║"
    echo "╠═══════════════════════════════════════════════════════════════╣"
    echo "║  Artifacts installed to: ~/.axiom/zkvm/                       ║"
    echo "║  All proofs are real RISC Zero STARK proofs. No dev mode.    ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
}

main "$@"
