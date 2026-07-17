# AXIOM System Requirements

This document lists all dependencies required to build, test, and run AXIOM components.

## Quick Install (macOS)

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Python packages (for testing tools)
pip3 install pynacl blake3

# Optional: for development
brew install protobuf
```

## Quick Install (Ubuntu/Debian)

```bash
# System packages (libclang-dev is required by bindgen when building the
# OpenSSL-linked crates: antie, the UNCLE stack, sdk/ffi)
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev libclang-dev

# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Python packages (for testing tools)
pip3 install pynacl blake3
```

---

## Detailed Requirements

### 1. Rust Toolchain (Required)

**Version:** 1.75+ (stable)

```bash
# Install
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Verify
rustc --version
cargo --version
```

**Components needed:**
- `rustc` - Rust compiler
- `cargo` - Package manager
- `clippy` - Linter (optional, for development)
- `rustfmt` - Formatter (optional, for development)

```bash
# Install optional components
rustup component add clippy rustfmt
```

---

### 2. Python 3 (Required for testing)

**Version:** 3.8+

```bash
# Verify
python3 --version
pip3 --version
```

**Required Python packages:**

| Package | Version | Purpose |
|---------|---------|---------|
| `pynacl` | ≥1.5.0 | Ed25519 signing for test transactions |
| `blake3` | ≥0.3.0 | BLAKE3 hashing for wallet_id checksum |

```bash
# Install
pip3 install pynacl blake3

# Or with user flag if permission issues
pip3 install --user pynacl blake3
```

**Verify installation:**
```python
python3 -c "import nacl; print('PyNaCl:', nacl.__version__)"
python3 -c "import blake3; print('blake3: OK')"
```

---

### 3. System Libraries (Build dependencies)

#### macOS

```bash
# Xcode command line tools (provides clang, make, etc.)
xcode-select --install

# OpenSSL (usually pre-installed)
brew install openssl
```

#### Ubuntu/Debian

```bash
sudo apt install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libclang-dev
```

#### Fedora/RHEL

```bash
sudo dnf install -y \
    gcc \
    gcc-c++ \
    make \
    pkg-config \
    openssl-devel \
    clang-devel
```

---

### 4. Optional Dependencies

#### For zkVM/RISC Zero (Future)

```bash
# RISC Zero toolchain
cargo install cargo-risczero
cargo risczero install
```

#### For Protocol Buffers (If using gRPC)

```bash
# macOS
brew install protobuf

# Ubuntu/Debian
sudo apt install -y protobuf-compiler

# Verify
protoc --version
```

#### For Database Tools

```bash
# SQLite (for debugging Lambda storage)
# macOS
brew install sqlite

# Ubuntu/Debian
sudo apt install -y sqlite3
```

---

## Runtime Requirements

### Lambda Server

| Requirement | Details |
|-------------|---------|
| Memory | Minimum 512MB, recommended 2GB |
| Disk | 1GB for state database |
| Network | TCP port (default 9123) |
| OS | Linux, macOS, Windows (with WSL) |

### ANTIE Gateway

| Requirement | Details |
|-------------|---------|
| Memory | Minimum 256MB |
| Disk | Space for maildir (depends on traffic) |
| Network | Access to Lambda server |
| OS | Linux, macOS |

### PMC Client

| Requirement | Details |
|-------------|---------|
| Memory | Minimum 128MB |
| Disk | 100MB for wallet database |
| Network | Access to Lambda server |
| OS | Linux, macOS, Windows |

---

## Verification Script

Run this script to verify all dependencies are installed:

```bash
#!/bin/bash
# verify-deps.sh

echo "=== AXIOM Dependency Check ==="
echo ""

# Rust
echo -n "Rust: "
if command -v rustc &> /dev/null; then
    rustc --version
else
    echo "NOT INSTALLED"
fi

echo -n "Cargo: "
if command -v cargo &> /dev/null; then
    cargo --version
else
    echo "NOT INSTALLED"
fi

# Python
echo -n "Python3: "
if command -v python3 &> /dev/null; then
    python3 --version
else
    echo "NOT INSTALLED"
fi

# Python packages
echo -n "PyNaCl: "
python3 -c "import nacl; print(nacl.__version__)" 2>/dev/null || echo "NOT INSTALLED"

echo -n "blake3: "
python3 -c "import blake3; print('OK')" 2>/dev/null || echo "NOT INSTALLED"

# OpenSSL
echo -n "OpenSSL: "
if command -v openssl &> /dev/null; then
    openssl version
else
    echo "NOT INSTALLED"
fi

echo ""
echo "=== End of Check ==="
```

---

## Cryptographic Libraries

AXIOM uses the following cryptographic primitives:

| Algorithm | Purpose | Rust Crate | Python Package |
|-----------|---------|------------|----------------|
| Ed25519 | Client signatures | `ed25519-dalek` | `pynacl` |
| Dilithium | PQ signatures (VBC) | `pqcrypto-dilithium` | - |
| SPHINCS+ | PQ backup signatures | `pqcrypto-sphincsplus` | - |
| BLAKE3 | Hashing, wallet_id | `blake3` | `blake3` |
| SHA3-256 | State hashing | `sha3` | `hashlib` (stdlib) |
| ChaCha20-Poly1305 | Encryption | `chacha20poly1305` | - |

---

## Troubleshooting

### "blake3 not found" error

```bash
# Install blake3
pip3 install blake3

# If using virtual environment
source venv/bin/activate
pip install blake3
```

### "pynacl installation fails"

```bash
# macOS - install libsodium first
brew install libsodium
pip3 install pynacl

# Ubuntu/Debian
sudo apt install -y libsodium-dev
pip3 install pynacl
```

### "cargo build fails with OpenSSL error"

```bash
# macOS
brew install openssl
export OPENSSL_DIR=$(brew --prefix openssl)

# Ubuntu/Debian  
sudo apt install -y libssl-dev pkg-config
```

### "linker error on macOS"

```bash
# Install Xcode command line tools
xcode-select --install
```

---

## Version Matrix

Tested and verified versions:

| Component | Minimum | Recommended | Notes |
|-----------|---------|-------------|-------|
| Rust | 1.70 | 1.75+ | Stable channel |
| Python | 3.8 | 3.11+ | For test tools |
| PyNaCl | 1.4 | 1.5+ | Ed25519 support |
| blake3 | 0.3 | 0.4+ | Python bindings |
| macOS | 12.0 | 14.0+ | Apple Silicon supported |
| Ubuntu | 20.04 | 22.04+ | LTS recommended |

---

## Docker (Alternative)

If you prefer containerized development:

```dockerfile
FROM rust:1.75-bookworm

# System dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Python packages
RUN pip3 install pynacl blake3

WORKDIR /app
COPY . .

RUN cargo build --release
```

Build and run:
```bash
docker build -t axiom .
docker run -it axiom
```

---

*Last updated: 2026-01-31*
