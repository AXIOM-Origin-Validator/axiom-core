//! G1 Genesis Ceremony — MASTER keypair generator
//!
//! Generates the Ed25519 MASTER keypair for FACT #0 signing.
//! Used by scripts/g1-ceremony.sh (step 1).
//!
//! Usage:
//!   cargo run -p axiom-core-logic --example g1_keygen -- <key_dir>
//!
//! Outputs:
//!   <key_dir>/master_private.key  — 32-byte raw Ed25519 secret key (mode 0600)
//!   <key_dir>/master_public.key   — 32-byte raw Ed25519 public key
//!   <key_dir>/master_public.hex   — hex-encoded public key (for baking into Core)
//!   stdout: hex-encoded public key

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let key_dir = if args.len() > 1 { &args[1] } else { "." };

    // Generate keypair
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key();

    let sk_path = format!("{}/master_private.key", key_dir);
    let pk_path = format!("{}/master_public.key", key_dir);
    let hex_path = format!("{}/master_public.hex", key_dir);

    // Write private key (restricted permissions)
    std::fs::write(&sk_path, sk.to_bytes()).expect("Failed to write private key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sk_path, std::fs::Permissions::from_mode(0o600))
            .expect("Failed to set private key permissions");
    }

    // Write public key
    std::fs::write(&pk_path, pk.as_bytes()).expect("Failed to write public key");

    // Write hex
    let hex_str = hex::encode(pk.as_bytes());
    std::fs::write(&hex_path, &hex_str).expect("Failed to write hex file");

    // Print to stdout (captured by g1-ceremony.sh)
    print!("{}", hex_str);
}
