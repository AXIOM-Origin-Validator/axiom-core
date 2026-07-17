//! G1 Genesis Ceremony — FACT #0 Signer
//!
//! Signs FACT #0 with the wallet identity private key and saves as JSON.
//! Used by scripts/g1-ceremony.sh (step 5).
//!
//! Usage:
//!   cargo run -p axiom-core-logic --example g1_sign_fact -- <sk_hex> <output_path>
//!
//! The signed FACT #0 is permanently stored in Nabla and anchors the entire AXIOM supply.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: g1_sign_fact <master_sk_hex> <output_path>");
        eprintln!("  master_sk_hex: 64-char hex-encoded Ed25519 private key");
        eprintln!("  output_path:   where to save the signed FACT #0 JSON");
        std::process::exit(1);
    }

    let sk_hex = &args[1];
    let output_path = &args[2];

    // Parse private key
    let sk_bytes = hex::decode(sk_hex).expect("invalid hex for private key");
    if sk_bytes.len() != 32 {
        eprintln!("ERROR: private key must be exactly 32 bytes (got {})", sk_bytes.len());
        std::process::exit(1);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&sk_bytes);

    // Derive public key and display it
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key);
    let public_key = signing_key.verifying_key();
    eprintln!("WALLET_IDENTITY_KEY: {}", hex::encode(public_key.as_bytes()));

    // Verify it matches the compiled-in WALLET_IDENTITY_KEY
    let compiled_pk = axiom_core_logic::wallet_id::WALLET_IDENTITY_KEY;
    if public_key.as_bytes() != &compiled_pk {
        eprintln!("WARNING: Derived public key does NOT match compiled WALLET_IDENTITY_KEY!");
        eprintln!("  Derived:  {}", hex::encode(public_key.as_bytes()));
        eprintln!("  Compiled: {}", hex::encode(compiled_pk));
        eprintln!("  Did you run step 2 (bake key into Core) and step 4 (rebuild)?");
        std::process::exit(1);
    }

    // Build and sign FACT #0
    let tick = 1; // Genesis tick
    let fact = axiom_core_logic::genesis_integrity::build_signed_genesis_fact(tick, &key);

    // Compute and display hash
    let hash = axiom_core_logic::genesis_integrity::compute_genesis_fact_hash(&fact);
    println!("genesis_fact_hash: {}", hex::encode(hash));
    println!("signature_len: {}", fact.core_signature.len());
    println!("pool_total: {}", fact.pool_total);
    println!("headlines: {}", fact.headlines.len());

    // Verify the signature passes
    match axiom_core_logic::genesis_integrity::verify_genesis_fact(&fact) {
        Ok(()) => println!("verification: PASSED"),
        Err(e) => {
            eprintln!("verification: FAILED — {}", e);
            std::process::exit(1);
        }
    }

    println!("signed: true");

    // Save as a simple text format (Core doesn't have serde_json)
    // Format: hex-encoded fields, one per line
    let mut output = String::new();
    output.push_str(&format!("fact_id={}\n", fact.fact_id));
    output.push_str(&format!("pool_total={}\n", fact.pool_total));
    output.push_str(&format!("tick={}\n", fact.tick));
    output.push_str(&format!("genesis_fact_hash={}\n", hex::encode(hash)));
    output.push_str(&format!("core_signature={}\n", hex::encode(&fact.core_signature)));
    output.push_str(&format!("headline_count={}\n", fact.headlines.len()));
    for (i, h) in fact.headlines.iter().enumerate() {
        output.push_str(&format!("headline_{}={} | {} | {}\n", i, h.country, h.organisation, h.headline));
    }
    for (i, p) in fact.sub_pools.iter().enumerate() {
        output.push_str(&format!("pool_{}={:?}:{}\n", i, p.pool_id, p.initial_balance));
    }
    std::fs::write(output_path, &output).expect("Failed to write output file");
    println!("saved: {}", output_path);
}
