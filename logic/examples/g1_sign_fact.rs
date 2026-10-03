//! G1 ceremony — sign FACT #0 with the MASTER (wallet-identity) private key.
//!
//! Usage: cargo run --release -p axiom-core-logic --example g1_sign_fact -- <private.key> <tick> <out.json>
//! The tick must be the value Nabla builds at boot (1 as of 2026-09-11,
//! `nabla_node.rs` "let genesis_tick = 1"), or the stored payload's hash will not
//! match the signed one. Called only by scripts/g1-full-ceremony.sh step 8.
use axiom_core_logic::genesis_integrity::{build_signed_genesis_fact, compute_genesis_fact_hash, verify_genesis_fact};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 { eprintln!("usage: g1_sign_fact <private.key> <tick> <out.json>"); std::process::exit(2); }
    let sk = std::fs::read(&args[1]).expect("read private.key");
    let mut key = [0u8; 32];
    key.copy_from_slice(&sk[..32]);
    let tick: u64 = args[2].parse().expect("tick");
    let fact = build_signed_genesis_fact(tick, &key);
    verify_genesis_fact(&fact).expect("the freshly signed FACT #0 must verify against the baked WALLET_IDENTITY_KEY — rebuild Core after baking the key");
    let hash = compute_genesis_fact_hash(&fact);
    let json = serde_json::to_string_pretty(&fact).expect("json");
    std::fs::write(&args[3], json).expect("write");
    println!("genesis_fact_hash: {}", hex::encode(hash));
    println!("signed: true  tick: {}  saved: {}", tick, args[3]);
}
