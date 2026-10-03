// One-shot: does the OLD 8-bit predicate consider `receiver_id` to be owned
// by `sender_pk`?  Used by tests/ki51_ownness_gate.py to FIND a real colliding
// pair deterministically instead of waiting for a soak to stumble into one.
//
// Prints "OWN" or "FOREIGN" — asking Core's own function, never a
// re-implementation.
//
//   cargo run -q -p axiom-core-logic --features dev-mode \
//     --example pk_bind_probe_one -- <receiver_wallet_id> <sender_pk_hex>

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: pk_bind_probe_one <receiver_wallet_id> <sender_pk_hex>");
        std::process::exit(2);
    }
    let receiver_id = &args[1];
    let pk_hex = &args[2];
    if pk_hex.len() != 64 {
        eprintln!("sender_pk_hex must be 64 hex chars");
        std::process::exit(2);
    }
    let mut pk = [0u8; 32];
    for i in 0..32 {
        pk[i] = match u8::from_str_radix(&pk_hex[2 * i..2 * i + 2], 16) {
            Ok(b) => b,
            Err(_) => {
                eprintln!("bad hex");
                std::process::exit(2);
            }
        };
    }
    let old_says_own =
        axiom_core_logic::wallet_id::verify_pk_binding(receiver_id, &pk).is_ok();
    println!("{}", if old_says_own { "OWN" } else { "FOREIGN" });
}
