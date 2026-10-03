// KI#51 — EXHAUSTIVE differential over the REAL wallet_id functions.
//
// Ground truth: a receiver address is "own" iff it is one of the tier
// addresses generated from the SENDER's (email, salt, pk) — the collapse
// model (one keypair -> its tier addresses, AXIOM_DESIGN_WalletPairCollapse).
//
// Compares, over every (sender identity) x (receiver address) x (suffix
// spelling) combination:
//   OLD = verify_pk_binding(receiver_id, sender_pk)          [8-bit, 7-way]
//   NEW = canonicalised exact match vs regenerated candidates
//
//   cargo run -q -p axiom-core-logic --features dev-mode --example ki51_ownness_exhaustive

use axiom_core_logic::wallet_id::{generate_all_wallet_ids, verify_pk_binding};

/// The SHIPPED predicate — `axiom_core_logic::wallet_id::is_own_address`
/// (KI#51 fix, landed 2026-08-02). This probe deliberately calls the real
/// function, not a local re-implementation, so it cannot drift from what
/// validation.rs actually consults.
fn is_own_new(sender_id: &str, receiver_id: &str, sender_pk: &[u8; 32]) -> bool {
    axiom_core_logic::wallet_id::is_own_address(sender_id, receiver_id, sender_pk)
}

fn main() {
    const IDENTITIES: usize = 120;

    // Build N identities: pk -> (email, salt = blake3(pk)[..2], 7 tier addrs).
    let mut ids = Vec::new();
    for i in 0..IDENTITIES {
        let pk: [u8; 32] = *blake3::hash(&(i as u64).to_le_bytes()).as_bytes();
        let email = format!("user{i}@axiom");
        let salt = hex::encode(blake3::hash(&pk).as_bytes())[..2].to_string();
        let tiers = generate_all_wallet_ids(&email, &salt, &pk).expect("gen");
        ids.push((pk, email, salt, tiers));
    }

    let suffixes = ["", "-P", "-G", "-01", "-99"];

    let (mut old_fp, mut old_fn_, mut new_fp, mut new_fn_) = (0u64, 0u64, 0u64, 0u64);
    let mut checks = 0u64;
    let mut old_fp_example = String::new();
    let mut new_bad_example = String::new();

    for (si, (spk, _semail, _ssalt, stiers)) in ids.iter().enumerate() {
        // The sender acts from each of its own tier addresses.
        for (sender_id, _, _, _) in stiers.iter() {
            for (ri, (_rpk, _remail, _rsalt, rtiers)) in ids.iter().enumerate() {
                for (recv_base, _, _, _) in rtiers.iter() {
                    for suf in suffixes {
                        let recv = format!("{recv_base}{suf}");
                        // GROUND TRUTH: same identity index => the receiver
                        // address really was generated from the sender's key.
                        let truth = si == ri;

                        let old = verify_pk_binding(&recv, spk).is_ok();
                        let new = is_own_new(sender_id, &recv, spk);
                        checks += 1;

                        if old && !truth {
                            old_fp += 1;
                            if old_fp_example.is_empty() {
                                old_fp_example = format!("{sender_id} -> {recv}");
                            }
                        }
                        if !old && truth {
                            old_fn_ += 1;
                        }
                        if new && !truth {
                            new_fp += 1;
                            if new_bad_example.is_empty() {
                                new_bad_example = format!("FP {sender_id} -> {recv}");
                            }
                        }
                        if !new && truth {
                            new_fn_ += 1;
                            if new_bad_example.is_empty() {
                                new_bad_example = format!("FN {sender_id} -> {recv}");
                            }
                        }
                    }
                }
            }
        }
    }

    println!("exhaustive own-ness differential");
    println!("  identities={IDENTITIES}  tiers=7  suffix spellings={}", suffixes.len());
    println!("  total (sender_addr, receiver_addr) checks: {checks}");
    println!();
    println!("  OLD verify_pk_binding(receiver, sender_pk):");
    println!("      false POSITIVES (foreign judged own): {old_fp}");
    println!("      false NEGATIVES (own judged foreign): {old_fn_}");
    if !old_fp_example.is_empty() {
        println!("      e.g. {old_fp_example}");
    }
    println!();
    println!("  NEW canonicalised exact-vs-regenerated:");
    println!("      false POSITIVES: {new_fp}");
    println!("      false NEGATIVES: {new_fn_}");
    if !new_bad_example.is_empty() {
        println!("      e.g. {new_bad_example}");
    }
    println!();
    if new_fp == 0 && new_fn_ == 0 {
        println!("  RESULT: NEW predicate is EXACT over the enumerated domain.");
    } else {
        println!("  RESULT: NEW predicate is WRONG — see example above.");
    }
}
