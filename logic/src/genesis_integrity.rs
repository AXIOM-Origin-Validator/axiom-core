//! YPX-011: Genesis Integrity & Supply Provenance
//!
//! FACT #0 — the root of the entire AXIOM supply.
//! Anchored to 7 real-world headlines from 7 countries.
//! Signed by Core with the wallet identity private key. Permanently stored in Nabla.
//!
//! Any party can verify: fetch FACT #0 from Nabla, verify signature
//! against WALLET_IDENTITY_KEY, look up headlines in public news archives.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::vec;
use alloc::format;
use serde::{Serialize, Deserialize};

/// Total public AXC supply — hardcoded, immutable, compile-time constant.
/// No function in the entire codebase can increase this number.
/// Changing it requires recompiling Core (new ELF = new worldline).
// SECURITY-BAL (Balance Integrity / Supply Cap):
// 100,000,000 AXC — the total public supply of AXIOM, fixed forever.
// This is the "no inflation" guarantee. No admin function. No governance override.
// Ref: White Paper §4 (Economic Invariants), Yellow Paper §1A Anchor 4, YPX-011.
//
// The DevTreasury pool below holds 1,000,000 dev-AXC separately. It is
// NOT counted in this 100M cap (`AXIOM_DESIGN_FactClassIsolation.md` §4).
pub const GENESIS_POOL_TOTAL: u64 = 100_000_000;

/// Dev-AXC supply held at FACT #0 by the `DevTreasury` pool. Separately
/// denominated, outside the 100M public cap. Fixed lifetime — no minting
/// authority (`AXIOM_DESIGN_FactClassIsolation.md` §4.4).
pub const GENESIS_DEV_POOL_TOTAL: u64 = 1_000_000;

/// Genesis date (ISO-8601)
pub const GENESIS_DATE: &str = "2026-03-19";

/// Genesis news anchor — unix timestamp (seconds) of GENESIS_DATE midnight UTC.
/// Derived from the 7 headline anchors: all 7 headlines were published on
/// 2026-03-19 across 7 countries (USA, Japan, UK, Taiwan, Australia, Germany,
/// France). Anyone can verify by looking up the headlines in public news archives.
/// This timestamp is the provable "no earlier than" bound for genesis.
/// Used as lockup start for genesis validator stakes (White Paper §2.10.1).
pub const GENESIS_NEWS_ANCHOR: u64 = 1_773_878_400;

/// Sub-pool identifiers.
///
/// The first seven variants are the public AXC pools that sum to
/// `GENESIS_POOL_TOTAL` (100M). `DevTreasury` is the dev-AXC pool —
/// `GENESIS_DEV_POOL_TOTAL` (1M), separately denominated, outside the
/// 100M cap (`AXIOM_DESIGN_FactClassIsolation.md` §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubPoolId {
    /// 10 genesis validators × 1,000,000 AXC (locked 3 years)
    Genesis,
    /// Sliding scale for early non-genesis validators
    Bootstrap,
    /// Market allocation (F2H distribution)
    Market,
    /// 1 AXC per new wallet
    Airdrop,
    /// Developer recognition
    Developer,
    /// Architecture contributor bonus
    Architecture,
    /// System Reserve Pool — continuity functions
    SRP,
    /// Dev-AXC treasury — 1M dev-AXC, class-isolated, fixed lifetime
    /// (no minting authority). NOT counted in the 100M public cap.
    DevTreasury,
}

/// Sub-pool declaration in FACT #0
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubPoolDeclaration {
    pub pool_id: SubPoolId,
    pub initial_balance: u64,
}

/// News headline anchor — proof-of-fair-launch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadlineAnchor {
    /// Country of origin
    pub country: String,
    /// News organisation name
    pub organisation: String,
    /// Timestamp as published (original timezone)
    pub timestamp: String,
    /// Exact headline text as published (original language)
    pub headline: String,
}

/// FACT #0 — Genesis declaration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisFact {
    /// Always 0
    pub fact_id: u64,
    /// Total AXC supply (must equal GENESIS_POOL_TOTAL)
    pub pool_total: u64,
    /// Sub-pool allocations (must sum to pool_total)
    pub sub_pools: Vec<SubPoolDeclaration>,
    /// 7 headline anchors from 7 countries
    pub headlines: Vec<HeadlineAnchor>,
    /// TARDIS genesis tick
    pub tick: u64,
    /// Ed25519 signature by Core over CBOR of all fields above
    pub core_signature: Vec<u8>,
}

/// Compute the genesis fact hash: BLAKE3 over canonical field concatenation.
/// Domain-tagged: "AXIOM_GENESIS_FACT" || fact_id || pool_total || sub_pools || headlines || tick
pub fn compute_genesis_fact_hash(fact: &GenesisFact) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_GENESIS_FACT");
    hasher.update(&fact.fact_id.to_le_bytes());
    hasher.update(&fact.pool_total.to_le_bytes());
    // Sub-pools: pool_id ordinal + balance for each
    for pool in &fact.sub_pools {
        let ordinal: u8 = match pool.pool_id {
            SubPoolId::Genesis => 0,
            SubPoolId::Bootstrap => 1,
            SubPoolId::Market => 2,
            SubPoolId::Airdrop => 3,
            SubPoolId::Developer => 4,
            SubPoolId::Architecture => 5,
            SubPoolId::SRP => 6,
            SubPoolId::DevTreasury => 7,
        };
        hasher.update(&[ordinal]);
        hasher.update(&pool.initial_balance.to_le_bytes());
    }
    // Headlines: country + org + timestamp + headline for each
    for h in &fact.headlines {
        hasher.update(h.country.as_bytes());
        hasher.update(h.organisation.as_bytes());
        hasher.update(h.timestamp.as_bytes());
        hasher.update(h.headline.as_bytes());
    }
    hasher.update(&fact.tick.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Verify FACT #0 integrity:
/// 1. fact_id == 0
/// 2. pool_total == GENESIS_POOL_TOTAL (public-AXC cap, 100M)
/// 3. public sub_pools sum == GENESIS_POOL_TOTAL (every pool EXCEPT
///    `DevTreasury`)
/// 4. DevTreasury sub_pool sum == GENESIS_DEV_POOL_TOTAL (1M dev-AXC,
///    outside the 100M cap)
/// 5. exactly 7 headlines
/// 6. core_signature verifies against WALLET_IDENTITY_KEY
pub fn verify_genesis_fact(fact: &GenesisFact) -> Result<(), String> {
    // 1. fact_id
    if fact.fact_id != 0 {
        return Err("FACT #0 must have fact_id = 0".into());
    }

    // 2. pool_total (public cap, unchanged)
    if fact.pool_total != GENESIS_POOL_TOTAL {
        return Err(format!("pool_total {} != GENESIS_POOL_TOTAL {}", fact.pool_total, GENESIS_POOL_TOTAL));
    }

    // 3. public-pool sum == GENESIS_POOL_TOTAL
    //    (sum of every pool EXCEPT DevTreasury, which is dev-AXC outside the cap)
    let public_sum: u64 = fact.sub_pools.iter()
        .filter(|p| !matches!(p.pool_id, SubPoolId::DevTreasury))
        .map(|p| p.initial_balance)
        .sum();
    if public_sum != GENESIS_POOL_TOTAL {
        return Err(format!("public sub_pools sum {} != GENESIS_POOL_TOTAL {}", public_sum, GENESIS_POOL_TOTAL));
    }

    // 4. DevTreasury sum == GENESIS_DEV_POOL_TOTAL
    let dev_sum: u64 = fact.sub_pools.iter()
        .filter(|p| matches!(p.pool_id, SubPoolId::DevTreasury))
        .map(|p| p.initial_balance)
        .sum();
    if dev_sum != GENESIS_DEV_POOL_TOTAL {
        return Err(format!("DevTreasury sum {} != GENESIS_DEV_POOL_TOTAL {}", dev_sum, GENESIS_DEV_POOL_TOTAL));
    }

    // 5. exactly 7 headlines
    if fact.headlines.len() != 7 {
        return Err(format!("expected 7 headlines, got {}", fact.headlines.len()));
    }

    // 6. verify signature
    let hash = compute_genesis_fact_hash(fact);
    let identity_pk = crate::wallet_id::WALLET_IDENTITY_KEY;
    crate::crypto::verify_signature(&identity_pk, &hash, &fact.core_signature)
        .map_err(|_| "FACT #0 signature invalid against WALLET_IDENTITY_KEY".to_string())?;

    Ok(())
}

/// Sign FACT #0 with the given Ed25519 private key.
/// Returns the signed GenesisFact (core_signature populated).
/// The key MUST correspond to WALLET_IDENTITY_KEY.
pub fn sign_genesis_fact(fact: &mut GenesisFact, master_private_key: &[u8; 32]) {
    let hash = compute_genesis_fact_hash(fact);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(master_private_key);
    use ed25519_dalek::Signer;
    let sig = signing_key.sign(&hash);
    fact.core_signature = sig.to_bytes().to_vec();
}

/// Build AND sign FACT #0 in one call.
/// Convenience wrapper for genesis ceremony.
pub fn build_signed_genesis_fact(tick: u64, master_private_key: &[u8; 32]) -> GenesisFact {
    let mut fact = build_genesis_fact(tick);
    sign_genesis_fact(&mut fact, master_private_key);
    fact
}

/// Build the canonical FACT #0 with the hardcoded genesis headlines.
/// Does NOT sign — caller must sign with wallet identity private key
/// or use build_signed_genesis_fact().
pub fn build_genesis_fact(tick: u64) -> GenesisFact {
    let sub_pools = vec![
        // ── Public AXC pools (sum to GENESIS_POOL_TOTAL = 100M) ─────
        SubPoolDeclaration { pool_id: SubPoolId::Genesis, initial_balance: 10_000_000 },
        SubPoolDeclaration { pool_id: SubPoolId::Airdrop, initial_balance: 600_000 },
        SubPoolDeclaration { pool_id: SubPoolId::Bootstrap, initial_balance: 200_000 },
        SubPoolDeclaration { pool_id: SubPoolId::SRP, initial_balance: 500_000 },
        SubPoolDeclaration { pool_id: SubPoolId::Developer, initial_balance: 500_000 },
        SubPoolDeclaration { pool_id: SubPoolId::Architecture, initial_balance: 200_000 },
        SubPoolDeclaration { pool_id: SubPoolId::Market, initial_balance: 88_000_000 },
        // ── Dev-AXC treasury (1M, outside the 100M cap) ─────────────
        SubPoolDeclaration { pool_id: SubPoolId::DevTreasury, initial_balance: GENESIS_DEV_POOL_TOTAL },
    ];

    let headlines = vec![
        HeadlineAnchor {
            country: "USA".into(),
            organisation: "Associated Press (AP)".into(),
            timestamp: "11:43 AM GMT+9, March 19, 2026".into(),
            headline: "Trump threatens to strike South Pars gas field if Iran attacks Qatar again".into(),
        },
        HeadlineAnchor {
            country: "Japan".into(),
            organisation: "NHK".into(),
            timestamp: "10:59 AM GMT+9, March 19, 2026".into(),
            headline: "\u{9ad8}\u{5e02}\u{9996}\u{76f8} \u{30a2}\u{30e1}\u{30ea}\u{30ab}\u{306b}\u{5230}\u{7740} 20\u{65e5}\u{672a}\u{660e}\u{306b}\u{30c8}\u{30e9}\u{30f3}\u{30d7}\u{5927}\u{7d71}\u{9818}\u{3068}\u{9996}\u{8133}\u{4f1a}\u{8ac7}".into(),
        },
        HeadlineAnchor {
            country: "UK".into(),
            organisation: "BBC News".into(),
            timestamp: "12:32 PM GMT+9, March 19, 2026".into(),
            headline: "Trump says US will 'massively blow up' major Iranian gas field if it attacks Qatar again".into(),
        },
        HeadlineAnchor {
            country: "Taiwan".into(),
            organisation: "Central News Agency (CNA)".into(),
            timestamp: "09:52 AM GMT+8, March 19, 2026".into(),
            headline: "\u{96fb}\u{5b50}\u{5165}\u{5883}\u{5361}\u{932f}\u{5217}\u{722d}\u{8b70}\u{3000}\u{6797}\u{4f73}\u{9f8d}\u{ff1a}\u{76fc}\u{5357}\u{97d3}\u{653f}\u{5e9c}\u{6b63}\u{8996}\u{53f0}\u{7063}\u{6c11}\u{610f}".into(),
        },
        HeadlineAnchor {
            country: "Australia".into(),
            organisation: "ABC Australia".into(),
            timestamp: "08:43 AM GMT+10, March 19, 2026".into(),
            headline: "Iran war live updates: Iran targets Gulf neighbours in retaliation for Israeli strike on major gas field".into(),
        },
        HeadlineAnchor {
            country: "Germany".into(),
            organisation: "Deutsche Welle".into(),
            timestamp: "03:46 AM GMT+9, March 19, 2026".into(),
            headline: "Merz zum Iran-Krieg: \"Wir h\u{00e4}tten abgeraten\"".into(),
        },
        HeadlineAnchor {
            country: "France".into(),
            organisation: "Le Monde".into(),
            timestamp: "11:18 AM GMT+9, March 19, 2026".into(),
            headline: "EN DIRECT, municipales 2026 : revivez le d\u{00e9}bat entre Emmanuel Gr\u{00e9}goire, Rachida Dati et Sophia Chikirou, les candidats au second tour \u{00e0} Paris".into(),
        },
    ];

    // Verify sub-pool sums per supply.
    let public_sum: u64 = sub_pools.iter()
        .filter(|p| !matches!(p.pool_id, SubPoolId::DevTreasury))
        .map(|p| p.initial_balance)
        .sum();
    assert_eq!(public_sum, GENESIS_POOL_TOTAL, "public sub-pools must sum to GENESIS_POOL_TOTAL");
    let dev_sum: u64 = sub_pools.iter()
        .filter(|p| matches!(p.pool_id, SubPoolId::DevTreasury))
        .map(|p| p.initial_balance)
        .sum();
    assert_eq!(dev_sum, GENESIS_DEV_POOL_TOTAL, "DevTreasury must sum to GENESIS_DEV_POOL_TOTAL");

    GenesisFact {
        fact_id: 0,
        pool_total: GENESIS_POOL_TOTAL,
        sub_pools,
        headlines,
        tick,
        core_signature: Vec::new(), // caller must sign
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_sub_pools_sum_to_total() {
        // Public pools (everything except DevTreasury) sum to 100M.
        let fact = build_genesis_fact(1);
        let public_sum: u64 = fact.sub_pools.iter()
            .filter(|p| !matches!(p.pool_id, SubPoolId::DevTreasury))
            .map(|p| p.initial_balance)
            .sum();
        assert_eq!(public_sum, GENESIS_POOL_TOTAL);
    }

    #[test]
    fn test_dev_pool_is_1m_outside_100m_cap() {
        // DevTreasury holds 1M dev-AXC and is NOT included in
        // GENESIS_POOL_TOTAL (the 100M public cap). The pool_total
        // field remains literally 100M; the grand total of all
        // sub_pools is 101M (100M public + 1M dev).
        let fact = build_genesis_fact(1);
        let dev_pool = fact.sub_pools.iter()
            .find(|p| matches!(p.pool_id, SubPoolId::DevTreasury))
            .expect("DevTreasury pool must exist");
        assert_eq!(dev_pool.initial_balance, GENESIS_DEV_POOL_TOTAL);
        assert_eq!(GENESIS_DEV_POOL_TOTAL, 1_000_000);
        assert_eq!(fact.pool_total, GENESIS_POOL_TOTAL, "pool_total = public cap only");
        let grand_total: u64 = fact.sub_pools.iter().map(|p| p.initial_balance).sum();
        assert_eq!(grand_total, GENESIS_POOL_TOTAL + GENESIS_DEV_POOL_TOTAL,
            "dev pool stacks on top of the 100M public cap, not into it");
    }

    #[test]
    fn test_exactly_7_headlines() {
        let fact = build_genesis_fact(1);
        assert_eq!(fact.headlines.len(), 7);
    }

    #[test]
    fn test_all_7_countries_distinct() {
        let fact = build_genesis_fact(1);
        let countries: Vec<&str> = fact.headlines.iter().map(|h| h.country.as_str()).collect();
        let mut deduped = countries.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(countries.len(), deduped.len(), "all countries must be distinct");
    }

    #[test]
    fn test_genesis_fact_hash_deterministic() {
        let fact = build_genesis_fact(1);
        let h1 = compute_genesis_fact_hash(&fact);
        let h2 = compute_genesis_fact_hash(&fact);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_genesis_fact_hash_changes_with_tick() {
        let f1 = build_genesis_fact(1);
        let f2 = build_genesis_fact(2);
        assert_ne!(compute_genesis_fact_hash(&f1), compute_genesis_fact_hash(&f2));
    }

    #[test]
    fn test_verify_rejects_wrong_pool_total() {
        let mut fact = build_genesis_fact(1);
        fact.pool_total = 999;
        assert!(verify_genesis_fact(&fact).is_err());
    }

    #[test]
    fn test_verify_rejects_wrong_public_sum() {
        // Bump a public pool entry — public sum no longer == 100M, reject.
        let mut fact = build_genesis_fact(1);
        let pub_idx = fact.sub_pools.iter()
            .position(|p| !matches!(p.pool_id, SubPoolId::DevTreasury))
            .unwrap();
        fact.sub_pools[pub_idx].initial_balance += 1;
        assert!(verify_genesis_fact(&fact).is_err());
    }

    #[test]
    fn test_verify_rejects_wrong_dev_sum() {
        // Bump the dev pool entry — dev sum no longer == 1M, reject.
        let mut fact = build_genesis_fact(1);
        let dev_idx = fact.sub_pools.iter()
            .position(|p| matches!(p.pool_id, SubPoolId::DevTreasury))
            .unwrap();
        fact.sub_pools[dev_idx].initial_balance += 1;
        assert!(verify_genesis_fact(&fact).is_err());
    }

    #[test]
    fn test_verify_rejects_missing_headlines() {
        let mut fact = build_genesis_fact(1);
        fact.headlines.pop(); // only 6
        assert!(verify_genesis_fact(&fact).is_err());
    }
}
