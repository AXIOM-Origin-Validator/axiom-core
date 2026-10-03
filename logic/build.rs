/// Read protocol_core.toml and generate protocol_constants.rs at compile time.
/// The generated file is include!'d by the crate to get compile-time constants.
use std::fs;
use std::path::Path;

fn main() {
    let toml_path = Path::new("protocol_core.toml");
    let wallets_path = Path::new("genesis_lockup_wallets.txt");
    println!("cargo:rerun-if-changed=protocol_core.toml");
    println!("cargo:rerun-if-changed=genesis_lockup_wallets.txt");
    // `version::CANONICAL_CORE_ID` is built from `option_env!` at
    // expansion time. Without this directive, cargo's incremental
    // cache would keep an old canonical baked in across env-var
    // changes — releases would silently ship stale gates.
    println!("cargo:rerun-if-env-changed=AXIOM_CANONICAL_CORE_ID");
    // Same reasoning for the CoreID lineage accept-set: `version::BLESSED_PRIOR_CORE_IDS`
    // is `option_env!`-expanded, so cargo must rebuild when the blessed set changes or a
    // rotation would ship the old accept-set (routine upgrade → stale/empty priors →
    // outstanding cheques wrongly rejected). See AXIOM_DESIGN_CoreUpgradeMigration.md §11.
    println!("cargo:rerun-if-env-changed=AXIOM_BLESSED_PRIOR_CORE_IDS");

    if !toml_path.exists() {
        panic!("protocol_core.toml not found — required for Core compilation");
    }

    let content = fs::read_to_string(toml_path).expect("Failed to read protocol_core.toml");

    let mut generated = String::from(
        "// AUTO-GENERATED from protocol_core.toml by build.rs — DO NOT EDIT\n\n"
    );

    // Two-pass: collect keys first so a `foo` + `foo_dev` pair emits ONE
    // constant name FOO with #[cfg(feature = "dev-mode")] selection — the
    // dev/prod tuning-register convention (2026-07-07; replaces hand-written
    // cfg'd const pairs scattered through the source).
    let mut entries: Vec<(String, String)> = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key_lower = key.trim();
            // `atoms_per_axc` is OWNED by axiom-denomination (the unit ladder, in
            // denomination/protocol_denomination.toml) — it is NOT in this file. Skip
            // it as a guard: if it's ever mistakenly added here it must NOT become a
            // `protocol_gen::*` duplicate of the denomination unit (drift source).
            // (`minimum_tx_atoms` — the dust POLICY — IS ours and emits normally.)
            if key_lower == "atoms_per_axc" {
                continue;
            }
            let value = value.trim().split('#').next().unwrap_or("").trim();
            entries.push((key_lower.to_string(), value.to_string()));
        }
    }
    let has = |name: &str| entries.iter().any(|(k, _)| k == name);
    // ACCOUNT-KEYED dev timers (AXIOM_DESIGN_AccountKeyedDevTiming.md §3). A base
    // name here emits BOTH the real `FOO` AND a `FOO_DEV` UNCONDITIONALLY — the
    // dev/real choice is made at RUNTIME by `is_dev_class` through the shared
    // `types::dev_or_real` helper, so one (mainnet) binary carries both values and
    // serves a dev account and a real account on their own clocks. A collective
    // timer (bloom era, console, emission caps, fob) is NOT here and keeps the
    // build-time `#[cfg(feature = "dev-mode")]` selection below.
    //
    // ⚠ A base name goes here ONLY when EVERY read of it has been switched to
    // `dev_or_real(...)`. Add it before its reads and a dev build silently gets the
    // REAL value at the un-switched sites (both compiled in, `FOO` = real). The
    // `check_dev_timing` preflight gate enforces the correspondence.
    const ACCOUNT_KEYED_DEV_TIMERS: &[&str] = &[
        "recall_init_window_low",
        "recall_init_window_high",
        "claim_interval_ticks",
        "oracle_maturity_ticks",
        // TVL (§23.15 / KI#221): the ONE read is verify_tx_velocity, switched to
        // dev_or_real on the k-signed prev_receipt.is_dev_class. Safe to key here.
        "tx_velocity_min_ticks",
        // Settle floor (YPX-001 §1.5.1b / ForkSettlement Q1): the ONE read is
        // fact::origin_settled_link, via dev_or_real on the k-signed is_dev_class.
        "scar_settle_ticks",
    ];
    let account_keyed = |base: &str| ACCOUNT_KEYED_DEV_TIMERS.contains(&base);
    for (key_lower, value) in &entries {
        if let Some(base) = key_lower.strip_suffix("_dev") {
            if has(base) && account_keyed(base) {
                // account-keyed dev half → its own `FOO_DEV` constant, always compiled in.
                generated.push_str(&format!(
                    "pub const {}_DEV: u64 = {};\n",
                    base.to_uppercase(),
                    value
                ));
                continue;
            }
            if has(base) {
                // build-selected dev half — emitted under the BASE name.
                generated.push_str(&format!(
                    "#[cfg(feature = \"dev-mode\")]\npub const {}: u64 = {};\n",
                    base.to_uppercase(),
                    value
                ));
                continue;
            }
        }
        if has(&format!("{key_lower}_dev")) {
            if account_keyed(key_lower) {
                // account-keyed real half → the plain `FOO`, always compiled in.
                generated.push_str(&format!(
                    "pub const {}: u64 = {};\n",
                    key_lower.to_uppercase(),
                    value
                ));
                continue;
            }
            // build-selected prod half.
            generated.push_str(&format!(
                "#[cfg(not(feature = \"dev-mode\"))]\npub const {}: u64 = {};\n",
                key_lower.to_uppercase(),
                value
            ));
            continue;
        }
        // Keep underscores for readability in generated code
        generated.push_str(&format!(
            "pub const {}: u64 = {};\n",
            key_lower.to_uppercase(),
            value
        ));
    }

    // ── KI#240 — THE BUILD'S TUNING PROFILE, as a constant a deploy check can read ──
    //
    // Every build-selected twin above (`foo` + `foo_dev`, not account-keyed) is
    // chosen by ONE switch: this crate's `dev-mode` feature. The guest ELF and the
    // natives are separate compilations of core/logic, so the switch can differ
    // between them — and on 2026-10-01 it did: trustmesh's ELF was built REAL
    // (ceremony-keyed tree) while every native and the SDK were built DEV, and a
    // stake claim stamped with the dev tier-3 stake lock (60 ticks) met the ELF's
    // real 6,500,000 -> E_STAKE_LOCK_TIME_DISAGREEMENT on every subsidy claim redeem.
    // Nothing could see it: no artifact said which twin set a binary carried.
    //
    // So the choice is emitted here, under the SAME cfg as the twins, and re-exported
    // as `version::TUNING_PROFILE{,_MARKER}`. Natives print the marker at startup
    // (that use keeps the bytes in the binary); `scripts/build_profile.py verify`
    // greps it and compares against the ELF. The guest never references it, so it
    // emits nothing into the ELF and the CoreID does not move.
    generated.push_str(
        "#[cfg(feature = \"dev-mode\")]\npub const TUNING_PROFILE: &str = \"dev\";\n\
         #[cfg(not(feature = \"dev-mode\"))]\npub const TUNING_PROFILE: &str = \"real\";\n\
         #[cfg(feature = \"dev-mode\")]\npub const TUNING_PROFILE_MARKER: &str = \"[axiom-tuning-profile:dev]\";\n\
         #[cfg(not(feature = \"dev-mode\"))]\npub const TUNING_PROFILE_MARKER: &str = \"[axiom-tuning-profile:real]\";\n",
    );

    // Genesis lockup wallet IDs — read from genesis_lockup_wallets.txt.
    // Each non-empty, non-comment line is `<wallet_id> <ed25519_pk_hex>` (§6c;
    // the pk column is what makes the wallet a genesis STAKE wallet — a wallet
    // id carries only a one-byte pk_bind and is an ADDRESS, never an identity).
    // A bare `<wallet_id>` line is accepted for the string lock only.
    // Generates: pub const GENESIS_LOCKUP_WALLET_IDS: [&str; N] = [...];
    //            pub const GENESIS_STAKE_WALLET_PKS: [[u8; 32]; M] = [...];
    let mut stake_pks: Vec<[u8; 32]> = Vec::new();
    let wallet_ids: Vec<String> = if wallets_path.exists() {
        fs::read_to_string(wallets_path)
            .expect("Failed to read genesis_lockup_wallets.txt")
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| {
                let mut parts = l.split_whitespace();
                let id = parts.next().unwrap_or("").to_string();
                if let Some(hexpk) = parts.next() {
                    let bytes = (0..hexpk.len() / 2)
                        .map(|i| u8::from_str_radix(&hexpk[i * 2..i * 2 + 2], 16)
                            .expect("genesis_lockup_wallets.txt: pk column must be hex"))
                        .collect::<Vec<u8>>();
                    let arr: [u8; 32] = bytes.as_slice().try_into()
                        .expect("genesis_lockup_wallets.txt: pk column must be 32 bytes");
                    stake_pks.push(arr);
                }
                id
            })
            .collect()
    } else {
        vec![]
    };

    let wallet_array_entries: Vec<String> = wallet_ids
        .iter()
        .map(|id| format!("    \"{}\"", id))
        .collect();

    // §6c — the genesis STAKE wallet public keys (exact 32-byte identities).
    if stake_pks.is_empty() {
        generated.push_str("pub const GENESIS_STAKE_WALLET_PKS: [[u8; 32]; 0] = [];\n");
    } else {
        let entries: Vec<String> = stake_pks.iter().map(|pk| {
            let bytes: Vec<String> = pk.iter().map(|b| format!("0x{:02X}", b)).collect();
            format!("    [{}]", bytes.join(", "))
        }).collect();
        generated.push_str(&format!(
            "pub const GENESIS_STAKE_WALLET_PKS: [[u8; 32]; {}] = [\n{}\n];\n",
            stake_pks.len(), entries.join(",\n")
        ));
    }

    let count = wallet_ids.len();
    if count == 0 {
        // No wallet IDs configured — generate empty array (dev/test mode).
        generated.push_str("pub const GENESIS_LOCKUP_WALLET_IDS: [&str; 0] = [];\n");
    } else {
        generated.push_str(&format!(
            "pub const GENESIS_LOCKUP_WALLET_IDS: [&str; {}] = [\n{}\n];\n",
            count,
            wallet_array_entries.join(",\n"),
        ));
    }

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join("protocol_constants.rs");
    // ── THE DISTRIBUTION MUST ADD UP, OR THIS DOES NOT COMPILE ──────────
    //
    // the owner, 2026-09-04: the whole allocation is one table in the TOML, and if
    // the rows do not sum to the declared supply the build REFUSES. A test
    // would be weaker: tests are run when someone remembers, and the two that
    // policed these numbers lived in different crates and still let a payout
    // change land half-applied (Nabla debiting 500 for a claim Core minted at
    // 505 — money created against a pool that never paid).
    //
    // The two subsidy pools are DERIVED (slots x claim) and checked here for
    // the same reason: a derived value with a hand-typed copy is a copy that
    // eventually disagrees.
    {
        let num = |name: &str| -> Option<u128> {
            entries.iter().find(|(k, _)| k == name)
                .and_then(|(_, v)| v.replace('_', "").parse::<u128>().ok())
        };
        let need = |name: &str| -> u128 {
            num(name).unwrap_or_else(|| panic!(
                "protocol_core.toml: `{name}` is missing or not a number — the \
                 genesis distribution table must be complete for the build to \
                 verify it"))
        };

        let declared = need("genesis_supply_total_axc");
        let rows: Vec<(&str, u128)> = vec![
            ("pool_genesis_axc", need("pool_genesis_axc")),
            ("pool_market_axc", need("pool_market_axc")),
            ("pool_validator_emission_axc", need("pool_validator_emission_axc")),
            ("pool_foundation_bootstrap_axc", need("pool_foundation_bootstrap_axc")),
            ("pool_airdrop_axc", need("pool_airdrop_axc")),
            ("pool_srp_axc", need("pool_srp_axc")),
            ("pool_developer_axc", need("pool_developer_axc")),
            ("pool_bootstrap_axc", need("pool_bootstrap_axc")),
            ("pool_architecture_axc", need("pool_architecture_axc")),
        ];
        let total: u128 = rows.iter().map(|(_, v)| *v).sum();
        if total != declared {
            let table = rows.iter()
                .map(|(k, v)| format!("    {k:<32} {v:>12}"))
                .collect::<Vec<_>>().join("\n");
            panic!(
                "\n\nGENESIS DISTRIBUTION DOES NOT ADD UP.\n\n{table}\n    \
                 {:<32} {:>12}\n    {:<32} {:>12}\n    {:<32} {:>12}\n\n\
                 Every row of the supply is declared in protocol_core.toml and \
                 must sum to `genesis_supply_total_axc`. Fix the table — do not \
                 relax this check: the sum IS the supply cap, and a distribution \
                 that does not add up is either unspendable coins or coins \
                 nobody funded.\n",
                "SUM", total, "declared total", declared,
                "difference", (total as i128 - declared as i128).unsigned_abs(),
            );
        }

        // Derived pools: slots x claim, never typed twice.
        for (pool, slots, claim) in [
            ("pool_foundation_bootstrap_axc", "foundation_subsidised_slots", "tier2_claim_axc"),
            ("pool_bootstrap_axc", "community_subsidised_slots", "tier3_claim_axc"),
        ] {
            let expected = need(slots) * need(claim);
            if need(pool) != expected {
                panic!(
                    "\n\n`{pool}` = {} but {slots} x {claim} = {} x {} = {}.\n\
                     A subsidy pool must divide EXACTLY by its claim: left over, \
                     it is supply nobody can spend; short, it is a grant the pool \
                     cannot fund. Neither shows up at runtime.\n",
                    need(pool), need(slots), need(claim), expected,
                );
            }
        }
    }

    fs::write(&out_path, generated).expect("Failed to write protocol_constants.rs");
}
