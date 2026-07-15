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
    for (key_lower, value) in &entries {
        if let Some(base) = key_lower.strip_suffix("_dev") {
            if has(base) {
                // dev half of a pair — emitted under the BASE name.
                generated.push_str(&format!(
                    "#[cfg(feature = \"dev-mode\")]\npub const {}: u64 = {};\n",
                    base.to_uppercase(),
                    value
                ));
                continue;
            }
        }
        if has(&format!("{key_lower}_dev")) {
            // prod half of a pair.
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

    // Genesis lockup wallet IDs — read from genesis_lockup_wallets.txt.
    // Each non-empty, non-comment line is a wallet_id string.
    // Generates: pub const GENESIS_LOCKUP_WALLET_IDS: [&str; N] = [...];
    let wallet_ids: Vec<String> = if wallets_path.exists() {
        fs::read_to_string(wallets_path)
            .expect("Failed to read genesis_lockup_wallets.txt")
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    } else {
        vec![]
    };

    let wallet_array_entries: Vec<String> = wallet_ids
        .iter()
        .map(|id| format!("    \"{}\"", id))
        .collect();

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
    fs::write(&out_path, generated).expect("Failed to write protocol_constants.rs");
}
