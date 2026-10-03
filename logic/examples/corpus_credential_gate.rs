//! ARTIFACT gate: the published conformance corpus must carry NO usable credential.
//!
//! KI#49 D1 (2026-10-01, pre-ceremony blocker). `tests/consensus_vectors.json`
//! ships in the public `axiom-core` repo. Its CL3 FACT vectors carry certificates
//! signed by the root keys, and Core accepts a FACT witness that binds through a
//! presented certificate (`fact::certify_presented`). If the SECRET behind such a
//! certificate's subject key can be derived from public data, the corpus hands
//! out a k=3 FACT-witness credential for every network running those roots.
//! Until 2026-10-01 it did: the generator derived the subject keys from
//! `StdRng::from_seed([seed; 32])` (seeds 0x11/0x22/0x33 — public).
//!
//! This gate reads the ARTIFACT, not the generator source: it decodes every
//! vector's inputs with the production IPC codec (and walks each vector's JSON), finds every
//! certificate that carries signatures, and refuses if any subject key
//! (Dilithium, SPHINCS+ or Ed25519) is one a public seed produces. "Public
//! seed" is measured, not guessed: for the forgery key (Dilithium) every key
//! the pre-fix recipe produces for EVERY seed byte (not just the three that were
//! used), so a regression to the old recipe with a different byte is caught too.
//!
//!   - Dilithium (ML-DSA-65): `StdRng::from_seed([b; 32])`, first 4 keys, b = 0..=255
//!   - SPHINCS+ (SLH-DSA-SHA2-128s): the exact pre-fix recipe `[seed ^ 0xA5, i, 0, …]`
//!     for seed ∈ {0x11, 0x22, 0x33, 0x5A}, i < 4 (narrower — see `public_sphincs_pks`)
//!   - Ed25519: secret `[b; 32]`, b = 0..=255
//!
//! It is a NEGATIVE check — it proves the subject keys are not from that public
//! family, not that they came from the root-secret KDF (that would need the
//! root secrets, which a D-check or a publish does not hold).
//!
//! Exit 0 = clean; exit 1 = a credential found, or the corpus could not be read
//! completely (an undecodable vector is a FAIL, never a skip — RULE 6).
//!
//! Run (release — the keygens are slow in debug; ~5 s in release):
//!   cargo run --release -p axiom-core-logic --example corpus_credential_gate $(python3 scripts/build_profile.py --features axiom-core-logic) -- tests/consensus_vectors.json

use std::collections::HashMap;

use rand::SeedableRng;
use serde_json::Value;

/// What produced a deny-listed key — printed on a hit so the operator sees the recipe.
type Origin = String;

fn public_dilithium_pks() -> HashMap<Vec<u8>, Origin> {
    use fips204::ml_dsa_65;
    use fips204::traits::SerDes;
    let mut m = HashMap::new();
    for b in 0..=255u8 {
        let mut rng = rand::rngs::StdRng::from_seed([b; 32]);
        for i in 0..4 {
            let (pk, _sk) = ml_dsa_65::try_keygen_with_rng(&mut rng).expect("ml-dsa keygen");
            m.insert(pk.into_bytes().to_vec(), format!("ML-DSA-65 StdRng::from_seed([0x{b:02x}; 32]) key #{i}"));
        }
    }
    m
}

fn public_sphincs_pks() -> HashMap<Vec<u8>, Origin> {
    // NARROWER than the Dilithium family, deliberately: SLH-DSA-128s keygen is
    // ~0.2 s, so the all-bytes family (1,280 keys) cost 4 minutes. The SPHINCS+
    // subject secret is not the forgery key (a FACT witness binds through
    // `(blake3(sphincs_pk), dilithium_pk)` and SIGNS with Dilithium — which IS
    // checked over every seed byte above); this pins the exact pre-fix recipe.
    use fips205::slh_dsa_sha2_128s;
    use fips205::traits::SerDes;
    let mut m = HashMap::new();
    for chain_seed in [0x11u8, 0x22, 0x33, 0x5A] {
        for i in 0..4u8 {
            let mut s = [0u8; 32];
            s[0] = chain_seed ^ 0xA5;
            s[1] = i;
            let mut rng = rand::rngs::StdRng::from_seed(s);
            let (pk, _sk) = slh_dsa_sha2_128s::try_keygen_with_rng(&mut rng).expect("slh-dsa keygen");
            m.insert(pk.into_bytes().to_vec(),
                format!("SLH-DSA StdRng::from_seed([0x{chain_seed:02x}^0xA5, {i}, 0…]) (pre-fix recipe)"));
        }
    }
    m
}

fn public_ed25519_pks() -> HashMap<Vec<u8>, Origin> {
    (0..=255u8)
        .map(|b| {
            let sk = ed25519_dalek::SigningKey::from_bytes(&[b; 32]);
            (sk.verifying_key().to_bytes().to_vec(), format!("Ed25519 secret [0x{b:02x}; 32]"))
        })
        .collect()
}

fn as_bytes(v: Option<&Value>) -> Option<Vec<u8>> {
    v?.as_array()?.iter().map(|x| x.as_u64().and_then(|n| u8::try_from(n).ok())).collect()
}

/// Every object in the tree that is a certificate (has the VBC subject/issuer
/// fields). Structural, so a certificate anywhere — fact_certificates,
/// supporting_vbcs, a cheque's or witness's vbc_bundle, an output — is found.
fn collect_certs<'a>(v: &'a Value, out: &mut Vec<&'a serde_json::Map<String, Value>>) {
    match v {
        Value::Object(m) => {
            if m.contains_key("subject_pubkey_dilithium") && m.contains_key("issuer_set") && m.contains_key("signatures") {
                out.push(m);
            }
            for x in m.values() {
                collect_certs(x, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| collect_certs(x, out)),
        _ => {}
    }
}

/// The gate itself, over a parsed corpus. Returns (findings, vectors decoded, signed certs inspected).
fn check_corpus(
    corpus: &Value,
    dil: &HashMap<Vec<u8>, Origin>,
    sph: &HashMap<Vec<u8>, Origin>,
    ed: &HashMap<Vec<u8>, Origin>,
) -> Result<(Vec<String>, usize, usize), String> {
    let vectors = corpus.get("vectors").and_then(|v| v.as_array()).ok_or("corpus has no `vectors` array")?;
    let mut findings = Vec::new();
    let (mut decoded, mut inspected) = (0usize, 0usize);
    for v in vectors {
        let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("<no id>");
        // INPUTS only: the outputs frame (codec `PO_*`, keys 0–21) has no
        // certificate field — and it is lossy (`ve_to_u64` folds unmapped
        // reasons into 9900, which does not decode back), so decoding it would
        // fail on a valid corpus while inspecting nothing.
        let mut trees = Vec::new();
        let hex_str = v.get("inputs_cbor_hex").and_then(|x| x.as_str()).unwrap_or("");
        if !hex_str.is_empty() {
            let bytes = hex::decode(hex_str).map_err(|e| format!("{id}: inputs_cbor_hex is not hex: {e}"))?;
            let pi = axiom_core_ipc::codec::decode_inputs(&bytes).map_err(|e| format!("{id}: inputs do not decode: {e}"))?;
            trees.push(serde_json::to_value(&pi).map_err(|e| format!("{id}: {e}"))?);
            decoded += 1;
        }
        // The JSON body itself too (a reference-only vector could inline a cert).
        trees.push(v.clone());
        for tree in &trees {
            let mut certs = Vec::new();
            collect_certs(tree, &mut certs);
            for c in certs {
                let signed = c.get("signatures").and_then(|s| s.as_array()).map_or(false, |s| !s.is_empty());
                if !signed {
                    continue; // an unsigned certificate certifies nothing
                }
                inspected += 1;
                for (field, set) in [
                    ("subject_pubkey_dilithium", dil),
                    ("subject_pubkey_sphincs", sph),
                    ("subject_pubkey_ed25519", ed),
                ] {
                    if let Some(pk) = as_bytes(c.get(field)) {
                        if let Some(origin) = set.get(&pk) {
                            findings.push(format!(
                                "  {id}: signed certificate (chain_depth {}) has {field} = {origin} — its secret is PUBLIC",
                                c.get("chain_depth").and_then(|d| d.as_u64()).unwrap_or(u64::MAX)
                            ));
                        }
                    }
                }
            }
        }
    }
    if decoded == 0 {
        return Err("no vector carried decodable CBOR — the gate inspected nothing".into());
    }
    Ok((findings, decoded, inspected))
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "tests/consensus_vectors.json".into());
    let corpus: Value = match std::fs::read_to_string(&path).map_err(|e| e.to_string()).and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string())) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("corpus_credential_gate: FAIL — cannot read {path}: {e}");
            std::process::exit(1);
        }
    };
    let (dil, sph, ed) = (public_dilithium_pks(), public_sphincs_pks(), public_ed25519_pks());
    match check_corpus(&corpus, &dil, &sph, &ed) {
        Err(e) => {
            eprintln!("corpus_credential_gate: FAIL — {e}");
            std::process::exit(1);
        }
        Ok((findings, decoded, inspected)) => {
            println!(
                "corpus_credential_gate: {decoded} vectors decoded, {inspected} signed certificate(s) inspected against {} public-seed keys",
                dil.len() + sph.len() + ed.len()
            );
            if findings.is_empty() {
                println!("corpus_credential_gate: PASS — no signed certificate's subject secret is derivable from public data");
            } else {
                println!("corpus_credential_gate: FAIL — the corpus carries a USABLE credential (KI#49 D1):\n{}", findings.join("\n"));
                std::process::exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cert(dil: Vec<u8>, signed: bool) -> Value {
        json!({ "subject_pubkey_dilithium": dil, "subject_pubkey_sphincs": [1, 2, 3],
                "subject_pubkey_ed25519": vec![0x11u8; 32], "issuer_set": [[9]],
                "signatures": if signed { json!([[1]]) } else { json!([]) }, "chain_depth": 0 })
    }

    /// The gate must FIND a public-seed subject (red) and pass a non-public one
    /// (green), and must not count an unsigned certificate. Exercised on the
    /// structural walk + the deny sets directly; the codec leg is exercised by
    /// running the binary on the real corpus (see the KI#49 entry).
    #[test]
    fn public_seed_subject_is_found_and_unsigned_is_ignored() {
        let dil = public_dilithium_pks();
        let (pub_pk, _) = dil.iter().find(|(_, o)| o.contains("0x11; 32]) key #0")).unwrap();
        let mut found = Vec::new();
        let tree = json!({ "a": [cert(pub_pk.clone(), true), cert(vec![7u8; 1952], true), cert(pub_pk.clone(), false)] });
        collect_certs(&tree, &mut found);
        assert_eq!(found.len(), 3);
        let hits: Vec<_> = found.iter()
            .filter(|c| c["signatures"].as_array().unwrap().len() > 0)
            .filter_map(|c| as_bytes(c.get("subject_pubkey_dilithium")))
            .filter(|pk| dil.contains_key(pk))
            .collect();
        assert_eq!(hits.len(), 1, "exactly the signed public-seed cert is a hit");
    }

    #[test]
    fn a_corpus_with_nothing_decodable_is_a_failure_not_a_pass() {
        let empty = HashMap::new();
        let corpus = json!({ "vectors": [ { "id": "X", "inputs_cbor_hex": "", "outputs_cbor_hex": "" } ] });
        assert!(check_corpus(&corpus, &empty, &empty, &empty).is_err());
    }
}
