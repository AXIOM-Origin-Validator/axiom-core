//! Verify each certificate LEVEL of a dumped VBC bundle separately, so a
//! failure names the CERTIFICATE instead of an anonymous "signature 0".
//!
//! Written 2026-09-04 after `verify_vbc_bundle` refused an assembled
//! certificate with `InvalidVBC` and "signature 0 matches no eligible signer
//! key". The message pointed a reader at the certificate being ISSUED, which
//! was fine — the failure was three levels down, in the genesis issuer certs
//! the harness had rebuilt with one wrong field. This example located that in
//! seconds against the dumped artifact, with no env and no round.
//!
//! Usage: `cargo run -p axiom-core-logic --features dev-mode \
//!         --example inspect_bundle -- <vbc_request_*.diag>`
use axiom_core_logic::types::VBCProofBundle;

fn main() {
    let path = std::env::args().nth(1).expect("usage: inspect_bundle <diag file>");
    let text = std::fs::read_to_string(&path).expect("read");
    let hex_line = text.lines().skip_while(|l| !l.contains("bundle_cbor_hex")).nth(1)
        .expect("no bundle_cbor_hex in dump");
    let bytes = hex::decode(hex_line.trim()).expect("hex");
    let bundle: VBCProofBundle = ciborium::de::from_reader(&bytes[..]).expect("cbor");

    let t = &bundle.target_vbc;
    println!("TARGET subject={} depth={} issuers={} sigs={} lineage={} baseline=({}, tick {})",
             hex::encode(&t.subject_pubkey_sphincs[..8]), t.chain_depth,
             t.issuer_set.len(), t.signatures.len(),
             hex::encode(&t.genesis_lineage[..8]),
             t.network_size_baseline, t.baseline_tick);
    println!("  target issued_at={} expires_at={} provisional={} nabla_stamp={}",
             t.issued_at, t.expires_at,
             axiom_core_logic::validation::vbc_is_provisional(t.issued_at, t.expires_at),
             t.nabla_registration.is_some());
    println!("supporting_vbcs: {}", bundle.supporting_vbcs.len());
    for c in &bundle.supporting_vbcs {
        println!("  subject={} depth={} issuers={} sigs={} lineage={} baseline=({}, tick {}) expires={} nabla_stamp={}",
                 hex::encode(&c.subject_pubkey_sphincs[..8]), c.chain_depth,
                 c.issuer_set.len(), c.signatures.len(),
                 hex::encode(&c.genesis_lineage[..8]),
                 c.network_size_baseline, c.baseline_tick, c.expires_at,
                 c.nabla_registration.is_some());
    }

    // Verify each SUPPORTING cert on its own — this is the recursion level the
    // bundle verify reaches after the target passes.
    for c in &bundle.supporting_vbcs {
        let solo = VBCProofBundle { target_vbc: c.clone(), supporting_vbcs: bundle.supporting_vbcs.clone(), candidacy_pulse: None, renewal_work_receipt: None };
        let r = axiom_core_logic::vbc::verify_vbc_bundle_no_time(&solo);
        println!("  verify(subject={}) -> {:?}", hex::encode(&c.subject_pubkey_sphincs[..8]), r);
    }
    println!("whole bundle LIVE (stamp required) -> {:?}", axiom_core_logic::vbc::verify_vbc_bundle_no_time(&bundle));
    println!("whole bundle HISTORICAL (chain only) -> {:?}", axiom_core_logic::vbc::verify_vbc_bundle_historical(&bundle, 0));
}
