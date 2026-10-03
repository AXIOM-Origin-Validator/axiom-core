//! DMAP-VM vs zk-VM differential conformance harness.
//!
//! # What this actually checks, and why it is NOT what CLAUDE.md claimed
//!
//! Until 2026-07-31 `CLAUDE.md` asserted:
//!
//!   "Both VMs MUST produce identical PublicOutputs for the same PublicInputs
//!    + the same axiom-core.elf. Conformance is checked by run_conformance.py."
//!
//! Every clause of that was wrong, and the last one was load-bearing:
//!
//! 1. **`run_conformance.py` never touches the zkVM.** It feeds the vector
//!    corpus to a Core binary over CBOR IPC — the third-party-reimplementation
//!    harness. Nothing checked the two-VM invariant at all.
//! 2. **They do not run the same file.** `core/logic` is compiled twice:
//!    `core/artifacts/axiom-core.elf` (riscv32im avm-guest, the CoreID artifact)
//!    and `~/.axiom/zkvm/axiom-core.elf` (risc0 zkvm-guest). Same filename,
//!    different binaries. Nothing in the build or deploy flow rebuilds the zkVM
//!    one — it was found a MONTH stale, predating RECALL, so every vector
//!    carrying `recall_target_tx_id` made the guest panic on decode.
//! 3. **"identical PublicOutputs" is architecturally impossible.** The zkVM
//!    guest is deliberately a MINIMAL ZK CHECKPOINT (see its own header): it
//!    proves client authorization, balance non-inflation, state-chain
//!    continuity, anti-replay and a few protocol rules. Dilithium FACT signing,
//!    FACT-chain verification, witness validation, txid and commitment_hash are
//!    executed NATIVELY on the host, outside the ZK boundary. The guest commits
//!    `ZkpCheckpointOutputs` — a strict subset — and never a `PublicOutputs`.
//!
//! A corollary of (3): `ZkvmProver::prove()`, whose signature returned
//! `PublicOutputs`, could never succeed against this guest. DELETED 2026-09-02
//! along with the `first-proof` / `zkp-demo` bins and the seven `#[ignore]`d
//! tests that drove it. The live path is `prove_checkpoint()`, which
//! `prover-worker` and Lambda both use.
//!
//! So this harness compares what can honestly be compared: the fields the
//! checkpoint actually COMPUTES.
//!
//! # The comparison set
//!
//! COMPARED — independently derived on both sides, so a mismatch is a real
//! consensus disagreement:
//!   result, produced_state_id, new_balance, new_wallet_seq, rejection_reason
//!
//! DELIBERATELY EXCLUDED — comparing these would be a check that cannot fail:
//!   fact_signature, txid   passthrough cargo: the guest copies them straight
//!                          from the native outputs it is handed, so comparing
//!                          them to those same native outputs is a tautology.
//!   (fact_commitment       field DELETED 2026-09-28, Fork Settlement R35 — it
//!                          was a stale guest hand copy nobody read.)
//!   input_hash             guest-internal SHA256 over the guest's own frame;
//!                          the DMAP side has no counterpart.
//!   zkp_nonce_hash         `execute_cl3_zkp_checkpoint` returns None and lets
//!                          the caller fill it, so it carries no guest claim.
//!
//! `produced_state_id` is genuinely independent — the checkpoint recomputes it
//! via `compute_produced_state_id(balance, seq, …)` rather than copying it. That
//! is what makes Lambda's one-field check at `lambda/src/core_client.rs:443`
//! meaningful, and this harness extends the same idea across the whole corpus
//! and to the reject side (Lambda's check sits inside the `Accept` arm, so a
//! DMAP-rejects/zkVM-accepts divergence is invisible to it).
//!
//! # Failure modes this harness refuses to have
//!
//! This session found seven "checks" that could not fail. This one is built to
//! fail loudly:
//!
//! * **No silent skips.** A decode error or a prove error is a FAILURE.
//! * **Zero executed is a failure.** A corpus that stops executing can never
//!   masquerade as a pass.
//! * **`--min-vectors` floor.** Assert a minimum count actually executed, so a
//!   corpus quietly shrinking goes red.
//! * **A missing `prove` feature is a FAILURE, not a skip.** Without it
//!   `prove_checkpoint` returns `Err`, and calling that "skipped" would make the
//!   whole harness vacuous.
//! * **`--limit` bounds cost, never correctness.** It caps how many vectors are
//!   proven (a risc0 STARK is minutes each); the floor and the zero-check still
//!   apply, and the number actually proven is always printed.
//!
//! # Usage
//!
//!   cargo run --release -p axiom-zk-vm \
//!     --features prove --features axiom-core-logic/dev-mode \
//!     --example differential_conformance -- [--limit N] [--min-vectors N]
//!
//! Both guests MUST be built with matching features — the avm-guest is built
//! with `axiom-core-logic/dev-mode`, so the zkvm-guest needs
//! `core/build-zkvm.sh --local --dev`. A feature mismatch makes them disagree
//! on dev-twin constants: a false divergence that looks exactly like a real one.

use std::path::PathBuf;
use std::process::ExitCode;

use axiom_core_logic::modes::ZkpCheckpointOutputs;
use axiom_core_logic::types::PublicOutputs;
use axiom_dmap_vm::AvmInterpreter;
use axiom_zk_vm::config::ZkvmConfig;
use axiom_zk_vm::prover::ZkvmProver;

/// A single vector's verdict. There is deliberately no `Skipped`.
///
/// `NoInputs` is not a skip in disguise: it records a vector carrying an EMPTY
/// `inputs_cbor_hex` — a defect in the committed corpus, not in either VM. No
/// implementation can execute it, yet it still declares an `expected_result`.
/// It is reported loudly and never counted as a pass; the `--min-vectors` floor
/// is what stops it becoming a hiding place.
enum Verdict {
    Match,
    Diverged { fields: Vec<String> },
    Failed { stage: &'static str, err: String },
    NoInputs,
    /// Vector is not in the checkpoint's domain (see `CHECKPOINT_MODE`).
    WrongMode(String),
    /// The DMAP-VM rejected on a check the checkpoint NEVER runs — FACT-chain
    /// verification and witness validation are native-only by design (the
    /// security analysis above `execute_cl3_zkp_checkpoint`: "Dilithium FACT
    /// signing, FACT chain verification, witness validation … run NATIVELY"),
    /// and production proves ONLY after native execution accepted, with
    /// `fact_witness_sigs` stripped from the guest's inputs
    /// (`lambda/src/core_client.rs`). A natively-rejected FACT vector never
    /// reaches the prover, so diffing the guest against it compares two
    /// functions on different domains — the CL1 artifact of 2026-07-31 in
    /// another coat. Found 2026-09-11: the two `CL3_FACT_*` reject vectors
    /// (added 2026-08-01, the day AFTER the last green run) "diverged".
    NativeGated(String),
}

/// Rejection reasons the zk checkpoint cannot produce because the check that
/// yields them runs natively before the prover is ever called. Exactly the
/// FACT-chain / witness family; nothing else is gated here.
fn is_native_only_reason(reason: &str) -> bool {
    reason.starts_with("Fact")
}

/// The zkVM guest runs `execute_cl3_zkp_checkpoint`, which implements **CL3
/// semantics and ignores `inputs.mode` entirely**. Feeding it a CL1/CL2/CL5/CL11
/// vector and diffing against the DMAP-VM's mode-aware output compares two
/// different functions and manufactures divergences that are artifacts of the
/// harness, not defects in either VM.
///
/// Observed concretely on 2026-07-31: `CL1_ACCEPT_001` reported
/// `new_balance: dmap=None zk=Some(9500000)`. The DMAP side is correct — the
/// corpus itself records `expected_new_balance: None`, because CL1 is the client
/// self-check and does not settle a balance. The checkpoint computed
/// `balance - amount` anyway, because that is what CL3 does.
///
/// So this harness only compares vectors it is entitled to compare.
const CHECKPOINT_MODE: &str = "CL3";

fn main() -> ExitCode {
    let mut avm_elf = PathBuf::from("core/artifacts/axiom-core.elf");
    let home = std::env::var("HOME").unwrap_or_default();
    let mut zk_elf = PathBuf::from(format!("{home}/.axiom/zkvm/axiom-core.elf"));
    let mut zk_image_id = PathBuf::from(format!("{home}/.axiom/zkvm/image-id.hex"));
    let mut vectors = PathBuf::from("tests/consensus_vectors.json");
    let mut limit: Option<usize> = None;
    let mut min_vectors: usize = 1;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--avm-elf" => { avm_elf = PathBuf::from(&args[i + 1]); i += 2; }
            "--zk-elf" => { zk_elf = PathBuf::from(&args[i + 1]); i += 2; }
            "--zk-image-id" => { zk_image_id = PathBuf::from(&args[i + 1]); i += 2; }
            "--vectors" => { vectors = PathBuf::from(&args[i + 1]); i += 2; }
            "--limit" => { limit = args[i + 1].parse().ok(); i += 2; }
            "--min-vectors" => { min_vectors = args[i + 1].parse().unwrap_or(1); i += 2; }
            other => { eprintln!("unknown arg: {other}"); return ExitCode::from(2); }
        }
    }

    println!("DMAP-VM vs zk-VM checkpoint differential");
    println!("  avm-elf : {}", avm_elf.display());
    println!("  zk-elf  : {}", zk_elf.display());
    println!("  vectors : {}", vectors.display());
    println!("  compares: result, produced_state_id, new_balance, new_wallet_seq, rejection_reason");
    println!("  excluded: fact_signature/txid (passthrough cargo — comparing them cannot fail)");

    let raw = match std::fs::read_to_string(&vectors) {
        Ok(r) => r,
        Err(e) => { eprintln!("FAIL: cannot read vectors: {e}"); return ExitCode::from(2); }
    };
    let doc: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(d) => d,
        Err(e) => { eprintln!("FAIL: vectors are not valid JSON: {e}"); return ExitCode::from(2); }
    };
    let list = match doc.get("vectors").and_then(|v| v.as_array()) {
        Some(l) => l.clone(),
        None => { eprintln!("FAIL: vectors file has no `vectors` array"); return ExitCode::from(2); }
    };
    println!("  corpus  : {} vector(s)\n", list.len());

    let elf_bytes = match std::fs::read(&avm_elf) {
        Ok(b) => b,
        Err(e) => { eprintln!("FAIL: cannot read avm ELF: {e}"); return ExitCode::from(2); }
    };
    let avm = AvmInterpreter::new(elf_bytes, [0u8; 32]);

    let zk_cfg = ZkvmConfig::new(&zk_elf, &zk_image_id);
    let mut prover = match ZkvmProver::production_with_config(zk_cfg) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("FAIL: cannot construct the zkVM prover: {e:?}");
            eprintln!("      Built without --features prove, or ~/.axiom/zkvm artifacts");
            eprintln!("      missing (run core/build-zkvm.sh --local --dev). Either way this");
            eprintln!("      is a FAILURE, not a skip — a harness that skips proves nothing.");
            return ExitCode::from(2);
        }
    };

    let mut executed = 0usize;
    let mut diverged = 0usize;
    let mut failed = 0usize;
    let mut no_inputs: Vec<String> = Vec::new();
    let mut wrong_mode: std::collections::BTreeMap<String, usize> = Default::default();
    let mut native_gated: Vec<String> = Vec::new();

    for v in list.iter() {
        let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("<no id>");
        if let Some(n) = limit {
            if executed >= n {
                println!("  [stop] --limit {n} reached; remaining vectors not proven this run");
                break;
            }
        }

        match run_one(v, &avm, &mut prover) {
            Verdict::Match => { executed += 1; println!("  [ok]   {id}"); }
            Verdict::Diverged { fields } => {
                executed += 1; diverged += 1;
                println!("  [DIVERGED] {id}");
                for f in fields { println!("      {f}"); }
            }
            Verdict::Failed { stage, err } => {
                failed += 1;
                println!("  [FAIL] {id} — {stage}: {err}");
            }
            Verdict::NoInputs => {
                no_inputs.push(id.to_string());
                println!("  [no-inputs] {id} — empty inputs_cbor_hex; CORPUS defect, not executed");
            }
            Verdict::WrongMode(m) => {
                *wrong_mode.entry(m).or_insert(0usize) += 1;
            }
            Verdict::NativeGated(r) => {
                native_gated.push(format!("{id} ({r})"));
                println!("  [native-gated] {id} — DMAP rejected {r}: a check the checkpoint never runs; production would not prove it");
            }
        }
    }

    println!(
        "\n  executed: {executed}   diverged: {diverged}   failed: {failed}   no-inputs: {}",
        no_inputs.len()
    );
    if !no_inputs.is_empty() {
        println!(
            "  NOTE: {} corpus vector(s) carry no inputs and were checked by NEITHER\n\
             \x20       VM: {}. They still declare an expected_result, so anyone\n\
             \x20       counting corpus entries over-counts what is verified. Fix\n\
             \x20       `generate_vectors` and regenerate rather than ignoring them.",
            no_inputs.len(),
            no_inputs.join(", ")
        );
    }

    if !native_gated.is_empty() {
        println!(
            "  {} vector(s) rejected natively on a FACT/witness check the checkpoint never runs, not compared: {}",
            native_gated.len(), native_gated.join(", ")
        );
    }
    if !wrong_mode.is_empty() {
        let skipped: usize = wrong_mode.values().sum();
        let breakdown: Vec<String> =
            wrong_mode.iter().map(|(m, n)| format!("{m}×{n}")).collect();
        println!(
            "  {skipped} vector(s) outside the checkpoint's CL3 domain, not compared: {}",
            breakdown.join(", ")
        );
    }

    if executed == 0 {
        eprintln!();
        eprintln!("FAIL: ZERO vectors were compared. This is NOT a pass.");
        if !wrong_mode.is_empty() {
            eprintln!();
            eprintln!("  Cause: the committed corpus contains NO {CHECKPOINT_MODE} vectors.");
            eprintln!("  The zkVM guest runs `execute_cl3_zkp_checkpoint` — CL3 semantics,");
            eprintln!("  mode-blind — so CL1/CL2/CL5/CL11 vectors cannot be compared against");
            eprintln!("  it without manufacturing false divergences.");
            eprintln!();
            eprintln!("  CONSEQUENCE: the DMAP-VM/zk-VM equivalence is currently");
            eprintln!("  UNVERIFIABLE against this corpus. It is not passing; it is unchecked.");
            eprintln!("  Do not paper over this by loosening the mode gate — that trades a");
            eprintln!("  known gap for a green light that means nothing.");
            eprintln!();
            eprintln!("  FIX: emit CL3 vectors from `generate_vectors`");
            eprintln!("       (cargo run -p axiom-core-logic --example generate_vectors)");
            eprintln!("       and commit the regenerated tests/consensus_vectors.json.");
        }
        return ExitCode::from(1);
    }
    if executed < min_vectors {
        eprintln!("FAIL: only {executed} vector(s) executed, below --min-vectors {min_vectors}.");
        return ExitCode::from(1);
    }
    if diverged > 0 || failed > 0 {
        eprintln!("FAIL: {diverged} divergence(s), {failed} error(s).");
        eprintln!("      A divergence means the two independent compilations of core/logic");
        eprintln!("      disagree about a consensus-critical field. Do not dismiss it as a");
        eprintln!("      harness artifact without first confirming BOTH guests were built");
        eprintln!("      from the same commit with the same features.");
        return ExitCode::from(1);
    }

    println!("\nPASS — the checkpoint fields agree on all {executed} executed vector(s).");
    ExitCode::SUCCESS
}

/// Compare the fields the checkpoint independently computes.
fn compare(dmap: &PublicOutputs, zk: &ZkpCheckpointOutputs) -> Vec<String> {
    let mut d = Vec::new();
    if dmap.result != zk.result {
        d.push(format!("result: dmap={:?} zk={:?}", dmap.result, zk.result));
    }
    if dmap.produced_state_id != zk.produced_state_id {
        d.push(format!(
            "produced_state_id: dmap={} zk={}",
            opt_hash(&dmap.produced_state_id),
            opt_hash(&zk.produced_state_id)
        ));
    }
    if dmap.new_balance != zk.new_balance {
        d.push(format!("new_balance: dmap={:?} zk={:?}", dmap.new_balance, zk.new_balance));
    }
    if dmap.new_wallet_seq != zk.new_wallet_seq {
        d.push(format!("new_wallet_seq: dmap={:?} zk={:?}", dmap.new_wallet_seq, zk.new_wallet_seq));
    }
    // Compare the rejection reason by its rendered form: the two sides may be
    // built from the same enum, but a divergence in WHICH rule fired is exactly
    // the kind of disagreement worth surfacing.
    let dr = dmap.rejection_reason.as_ref().map(|r| format!("{r:?}"));
    let zr = zk.rejection_reason.as_ref().map(|r| format!("{r:?}"));
    if dr != zr {
        d.push(format!("rejection_reason: dmap={dr:?} zk={zr:?}"));
    }
    d
}

fn opt_hash(h: &Option<[u8; 32]>) -> String {
    match h {
        Some(b) => hex::encode(&b[..8]),
        None => "None".to_string(),
    }
}

fn run_one(
    v: &serde_json::Value,
    avm: &AvmInterpreter,
    prover: &mut ZkvmProver,
) -> Verdict {
    // No inputs at all is a CORPUS defect; inputs present but undecodable is a
    // real FAILURE. The two are never collapsed.
    // Domain gate FIRST — before spending minutes on a STARK proof that could
    // only ever produce a meaningless comparison.
    let mode = v.get("mode").and_then(|x| x.as_str()).unwrap_or("<none>");
    if mode != CHECKPOINT_MODE {
        return Verdict::WrongMode(mode.to_string());
    }

    let hex_in = match v.get("inputs_cbor_hex").and_then(|x| x.as_str()) {
        Some(h) if !h.is_empty() => h,
        _ => return Verdict::NoInputs,
    };
    let bytes = match hex::decode(hex_in) {
        Ok(b) => b,
        Err(e) => return Verdict::Failed { stage: "hex-decode", err: e.to_string() },
    };
    // Vectors are integer-keyed canonical CBOR — decode via core/ipc, not plain
    // serde, which would silently produce a different byte string.
    let inputs = match axiom_core_ipc::codec::decode_inputs(&bytes) {
        Ok(i) => i,
        Err(e) => return Verdict::Failed { stage: "cbor-decode", err: e },
    };

    let dmap_out = match avm.execute(inputs.clone()) {
        Ok(o) => o,
        Err(e) => return Verdict::Failed { stage: "dmap-vm", err: format!("{e:?}") },
    };
    // Second domain gate: a native-only rejection (FACT chain / witnesses)
    // is the host's verdict, not the checkpoint's — production never proves
    // it. Named and counted, never silently skipped.
    if let Some(r) = dmap_out.rejection_reason.as_ref() {
        let r = format!("{r:?}");
        if is_native_only_reason(&r) {
            return Verdict::NativeGated(r);
        }
    }

    // Mirror production exactly: `prover-worker` and Lambda both call
    // prove_checkpoint with the native outputs as FACT passthrough cargo. Those
    // passthrough fields are excluded from `compare` precisely because handing
    // them in and then comparing them would be a check that cannot fail.
    let (zk_out, _receipt) = match prover.prove_checkpoint(inputs, Some(dmap_out.clone())) {
        Ok(o) => o,
        Err(e) => return Verdict::Failed { stage: "zk-vm", err: format!("{e:?}") },
    };

    let d = compare(&dmap_out, &zk_out);
    if d.is_empty() { Verdict::Match } else { Verdict::Diverged { fields: d } }
}
