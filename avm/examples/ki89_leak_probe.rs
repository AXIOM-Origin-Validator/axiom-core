//! KI#89 leak probe — MEASURES whether the AVM hot path Lambda runs per request
//! retains memory without bound. Read-only harness: no protocol code changed.
//!
//! A counting global allocator (wrapping `System`) gives the LIVE heap bytes
//! (alloc − dealloc) — the analogue of jemalloc `stats.allocated` — so a real
//! leak (live bytes growing per call) is separated from allocator retention
//! (RSS growing while live bytes stay flat). VmRSS/VmSwap/VmHWM are sampled
//! from /proc/self/status beside it.
//!
//! Stages (first arg):
//!   execute       persistent AvmInterpreter, `execute()` (CL1/CL2 path, unaudited)
//!   audited       `execute_audited()` (CL5 redeem path, joins the YPX-009 chain)
//!   dmap          `execute_with_dmap()` (non-final CL3 hop)
//!   dmap_audited  `execute_with_dmap_audited()` (finalizing CL3)
//!   threads       `execute()` with every call on a FRESH OS thread (thread-local
//!                 GuestMemory cache churn — the tokio block_in_place shape)
//!   sizes         no loop: HEAP bytes (counting-allocator delta of a clone) of
//!                 each vector's heavy fields — the per-entry cost of anything
//!                 Lambda RETAINS that embeds them (e.g. the idempotency caches)
//!   cheque        no loop: `<stage> 0 _ <sdk-cheque.cbor>...` — decode REAL soak
//!                 cheque files (SDK `cheques/` dir) into `ValidatorCheque` and
//!                 report the HEAP bytes of one cheque and of its sender FACT
//!                 chain: the two FACT-chain-bearing members of the finalize
//!                 `WitnessResponse` Lambda caches (`remember_witness_response`)
//!   new_avm       construct + drop an AvmInterpreter per iteration (JIT compile
//!                 + JITModule drop; Lambda does this ONCE — control stage)
//!
//! Usage:
//!   cargo run --release -p axiom-dmap-vm --example ki89_leak_probe \
//!       $(python3 scripts/build_profile.py --features axiom-dmap-vm) -- \
//!       <stage> <iterations> <elf> <consensus_vectors.json> [vector-id-substring]

use axiom_core_ipc::codec::decode_inputs;
use axiom_core_logic::types::PublicInputs;
use axiom_dmap_vm::AvmInterpreter;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

struct Counting;
static LIVE: AtomicI64 = AtomicI64::new(0);
static ALLOCS: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() { LIVE.fetch_add(l.size() as i64, Ordering::Relaxed); ALLOCS.fetch_add(1, Ordering::Relaxed); }
        p
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() { LIVE.fetch_add(l.size() as i64, Ordering::Relaxed); ALLOCS.fetch_add(1, Ordering::Relaxed); }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        LIVE.fetch_sub(l.size() as i64, Ordering::Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        let q = System.realloc(p, l, n);
        if !q.is_null() { LIVE.fetch_add(n as i64 - l.size() as i64, Ordering::Relaxed); }
        q
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn status_kb(key: &str) -> i64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    s.lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(-1)
}

/// Executable (JIT) mappings: count + total KB from /proc/self/maps — a JIT
/// code-buffer leak shows here even though it never touches the heap counter.
fn exec_maps_kb() -> (usize, u64) {
    let s = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
    let mut n = 0; let mut kb = 0u64;
    for l in s.lines() {
        let mut it = l.split_whitespace();
        let (range, perms) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
        let path = l.split_whitespace().nth(5);
        if perms.contains('x') && path.is_none() {
            if let Some((a, b)) = range.split_once('-') {
                let a = u64::from_str_radix(a, 16).unwrap_or(0);
                let b = u64::from_str_radix(b, 16).unwrap_or(0);
                n += 1; kb += (b - a) / 1024;
            }
        }
    }
    (n, kb)
}

#[derive(Clone, Copy)]
struct Sample { it: usize, live: i64, rss: i64, swap: i64, exec_kb: u64, exec_n: usize }

fn sample(it: usize) -> Sample {
    let (exec_n, exec_kb) = exec_maps_kb();
    Sample { it, live: LIVE.load(Ordering::Relaxed), rss: status_kb("VmRSS:"), swap: status_kb("VmSwap:"), exec_kb, exec_n }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 5 {
        eprintln!("usage: {} <stage> <iterations> <elf> <vectors.json> [small|id1,id2,..]", a[0]);
        std::process::exit(2);
    }
    let stage = a[1].clone();
    let iters: usize = a[2].parse().expect("iterations");
    let elf = std::fs::read(&a[3]).expect("read elf");
    let filter = a.get(5).cloned();

    if stage == "cheque" { cheque_sizes(&a[4..]); return; }

    let raw = std::fs::read_to_string(&a[4]).expect("read vectors");
    let json: serde_json::Value = serde_json::from_str(&raw).expect("json");
    let mut inputs: Vec<(String, PublicInputs)> = Vec::new();
    for v in json["vectors"].as_array().expect("vectors") {
        let id = v["id"].as_str().unwrap_or("?").to_string();
        let Some(h) = v["inputs_cbor_hex"].as_str() else { continue };
        let Ok(b) = hex::decode(h) else { continue };
        if b.is_empty() { continue; }
        // Filter: "small" = every vector whose CBOR is < 10 KB (the fast
        // CL1/CL2/CL3/CL5/CL11 shapes); otherwise comma-separated id substrings.
        if let Some(f) = &filter {
            let keep = if f == "small" { b.len() < 10_000 } else { f.split(',').any(|x| id.contains(x)) };
            if !keep { continue; }
        }
        match decode_inputs(&b) { Ok(i) => inputs.push((id, i)), Err(e) => eprintln!("skip {}: {}", id, e) }
    }
    assert!(!inputs.is_empty(), "no vectors selected");
    eprintln!("[KI89] stage={} iters={} vectors={} ids={:?}", stage, iters, inputs.len(),
        inputs.iter().map(|(i, _)| i.as_str()).collect::<Vec<_>>());

    if stage == "sizes" { sizes(&inputs); return; }

    let s0 = sample(0);
    let t0 = Instant::now();
    let avm = Arc::new(AvmInterpreter::new(elf.clone(), [0u8; 32]));
    let s_built = sample(0);
    eprintln!("[KI89] AvmInterpreter::new took {:?}; live +{} KB, rss +{} KB, exec maps {} ({} KB), jit_degraded={}",
        t0.elapsed(), (s_built.live - s0.live) / 1024, s_built.rss - s0.rss, s_built.exec_n, s_built.exec_kb, avm.jit_degraded());

    let mut ok = 0u64; let mut err = 0u64; let mut accept = 0u64;
    let mut errs: std::collections::BTreeMap<String, u64> = Default::default();
    let every = (iters / 20).max(1);
    let mut samples: Vec<Sample> = Vec::new();
    let t = Instant::now();
    for it in 1..=iters {
        let (_, inp) = &inputs[(it - 1) % inputs.len()];
        let inp = inp.clone();
        let r: Result<axiom_core_logic::types::PublicOutputs, String> = match stage.as_str() {
            "execute" => avm.execute(inp).map_err(|e| e.to_string()),
            "audited" => avm.execute_audited(inp).map_err(|e| e.to_string()),
            "dmap" => avm.execute_with_dmap(inp).map(|r| r.outputs).map_err(|e| e.to_string()),
            "dmap_audited" => avm.execute_with_dmap_audited(inp).map(|r| r.outputs).map_err(|e| e.to_string()),
            "threads" => {
                let av = avm.clone();
                std::thread::spawn(move || av.execute(inp).map_err(|e| e.to_string())).join().unwrap()
            }
            "new_avm" => {
                let fresh = AvmInterpreter::new(elf.clone(), [0u8; 32]);
                let r = fresh.execute(inp).map_err(|e| e.to_string());
                drop(fresh);
                r
            }
            s => panic!("unknown stage {}", s),
        };
        match r {
            Ok(o) => { ok += 1; if o.result == axiom_core_logic::types::ValidationResult::Accept { accept += 1; } }
            Err(e) => { err += 1; *errs.entry(e.chars().take(200).collect()).or_default() += 1; }
        }
        if it % every == 0 || it == iters {
            let s = sample(it);
            eprintln!("[KI89] it={:>6} live={:>9} KB rss={:>8} KB swap={:>6} KB exec_maps={} ({} KB) ok={} accept={} err={} {:.1}/s",
                it, s.live / 1024, s.rss, s.swap, s.exec_n, s.exec_kb, ok, accept, err, it as f64 / t.elapsed().as_secs_f64());
            samples.push(s);
        }
    }
    // Growth per 1k iterations over the post-warmup half (first sample after
    // 50% of the run → last), so one-time warmup (thread-local GuestMemory,
    // first-touch pages) is excluded.
    let half = samples.iter().position(|s| s.it >= iters / 2).unwrap_or(0);
    let (a0, b0) = (samples[half], *samples.last().unwrap());
    let span = (b0.it - a0.it).max(1) as f64 / 1000.0;
    println!("KI89 stage={} iters={} vectors={} ok={} accept={} err={} errs={:?}", stage, iters, inputs.len(), ok, accept, err, errs);
    println!("KI89 warmup(it 0->{}): live {:+} KB, rss {:+} KB", a0.it, (a0.live - s_built.live) / 1024, a0.rss - s_built.rss);
    println!("KI89 slope(it {}->{}): live {:+.1} KB/1k, rss {:+.1} KB/1k, swap {:+.1} KB/1k, exec_maps {:+} ({:+} KB)",
        a0.it, b0.it,
        (b0.live - a0.live) as f64 / 1024.0 / span,
        (b0.rss - a0.rss) as f64 / span,
        (b0.swap - a0.swap) as f64 / span,
        b0.exec_n as i64 - a0.exec_n as i64, b0.exec_kb as i64 - a0.exec_kb as i64);
    println!("KI89 HWM={} KB allocs_total={}", status_kb("VmHWM:"), ALLOCS.load(Ordering::Relaxed));
}

/// Heap bytes owned by `v` (excluding its inline size): LIVE delta of a clone.
fn heap_of<T: Clone>(v: &T) -> i64 {
    let before = LIVE.load(Ordering::Relaxed);
    let c = v.clone();
    let after = LIVE.load(Ordering::Relaxed);
    drop(c);
    after - before
}

fn sizes(inputs: &[(String, PublicInputs)]) {
    println!("KI89 sizes: id | inputs_heap | sender_fact_chain(links,heap) | receiver_fact_chain(links,heap) | vbc_bundle | fact_certificates(n,heap) | cheque_bundle | prev_receipts(n,heap) | cl1_proof");
    for (id, i) in inputs {
        let sfc = i.sender_fact_chain.as_ref().map(|c| (c.links.len(), heap_of(c))).unwrap_or((0, 0));
        let rfc = i.receiver_fact_chain.as_ref().map(|c| (c.links.len(), heap_of(c))).unwrap_or((0, 0));
        println!("KI89 size {} | {} | ({},{}) | ({},{}) | {} | ({},{}) | {} | ({},{}) | {}",
            id, heap_of(i), sfc.0, sfc.1, rfc.0, rfc.1,
            i.vbc_bundle.as_ref().map(heap_of).unwrap_or(0),
            i.fact_certificates.len(), heap_of(&i.fact_certificates),
            i.cheque_bundle.as_ref().map(heap_of).unwrap_or(0),
            i.prev_receipts.len(), heap_of(&i.prev_receipts),
            i.cl1_execution_proof.as_ref().map(|p| p.len()).unwrap_or(0));
    }
}

fn cheque_sizes(files: &[String]) {
    use axiom_core_logic::types::ValidatorCheque;
    println!("KI89 cheque: file | cheques | cheque_heap | sender_fact_chain(links,heap) | fact_certificates(n,heap) | vbc_bundle | execution_proof");
    for f in files {
        let bytes = std::fs::read(f).expect("read cheque file");
        let v: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).expect("cbor");
        let top = v.as_map().expect("map");
        let cheques = top.iter().find(|(k, _)| k.as_text() == Some("cheques")).map(|(_, v)| v.as_array().expect("arr").clone()).unwrap_or_default();
        for c in &cheques {
            let inner = c.as_map().unwrap().iter().find(|(k, _)| k.as_text() == Some("cheque")).map(|(_, v)| v.clone()).expect("cheque");
            let ch: ValidatorCheque = inner.deserialized().expect("decode ValidatorCheque");
            let sfc = ch.sender_fact_chain.as_ref().map(|c| (c.links.len(), heap_of(c))).unwrap_or((0, 0));
            println!("KI89 cheque {} | {} | {} | ({},{}) | ({},{}) | {} | {}",
                f.rsplit('/').next().unwrap_or(f).chars().take(16).collect::<String>(), cheques.len(), heap_of(&ch), sfc.0, sfc.1,
                ch.fact_certificates.len(), heap_of(&ch.fact_certificates),
                ch.vbc_bundle.as_ref().map(heap_of).unwrap_or(0), ch.execution_proof.len());
        }
    }
}
