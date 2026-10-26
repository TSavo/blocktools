//! sol-tron-tx: build unsigned, decode and verify Solana and Tron transfers. The chain is detected
//! from the input (transaction bytes, or the plan's `from` address); `--chain sol|tron` overrides.
//! Public data only: takes no keys and signs nothing.
//!   sol-tron-tx decode < tx.hex
//!   sol-tron-tx verify --expect '{"to":"…","lamports":"1000"}' < tx.hex
//!   sol-tron-tx build --plan plan.json
use blocktools::{soltron, sol, tron};
use blocktools_io::outln;
use serde_json::{json, Value};
use std::io::Read;

fn emit(v: Value) -> ! {
    let s = v["status"].as_str().unwrap_or("error").to_string();
    if s == "ok" { outln!("{v}") } else { eprintln!("{v}") }
    std::process::exit(blocktools_io::exit_code(&s))
}
fn bad(e: &str) -> ! { emit(json!({"tool": "sol-tron-tx", "status": "bad_input", "error": e})) }

fn main() {
    blocktools_io::help("sol-tron-tx decode|verify|build [--chain sol|tron] [--expect JSON] [--plan FILE] [HEX_OR_BASE64]
  decode           decode a transaction (hex or base64, argument or stdin): Solana wire tx (legacy/v0) or Tron raw_data / Transaction
  verify --expect  Solana: {owner?, to?, lamports?, mint?, amount?, allow_programs?}
                   Tron:   {owner?, to?, amount_sun?, contract?, amount?, max_fee_limit_sun?, now_ms?}
                   (one TRX transfer or TRC-20 transfer; signatures recovered and must be the owner)
  build --plan F   unsigned transfer from a plan file (solBuildTransfer / tronBuildTransfer JSON, EXPORTS.md); prints hex
  --chain sol|tron skip auto-detect. Without it, bytes that parse as both chains, or neither, are refused (bad_input).
Takes no keys and signs nothing.");
    let a: Vec<String> = std::env::args().skip(1).collect();
    let val = |k: &str| a.iter().position(|x| x == k).map(|i| a.get(i + 1).cloned().unwrap_or_else(|| bad(&format!("{k}_needs_a_value"))));
    let forced = val("--chain");
    if let Some(c) = &forced { if c != "sol" && c != "tron" { bad("unknown_chain") } }
    let mut pos = Vec::new(); let mut i = 0;
    while i < a.len() { if a[i].starts_with("--") { i += 2 } else { pos.push(a[i].clone()); i += 1 } }
    let cmd = pos.first().cloned().unwrap_or_else(|| bad("missing_command"));
    let input = || pos.get(1).cloned().unwrap_or_else(|| { let mut s = String::new(); std::io::stdin().take(16 << 20).read_to_string(&mut s).ok(); s });
    let chain_of = |b: &[u8]| forced.clone().unwrap_or_else(|| soltron::detect_tx(b).unwrap_or_else(|e| bad(e)).into());
    match cmd.as_str() {
        "decode" => {
            let b = soltron::raw(&input()).unwrap_or_else(|e| bad(e)); let c = chain_of(&b);
            let d = if c == "sol" { sol::decode_tx(&b) } else { tron::decode(&b) }.unwrap_or_else(|e| bad(e));
            emit(json!({"tool": "sol-tron-tx", "status": "ok", "chain": c, "decoded": d}))
        }
        "verify" => {
            let e: Value = serde_json::from_str(&val("--expect").unwrap_or_else(|| bad("verify_needs_--expect"))).unwrap_or_else(|_| bad("bad_expect"));
            let b = soltron::raw(&input()).unwrap_or_else(|e| bad(e)); let c = chain_of(&b);
            let r = if c == "sol" { sol::verify_tx(&b, &e) } else { tron::verify_tx(&b, &e) }.unwrap_or_else(|e| bad(e));
            let ok = r["ok"] == json!(true);
            emit(json!({"tool": "sol-tron-tx", "status": if ok { "ok" } else { "verify_failed" }, "chain": c, "result": r}))
        }
        "build" => {
            let p = std::fs::read_to_string(val("--plan").unwrap_or_else(|| bad("build_needs_--plan"))).unwrap_or_else(|_| bad("cannot_read_file"));
            let v: Value = serde_json::from_str(&p).unwrap_or_else(|_| bad("bad_plan_json"));
            let c = forced.clone().unwrap_or_else(|| soltron::detect_plan(&v).unwrap_or_else(|e| bad(e)).into());
            let b = soltron::build(&c, &v).unwrap_or_else(|e| bad(e));
            let mut o = json!({"tool": "sol-tron-tx", "status": "ok", "chain": c, "unsigned_hex": blocktools::hex_enc(&b)});
            if c == "tron" { o["txid"] = json!(tron::txid(&b)) }
            emit(o)
        }
        _ => bad("unknown_command"),
    }
}
