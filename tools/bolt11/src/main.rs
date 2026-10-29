//! bolt11: decode a BOLT11 Lightning invoice and (via the library) re-encode it byte-identically.
//!   bolt11 <invoice>           or   printf %s "<invoice>" | bolt11
//! stdout: one JSON line {tool,status,network,currency,amount_msat?,amount_raw?,timestamp,payment_hash?,
//! description?,description_hash?,payment_secret?,payee_pubkey?,recovered_payee,expiry?,
//! min_final_cltv_expiry?,features?,fallback?,routing_hints,signature,recovery_id}. The payee pubkey is
//! RECOVERED from the signature (and `payee_pubkey` is the invoice's own `n` tag when present). The decode
//! and re-encode logic lives in blocktools-tx (`tx::bolt11`), shared with the `bolt11Decode`/`bolt11Reencode`
//! wasm exports so the tool and the binding cannot disagree. Offline, public input, no keys.
use blocktools_io::outln;
use blocktools_tx::bolt11;
use serde_json::json;
use std::io::Read;

fn die(status: &str, e: &str) -> ! {
    eprintln!("{}", json!({"tool": "bolt11", "status": status, "error": e}));
    std::process::exit(if status == "bad_input" { 2 } else { 1 })
}

fn main() {
    blocktools_io::help(
        "bolt11 <invoice>   (or pipe the invoice on stdin)
  Decode a BOLT11 Lightning invoice: bech32 + tagged fields + the payee pubkey recovered from the
  signature; re-encodes byte-identically. Offline, reads only the public invoice string, holds no key.",
    );
    let args: Vec<String> = std::env::args().skip(1).collect();
    let input = match args.iter().find(|a| !a.starts_with("--")) {
        Some(a) => a.clone(),
        None => {
            let mut s = String::new();
            std::io::stdin().take(1 << 20).read_to_string(&mut s).ok();
            s.trim().to_string()
        }
    };
    if input.is_empty() {
        die("bad_input", "no invoice (pass it as an argument or on stdin)");
    }
    // --reencode: prove the byte-identical round-trip (decode the words, re-emit with a fresh checksum).
    if args.iter().any(|a| a == "--reencode") {
        let re = bolt11::reencode(&input).unwrap_or_else(|e| die("bad_input", e));
        let ok = re == input.to_ascii_lowercase();
        outln!("{}", json!({"tool":"bolt11","status":if ok {"ok"} else {"mismatch"},"reencoded":re,"roundtrip":ok}));
        std::process::exit(if ok { 0 } else { 1 });
    }
    // The library builds the field object (no envelope); add tool+status. serde_json sorts keys, so the
    // output bytes are identical regardless of insertion order.
    let mut v = bolt11::decode_value(&input).unwrap_or_else(|e| die("bad_input", e));
    let o = v.as_object_mut().unwrap();
    o.insert("tool".into(), json!("bolt11"));
    o.insert("status".into(), json!("ok"));
    outln!("{v}");
}
