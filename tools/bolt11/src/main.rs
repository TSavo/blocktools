//! bolt11: decode a BOLT11 Lightning invoice and (via the library) re-encode it byte-identically.
//!   bolt11 <invoice>           or   printf %s "<invoice>" | bolt11
//! stdout: one JSON line {tool,status,network,amount_msat?,timestamp,payment_hash?,description?,
//! description_hash?,payment_secret?,payee_pubkey?,recovered_payee,expiry?,min_final_cltv_expiry?,
//! features?,fallback?,routing_hints,signature,recovery_id}. The payee pubkey is RECOVERED from the
//! signature (and `payee_pubkey` is the invoice's own `n` tag when present). Offline, public input, no keys.
mod decode;
use blocktools_io::outln;
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
        let re = decode::reencode(&input).unwrap_or_else(|e| die("bad_input", e));
        let ok = re == input.to_ascii_lowercase();
        outln!("{}", json!({"tool":"bolt11","status":if ok {"ok"} else {"mismatch"},"reencoded":re,"roundtrip":ok}));
        std::process::exit(if ok { 0 } else { 1 });
    }
    let inv = decode::decode(&input).unwrap_or_else(|e| die("bad_input", e));
    let mut v = json!({
        "tool": "bolt11",
        "status": "ok",
        "network": inv.network,
        "currency": inv.currency,
        "timestamp": inv.timestamp,
        "recovered_payee": inv.recovered_payee,
        "signature": inv.signature,
        "recovery_id": inv.recovery_id,
        "routing_hints": inv.routing_hint_count,
    });
    let o = v.as_object_mut().unwrap();
    if let Some(a) = inv.amount_msat {
        o.insert("amount_msat".into(), json!(a.to_string()));
    }
    if !inv.amount_raw.is_empty() {
        o.insert("amount_raw".into(), json!(inv.amount_raw));
    }
    for (k, val) in [
        ("payment_hash", &inv.payment_hash),
        ("payment_secret", &inv.payment_secret),
        ("description", &inv.description),
        ("description_hash", &inv.description_hash),
        ("payee_pubkey", &inv.payee_pubkey_field),
        ("features", &inv.features_hex),
        ("fallback", &inv.fallback_hex),
    ] {
        if let Some(x) = val {
            o.insert(k.into(), json!(x));
        }
    }
    if let Some(x) = inv.expiry {
        o.insert("expiry".into(), json!(x));
    }
    if let Some(x) = inv.min_final_cltv_expiry {
        o.insert("min_final_cltv_expiry".into(), json!(x));
    }
    outln!("{v}");
}
