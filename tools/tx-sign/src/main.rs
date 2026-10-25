//! tx-sign: sign ONE transaction after a human reads its summary and types a code on /dev/tty.
//!   tx-sign --tx FILE --expect-to ADDR [--expect-to ADDR]... [--change ADDR]... [--chain btc|ltc|doge]
//!           [--chain-id N] [--max-fee SATS_OR_WEI] [--from 0xADDR] [--allow-warnings]  < keys
//! The transaction (PSBT from tx-build, or an unsigned EVM tx) comes from --tx FILE (it is public).
//! Keys come ONLY on stdin: one per line, WIF or 64-hex, or JSON lines with wif/private_key/key/secret.
//! Order: policy checks (destination, fee cap, chain id, no warnings) -> sign in memory -> print the
//! tx-decode summary on the terminal -> human types the code -> re-decode + re-check -> print
//! {"signed_tx": hex[, "psbt": finalized base64]}. Without a terminal, or with the wrong code, nothing is printed except "aborted".
//! Default fee cap: 100000 sats (UTXO) / 0.01 ETH (EVM); raise it with --max-fee.
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use kr_tx::policy::{self, check, Policy};
use serde_json::json;
use std::io::{BufRead, Read};
use zeroize::Zeroizing;

fn out(status: &str, extra: serde_json::Value) -> ! {
    let mut v = json!({"tool":"tx-sign","status":status}); v.as_object_mut().unwrap().extend(extra.as_object().cloned().unwrap_or_default());
    kr_io::outln!("{v}"); std::process::exit(if status == "ok" { 0 } else if status == "bad_input" { 2 } else { 1 })
}
fn key(s: &str) -> Option<SecretKey> {
    let s = s.trim();
    let tok: Zeroizing<String> = Zeroizing::new(match serde_json::from_str::<serde_json::Value>(s) {
        Ok(v) if v.is_object() => ["wif", "private_key", "key", "secret"].iter().find_map(|k| v[*k].as_str().map(String::from))?,
        _ => s.to_string(),
    });
    if let Ok(k) = bitcoin::PrivateKey::from_wif(&tok) { return Some(k.inner) }
    let h = tok.strip_prefix("0x").unwrap_or(&tok);
    if h.len() == 64 { return SecretKey::from_slice(&Zeroizing::new(kr_core::hex_dec(h)?)).ok() }
    None
}
fn main() {
    kr_io::help("tx-sign --tx FILE --expect-to ADDR [...] [--max-fee N] < keys   (asks for a code on the terminal)");
    let a: Vec<String> = std::env::args().collect();
    let all = |k: &str| a.windows(2).filter(|w| w[0] == k).map(|w| w[1].clone()).collect::<Vec<_>>();
    let one = |k: &str| all(k).pop();
    let bad = |e: &str| -> ! { out("bad_input", json!({"error":e})) };
    let chain = one("--chain").unwrap_or("btc".into());
    let mut txt = String::new();
    std::fs::File::open(one("--tx").unwrap_or_else(|| bad("--tx FILE required"))).and_then(|f| f.take(kr_tx::MAX_INPUT as u64).read_to_string(&mut txt)).unwrap_or_else(|_| bad("cannot read --tx file"));
    let d = kr_tx::decode(&txt, &chain).unwrap_or_else(|e| bad(e));
    if d.signed { bad("already_signed") }
    let p = Policy { expect_to: all("--expect-to"), change: all("--change"),
        chain_id: one("--chain-id").map(|s| s.parse().unwrap_or_else(|_| bad("--chain-id"))),
        max_fee: Some(one("--max-fee").map(|s| s.parse().unwrap_or_else(|_| bad("--max-fee")))
            .unwrap_or(if d.evm.is_some() { policy::DEFAULT_MAX_FEE_WEI } else { policy::DEFAULT_MAX_FEE_SATS })),
        allow_warnings: a.iter().any(|x| x == "--allow-warnings") };
    if p.expect_to.is_empty() { bad("--expect-to ADDR is required (destination assertion)") }
    for e in p.expect_to.iter().chain(&p.change) {
        let c = if d.evm.is_some() { "eth" } else { chain.as_str() };
        if kr_core::validate::validate(c, e).is_err() { bad("invalid --expect-to/--change address") }
    }
    let f = check(&d, &p);
    if !f.is_empty() { out("refused", json!({"failures":f,"warnings":d.warnings})) }

    let mut keys = Vec::new();
    for l in std::io::stdin().lock().take(4 << 20).lines().map_while(Result::ok) {
        let l = Zeroizing::new(l);
        if l.trim().is_empty() { continue }
        if keys.len() >= 10_000 { bad("too_many_keys") }
        keys.push(key(&l).unwrap_or_else(|| bad("unreadable key line")));
    }
    if keys.is_empty() { bad("no keys on stdin") }
    let secp = Secp256k1::new();
    let raw = kr_tx::input_bytes(&txt).unwrap_or_else(|e| bad(e));
    // (signed network bytes, signer description, bytes to re-decode for the re-check)
    let (signed, signer, recheck): (Vec<u8>, String, Vec<u8>) = if let Some(mut t) = d.evm.clone() {
        let pick = match one("--from") {
            Some(f) => keys.iter().find(|k| kr_core::eth_address(k, &secp).eq_ignore_ascii_case(&f)).unwrap_or_else(|| bad("no key for --from")),
            None if keys.len() == 1 => &keys[0],
            None => bad("several keys: pass --from 0xADDR"),
        };
        t.sign(pick).unwrap_or_else(|e| bad(e));
        let from = kr_core::eth_address(pick, &secp);
        if t.from().map(|x| kr_tx::addr(&x)).as_deref() != Some(from.as_str()) { out("error", json!({"error":"signature_self_check_failed"})) }
        let b = t.encode_signed().unwrap_or_else(|| bad("encode")); (b.clone(), from, b)
    } else {
        let mut ps = Psbt::deserialize(&raw).unwrap_or_else(|_| bad("UTXO signing needs a PSBT (from tx-build)"));
        let n = kr_tx::sign::sign_psbt(&mut ps, &keys).unwrap_or_else(|e| bad(e));
        if n != ps.inputs.len() { out("refused", json!({"failures":["input_without_key"],"inputs":ps.inputs.len(),"signed_inputs":n})) }
        let tx = kr_tx::sign::extract(&ps).unwrap_or_else(|e| bad(e));
        let mut bare = tx.clone();
        for i in &mut bare.input { i.script_sig = bitcoin::ScriptBuf::new(); i.witness = bitcoin::Witness::new() }
        if bare != ps.unsigned_tx { out("error", json!({"error":"signed_tx_differs_from_psbt"})) }
        let who: Vec<String> = d.inputs.iter().filter_map(|i| i.address.clone()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
        (bitcoin::consensus::serialize(&tx), who.join(", "), ps.serialize())
    };
    drop(keys);
    // Re-decode the exact signed bytes and re-check before anything is shown or released.
    let d2 = kr_tx::decode_bytes(&recheck, &chain).unwrap_or_else(|_| out("error", json!({"error":"signed_tx_does_not_decode"})));
    let f2 = check(&d2, &p);
    if !d2.signed || !f2.is_empty() { out("error", json!({"error":"signed_tx_failed_recheck","failures":f2})) }
    let summary = format!("{}\nSigned by: {signer}\nChecks passed: destination {}, fee cap {}{}\n",
        d2.text().trim_end(), p.expect_to.join(", "), p.max_fee.unwrap_or(0), if d2.evm.is_some() { " wei" } else { " sats" });
    if !kr_tty::confirm(&summary) { out("aborted", json!({})) }
    let mut o = json!({"type":d2.ty,"signed_tx":kr_core::hex_enc(&signed)});
    // finalized PSBT too, so the after-signing tx-decode can show input amounts and the fee
    if d2.evm.is_none() { o["psbt"] = json!(kr_core::b64::encode(&recheck)) }
    out("ok", o)
}
