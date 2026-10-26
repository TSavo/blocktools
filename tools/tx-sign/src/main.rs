//! tx-sign: sign ONE transaction after a human reads its summary and types a code on /dev/tty.
//!   tx-sign --tx FILE --expect-to ADDR [--expect-to ADDR]... [--change ADDR]... [--chain btc|ltc|doge]
//!           [--chain-id N (required for EVM)] [--max-fee SATS_OR_WEI] [--from 0xADDR] [--allow-warnings] [--allow-value-with-token] [--policy FILE]  < keys
//! --policy FILE: offline policy file (docs/POLICY.md), checked in addition to the flags, before signing and on the signed bytes.
//! The transaction (PSBT from tx-build, a pos-ntime or zec JSON line from tx-build, or an unsigned EVM tx) comes from --tx FILE (it is public).
//! Keys come ONLY on stdin: one per line, WIF or 64-hex, or JSON lines with wif/private_key/key/secret
//! (JSON lines without any of those fields, e.g. a reader's "done" line, are skipped).
//! Order: policy checks (destination, fee cap, chain id, no warnings) -> sign in memory -> print the
//! tx-decode summary on the terminal -> human types the code -> re-decode + re-check -> print
//! {"signed_tx": hex[, "psbt": finalized base64]}. Without a terminal, or with the wrong code, nothing is printed except "aborted".
//! Default fee cap: UTXO per chain (chain rate limit x vsize, never below 100000 sats; policy::default_fee_cap) / 0.01 ETH (EVM); raise it with --max-fee.
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::Secp256k1;
use blocktools_tx::policy::{check, Policy};
use serde_json::json;
use std::io::{BufRead, Read};
use zeroize::Zeroizing;

fn out(status: &str, extra: serde_json::Value) -> ! {
    let mut v = json!({"tool":"tx-sign","status":status}); v.as_object_mut().unwrap().extend(extra.as_object().cloned().unwrap_or_default());
    blocktools_io::outln!("{v}"); std::process::exit(if status == "ok" { 0 } else if status == "bad_input" { 2 } else { 1 })
}
fn main() {
    blocktools_io::help("tx-sign --tx FILE --expect-to ADDR [...] [--max-fee N] [--policy FILE] < keys   (asks for a code on the terminal)");
    let a: Vec<String> = blocktools_core::chain_spec::args_or_exit("tx-sign");
    let all = |k: &str| a.windows(2).filter(|w| w[0] == k).map(|w| w[1].clone()).collect::<Vec<_>>();
    let one = |k: &str| all(k).pop();
    let bad = |e: &str| -> ! { out("bad_input", json!({"error":e})) };
    let mut txt = String::new();
    std::fs::File::open(one("--tx").unwrap_or_else(|| bad("--tx FILE required"))).and_then(|f| f.take(blocktools_tx::MAX_INPUT as u64).read_to_string(&mut txt)).unwrap_or_else(|_| bad("cannot read --tx file"));
    let chain = blocktools_tx::resolve_chain(&txt, one("--chain")).unwrap_or_else(|e| bad(e));
    blocktools_core::chain_spec::tx_ready(&chain, true).unwrap_or_else(|e| bad(e)); // spec chain: spec_missing_wif etc.
    let d = blocktools_tx::decode(&txt, &chain).unwrap_or_else(|e| bad(e));
    if d.signed { bad("already_signed") }
    let p = Policy { expect_to: all("--expect-to"), change: all("--change"),
        chain_id: one("--chain-id").map(|s| s.parse().unwrap_or_else(|_| bad("--chain-id"))),
        max_fee: one("--max-fee").map(|s| s.parse().unwrap_or_else(|_| bad("--max-fee"))),
        allow_warnings: a.iter().any(|x| x == "--allow-warnings"), allow_value_with_token: a.iter().any(|x| x == "--allow-value-with-token") };
    if p.expect_to.is_empty() { bad("--expect-to ADDR is required (destination assertion)") }
    for e in p.expect_to.iter().chain(&p.change) {
        let c = if d.evm.is_some() { "eth" } else { chain.as_str() };
        let ok = if c == "zec" { blocktools_tx::zcash::address_to_script(e).is_some() } else { blocktools_core::validate::validate(c, e).is_ok() };
        if !ok { bad("invalid --expect-to/--change address") }
    }
    let pol = one("--policy").map(|f| blocktools_tx::policy_file::parse(&std::fs::read_to_string(f).unwrap_or_else(|_| bad("cannot read --policy file"))).unwrap_or_else(|e| bad(e)));
    let pkey = one("--chain").unwrap_or(chain.clone());
    let full = |d: &blocktools_tx::Decoded| -> Vec<String> {
        let mut f: Vec<String> = check(d, &p).into_iter().map(String::from).collect();
        if let Some(pf) = &pol { for x in blocktools_tx::policy_file::check(d, &pkey, pf) { if !f.contains(&x) { f.push(x) } } }
        f
    };
    let f = full(&d);
    if !f.is_empty() { out("refused", json!({"failures":f,"warnings":d.warnings})) }

    let mut keys = Vec::new();
    for l in std::io::stdin().lock().take(4 << 20).lines().map_while(Result::ok) {
        let l = Zeroizing::new(l);
        if l.trim().is_empty() { continue }
        if keys.len() >= 10_000 { bad("too_many_keys") }
        // Upstream status lines ({"status":"done",...}) carry no key: skip them so reader pipes compose.
        if let Ok(serde_json::Value::Object(o)) = serde_json::from_str::<serde_json::Value>(&l) {
            if !["wif", "private_key", "key", "secret"].iter().any(|k| o.contains_key(*k)) { continue }
        }
        keys.push(blocktools_secrets::keys::parse_key_line(&l).unwrap_or_else(|| bad("unreadable key line")));
    }
    if keys.is_empty() { bad("no keys on stdin") }
    let secp = Secp256k1::new();
    let raw = blocktools_tx::input_bytes(&txt).unwrap_or_else(|e| bad(e));
    // (signed network bytes, signer description, bytes to re-decode for the re-check)
    let (signed, signer, recheck): (Vec<u8>, String, Vec<u8>) = if let Some(mut t) = d.evm.clone() {
        let pick = match one("--from") {
            Some(f) => keys.iter().find(|k| blocktools_core::eth_address(k, &secp).eq_ignore_ascii_case(&f)).unwrap_or_else(|| bad("no key for --from")),
            None if keys.len() == 1 => &keys[0],
            None => bad("several keys: pass --from 0xADDR"),
        };
        t.sign(pick).unwrap_or_else(|e| bad(e));
        let from = blocktools_core::eth_address(pick, &secp);
        if t.from().map(|x| blocktools_tx::addr(&x)).as_deref() != Some(from.as_str()) { out("error", json!({"error":"signature_self_check_failed"})) }
        let b = t.encode_signed().unwrap_or_else(|| bad("encode")); (b.clone(), from, b)
    } else if d.ty == "pos-ntime" {
        let prev = blocktools_tx::pos::prevouts_from_json(&txt).unwrap_or_else(|e| bad(e)).unwrap_or_else(|| bad("pos-ntime signing needs pos_prevouts (from tx-build)"));
        let mut t = blocktools_tx::pos::PosTx::parse(&chain, &raw).unwrap_or_else(|e| bad(e));
        let unsigned = t.clone();
        let n = blocktools_tx::sign::sign_pos(&mut t, &prev, &keys).unwrap_or_else(|e| bad(e));
        if n != t.inputs.len() { out("refused", json!({"failures":[blocktools_tx::code!("input_without_key")],"inputs":t.inputs.len(),"signed_inputs":n})) }
        let mut bare = t.clone(); for i in &mut bare.inputs { i.script_sig.clear() }
        if bare != unsigned { out("error", json!({"error":"signed_tx_differs_from_unsigned"})) }
        let who: Vec<String> = d.inputs.iter().filter_map(|i| i.address.clone()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
        (t.serialize(), who.join(", "), blocktools_tx::pos::envelope(&chain, &t, &prev, &blocktools_tx::pos::prev_txs_from_json(&txt)).to_string().into_bytes())
    } else if chain == "zec" {
        let (prev, branch) = blocktools_tx::zcash::envelope_from_json(&txt).unwrap_or_else(|e| bad(e)).unwrap_or_else(|| bad("zec signing needs zec_prevouts and branch_id (from tx-build)"));
        let mut t = blocktools_tx::zcash::ZTx::parse(&raw, branch).unwrap_or_else(|e| bad(e));
        if !t.sapling.spends.is_empty() || !t.sapling.outputs.is_empty() || !t.orchard.actions.is_empty() || !t.joinsplits.is_empty() { bad("zec: shielded components are not signed here") }
        let unsigned = t.clone();
        let n = blocktools_tx::sign::sign_zcash(&mut t, &prev, &keys).unwrap_or_else(|e| bad(e));
        if n != t.inputs.len() { out("refused", json!({"failures":[blocktools_tx::code!("input_without_key")],"inputs":t.inputs.len(),"signed_inputs":n})) }
        let mut bare = t.clone(); for i in &mut bare.inputs { i.script_sig.clear() }
        if bare != unsigned { out("error", json!({"error":"signed_tx_differs_from_unsigned"})) }
        let who: Vec<String> = d.inputs.iter().filter_map(|i| i.address.clone()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
        (t.serialize(), who.join(", "), blocktools_tx::zcash::envelope(&t, &prev).to_string().into_bytes())
    } else {
        let mut ps = Psbt::deserialize(&raw).unwrap_or_else(|_| bad("UTXO signing needs a PSBT (from tx-build)"));
        let n = blocktools_tx::sign::sign_psbt_digest(&mut ps, &keys, blocktools_core::chains::chain(&chain).map(blocktools_tx::sign::Digest::for_chain).unwrap_or(blocktools_tx::sign::Digest::Sha256d)).unwrap_or_else(|e| bad(e));
        if n != ps.inputs.len() { out("refused", json!({"failures":[blocktools_tx::code!("input_without_key")],"inputs":ps.inputs.len(),"signed_inputs":n})) }
        let tx = blocktools_tx::sign::extract(&ps).unwrap_or_else(|e| bad(e));
        let mut bare = tx.clone();
        for i in &mut bare.input { i.script_sig = bitcoin::ScriptBuf::new(); i.witness = bitcoin::Witness::new() }
        if bare != ps.unsigned_tx { out("error", json!({"error":"signed_tx_differs_from_psbt"})) }
        let who: Vec<String> = d.inputs.iter().filter_map(|i| i.address.clone()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
        (bitcoin::consensus::serialize(&tx), who.join(", "), ps.serialize())
    };
    drop(keys);
    // Re-decode the exact signed bytes and re-check before anything is shown or released.
    let env = d.ty == "pos-ntime" || chain == "zec";
    let d2 = if env { blocktools_tx::decode(std::str::from_utf8(&recheck).unwrap_or(""), &chain) } else { blocktools_tx::decode_bytes(&recheck, &chain) }.unwrap_or_else(|_| out("error", json!({"error":"signed_tx_does_not_decode"})));
    let f2 = full(&d2);
    if !d2.signed || !f2.is_empty() { out("error", json!({"error":"signed_tx_failed_recheck","failures":f2})) }
    let summary = format!("{}\nSigned by: {signer}\nChecks passed: destination {}, fee cap {}{}\n",
        d2.text().trim_end(), p.expect_to.join(", "), p.max_fee.unwrap_or(0), if d2.evm.is_some() { " wei" } else { " sats" });
    if !blocktools_tty::confirm(&summary) { out("aborted", json!({})) }
    let mut o = json!({"type":d2.ty,"signed_tx":blocktools_core::hex_enc(&signed)});
    // finalized PSBT too, so the after-signing tx-decode can show input amounts and the fee
    if env { // chain, tx_format, time/branch_id, pos_prevouts/zec_prevouts (so tx-decode shows the fee)
        if let Ok(serde_json::Value::Object(e)) = serde_json::from_slice::<serde_json::Value>(&recheck) { for (k, v) in e { if k != "signed_tx" { o[k] = v } } }
    }
    else if d2.evm.is_none() { o["psbt"] = json!(blocktools_core::b64::encode(&recheck)) }
    out("ok", o)
}
