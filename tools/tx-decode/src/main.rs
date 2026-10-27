//! tx-decode: one transaction on stdin (hex/base64 raw tx, PSBT, EVM RLP, or a JSON line with
//! "psbt"/"tx"/"unsigned_tx"/"signed_tx") -> public JSON lines, or --text for a human summary.
//! Offline, no keys, never opens a network connection. Flags: --chain btc|ltc|doge (address
//! encoding for UTXO txs), --text, --nvc-json TXID (Novacoin explorer JSON on stdin -> raw hex,
//! hash-checked against TXID), --prevtxs FILE (full previous transactions, one per line as hex or a
//! JSON line with "tx"/"hex", e.g. the output of `rpc URL prevtxs` or `rpc URL rawtx`): input
//! amounts and the fee are filled in for a raw UTXO tx. A prev tx counts only if it hashes to the
//! input's outpoint txid; an input with no matching prev tx stays unknown (warning prevout_missing);
//! a prev tx matching no input is refused (prevtx_unused). Fetching prev txs is rpc's job (its
//! allowlist, deny-list and credential redaction apply); tx-decode itself stays offline.
use std::io::Read;
fn main() {
    blocktools_io::help("tx-decode [--chain btc|ltc|doge] [--text] [--prevtxs FILE] < transaction -> JSON lines (or plain summary)\n       tx-decode --nvc-json TXID < api.novaco.in gettransaction JSON -> raw tx hex (fails unless the hash is TXID)\n       rpc URL rawtx TXID [BLOCKHASH] | tx-decode                      decode a tx fetched by rpc (its JSON line has \"tx\")\n       rpc URL rawtx TXID > t; rpc URL prevtxs < t > p; tx-decode --prevtxs p < t   input amounts + fee\n  --prevtxs FILE: previous txs, one per line (hex, or JSON with \"tx\"/\"hex\"); each must hash to an input's outpoint\n  txid (else prevtx_unused); inputs without one warn prevout_missing. tx-decode never opens a socket.\n  Input is read from stdin only; a hex argument is not read (bad_transaction on empty stdin).");
    let a: Vec<String> = blocktools_core::chain_spec::args_or_exit("tx-decode");
    let chain = a.iter().position(|x| x == "--chain").and_then(|i| a.get(i + 1)).map_or("btc", |s| s.as_str());
    let text = a.iter().any(|x| x == "--text");
    let prevtxs = match a.iter().position(|x| x == "--prevtxs") {
        None => None,
        Some(i) => {
            let Some(f) = a.get(i + 1) else { return fail("prevtxs_needs_file") };
            let Ok(s) = std::fs::read_to_string(f) else { return fail("prevtxs_unreadable") };
            if s.len() > blocktools_tx::MAX_INPUT { return fail("too_large") }
            let mut v = vec![];
            for l in s.lines().map(str::trim).filter(|l| !l.is_empty()).take(2001) {
                let h = if l.starts_with('{') {
                    let Ok(j) = serde_json::from_str::<serde_json::Value>(l) else { return fail("bad_prevtx") };
                    match j.get("tx").or_else(|| j.get("hex")).and_then(|x| x.as_str()) { Some(h) => h.to_string(), None => return fail("bad_prevtx") }
                } else { l.to_string() };
                match blocktools_core::hex_dec(&h) { Some(b) => v.push(b), None => return fail("bad_prevtx") }
            }
            if v.len() > 2000 { return fail("too_many_prevtxs") }
            Some(v)
        }
    };
    let mut s = String::new();
    if std::io::stdin().take(blocktools_tx::MAX_INPUT as u64 + 1).read_to_string(&mut s).is_err() { return fail("bad_input") }
    if let Some(i) = a.iter().position(|x| x == "--nvc-json") {
        let Some(t) = a.get(i + 1) else { return fail("nvc_json_needs_txid") };
        return match blocktools_tx::nvc_json::serialize_nvc_tx_from_json(&s, t) { Ok(h) => blocktools_io::outln!("{h}"), Err(e) => fail(e) };
    }
    let r = match &prevtxs {
        Some(p) => blocktools_tx::input_bytes(&s).and_then(|b| blocktools_tx::decode_with_prevtxs(&b, chain, p)),
        None => blocktools_tx::decode(&s, chain),
    };
    match r {
        Ok(d) if text => blocktools_io::outln!("{}", d.text().trim_end()),
        Ok(d) => for l in d.json_lines() { blocktools_io::outln!("{l}") },
        Err(e) => fail(e),
    }
}
fn fail(e: &str) { blocktools_io::outln!("{}", serde_json::json!({"tool":"tx-decode","status":"bad_input","error":e})); std::process::exit(2) }
