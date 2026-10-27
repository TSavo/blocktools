//! tx-decode: one transaction on stdin (hex/base64 raw tx, PSBT, EVM RLP, or a JSON line with
//! "psbt"/"tx"/"unsigned_tx"/"signed_tx") -> public JSON lines, or --text for a human summary.
//! Offline, no keys, never opens a network connection. Flags: --chain btc|ltc|doge (address
//! encoding for UTXO txs; eth insists on an EVM tx, which is otherwise auto-detected: legacy, 2930, 1559, 4844, 7702), --text, --nvc-json TXID (Novacoin explorer JSON on stdin -> raw hex,
//! hash-checked against TXID), --prevtxs FILE (full previous transactions, one per line as hex or a
//! JSON line with "tx"/"hex", e.g. the output of `rpc URL prevtxs` or `rpc URL rawtx`): input
//! amounts and the fee are filled in for a raw UTXO tx. A prev tx counts only if it hashes to the
//! input's outpoint txid; an input with no matching prev tx stays unknown (warning prevout_missing);
//! a prev tx matching no input is refused (prevtx_unused). Fetching prev txs is rpc's job (its
//! allowlist, deny-list and credential redaction apply); tx-decode itself stays offline.
use std::io::Read;
fn main() {
    blocktools_io::help("tx-decode [--chain btc|ltc|doge|eth|...] [--text] [--prevtxs FILE] < transaction -> JSON lines (or plain summary)\n       tx-decode --nvc-json TXID < api.novaco.in gettransaction JSON -> raw tx hex (fails unless the hash is TXID)\n       rpc URL rawtx TXID [BLOCKHASH] | tx-decode                      decode a tx fetched by rpc (its JSON line has \"tx\")\n       rpc URL rawtx TXID > t; rpc URL prevtxs < t > p; tx-decode --prevtxs p < t   input amounts + fee\n  --prevtxs FILE: previous txs, one per line (hex, or JSON with \"tx\"/\"hex\"); each must hash to an input's outpoint\n  txid (else prevtx_unused); inputs without one warn prevout_missing. tx-decode never opens a socket.\n  EVM (legacy, EIP-2930, EIP-1559, EIP-4844 incl. the blob network form, EIP-7702; signed or unsigned) is detected\n  from the bytes, also in an `rpc URL eth_getRawTransactionByHash` reply; --chain eth only refuses non-EVM input (not_evm).\n  Same summary keys as the UTXO path (chain, type, signed, txid, inputs, outputs, warnings) plus from, to, nonce, gas,\n  value, tx_type, data, access_list, v/r/s and the per-type fee fields; no per-input/output lines.\n  --chain xlm|algo|atom|ton|ada|dot runs `acct-tx decode --chain C`, sol|tron `sol-tron-tx decode --chain C`, xrp `xrp-tx decode`\n  (same directory, same output as calling them; --testnet passed through): one decode verb for every chain.\n  Input is read from stdin only; a hex argument is not read (bad_transaction on empty stdin).");
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
    // One decode verb: for account / non-UTXO chains tx-decode hands stdin to the chain's existing decoder
    // (same binary directory), whose output shape is unchanged: acct-tx decode, sol-tron-tx decode, xrp-tx decode.
    let delegate: Option<(&str, Vec<String>)> = match chain {
        "xlm" | "algo" | "atom" | "ton" | "ada" | "dot" => Some(("acct-tx", vec!["decode".into(), "--chain".into(), chain.into()])),
        "sol" | "tron" => Some(("sol-tron-tx", vec!["decode".into(), "--chain".into(), chain.into()])),
        "xrp" => Some(("xrp-tx", vec!["decode".into()])),
        _ => None,
    };
    if let Some((tool, mut args)) = delegate {
        if a.iter().any(|x| x == "--testnet") { args.push("--testnet".into()) }
        let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())) else { return fail("delegate_missing") };
        return match std::process::Command::new(dir.join(tool)).args(&args).status() {
            Ok(st) => std::process::exit(st.code().unwrap_or(1)),
            Err(_) => fail("delegate_missing"),
        };
    }
    let mut s = String::new();
    if std::io::stdin().take(blocktools_tx::MAX_INPUT as u64 + 1).read_to_string(&mut s).is_err() { return fail("bad_input") }
    if let Some(i) = a.iter().position(|x| x == "--nvc-json") {
        let Some(t) = a.get(i + 1) else { return fail("nvc_json_needs_txid") };
        return match blocktools_tx::nvc_json::serialize_nvc_tx_from_json(&s, t) { Ok(h) => blocktools_io::outln!("{h}"), Err(e) => fail(e) };
    }
    // EVM: auto-detected from the bytes (an RLP list, or type byte 0x01..=0x04 then a list); --chain eth
    // only insists on it. An `rpc URL eth_getRawTransactionByHash` reply ({"result":"0x.."}) is read as the raw tx.
    let evm_bytes = || -> Option<Vec<u8>> {
        let t = s.trim();
        let b = if t.starts_with('{') {
            let j: serde_json::Value = serde_json::from_str(t).ok()?;
            match j.get("result").and_then(|x| x.as_str()) { Some(h) => blocktools_core::hex_dec(h)?, None => blocktools_tx::input_bytes(t).ok()? }
        } else { blocktools_tx::input_bytes(t).ok()? };
        blocktools_tx::evm_decode::is_evm(&b).then_some(b)
    };
    if prevtxs.is_none() {
        if let Some(b) = evm_bytes() {
            return match blocktools_tx::decode_evm_view(&b) {
                Ok((d, _)) if text => blocktools_io::outln!("{}", d.text().trim_end()),
                Ok((d, v)) => {
                    let mut l = d.json_lines();
                    if let Some(o) = l[0].as_object_mut() { for (k, x) in v.extra() { o.entry(k).or_insert(x); } }
                    for x in l { blocktools_io::outln!("{x}") }
                }
                Err(e) => fail(e),
            };
        }
        if chain == "eth" { return fail("not_evm") }
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
