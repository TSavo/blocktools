//! utxo-fetch (HOST-SIDE, network): public chain data for addresses -> files tx-build reads.
//!   utxo-fetch --chain btc|ltc|doge [--url ESPLORA_BASE] [--no-prev-tx] [ADDR...]  (or addresses on stdin)
//!       prev_tx is fetched for every legacy (non-witness-program, incl. P2SH) input; tx-build refuses such inputs without it
//!       (--no-prev-tx is only useful for segwit-only sets).
//!       stdout: UTXO JSON lines {"txid","vout","amount","address"[,"prev_tx"]}  (tx-build --utxos FILE)
//!   utxo-fetch --chain eth [--url RPC] ADDR
//!       stdout: one account object {"nonce","balance","max_fee_per_gas","max_priority_fee_per_gas","chain_id"}
//!   utxo-fetch --chain xlm|algo|atom|ton [--url NODE] ADDR
//!       ton: balance_nanoton, seqno, wallet_type, account_state (toncenter v2)
//!       atom: balance_uatom, account_number, sequence, pubkey (hex, once the account has signed)
//!       stdout: one account object (xlm: balance_str, next_seq, subentry_count; algo: amount, min_balance, assets, last_round, min_fee) for acct-tx build
//! Only ADDRESSES go in (bare, or JSON lines with an "address" field, e.g. redact output).
//! Server data is untrusted: txids are re-checked here, prev_tx is re-hashed by tx-build.
//! A summary goes to stderr. Defaults: btc blockstream.info, ltc litecoinspace.org, eth publicnode.
use serde_json::{json, Value};
use std::io::{BufRead, Read};

fn die(e: &str) -> ! { eprintln!("{}", json!({"tool":"utxo-fetch","status":"error","error":e})); std::process::exit(1) }
fn main() {
    blocktools_io::help("utxo-fetch --chain btc|ltc|doge|eth|xlm|algo|atom|ton [--url URL] [--no-prev-tx] [ADDR...] -> UTXO lines / account object");
    let a: Vec<String> = std::env::args().skip(1).collect();
    let mut chain = "btc".to_string(); let mut url = None; let mut prev = true; let mut addrs = Vec::new();
    let mut it = a.into_iter();
    while let Some(x) = it.next() { match x.as_str() {
        "--chain" => chain = it.next().unwrap_or_else(|| die("--chain")), "--url" => url = it.next(), "--no-prev-tx" => prev = false,
        s if s.starts_with('-') => die("unknown flag"), _ => addrs.push(x) } }
    if addrs.is_empty() {
        for l in std::io::stdin().lock().take(4 << 20).lines().map_while(Result::ok) {
            let t = l.trim(); if t.is_empty() { continue }
            match serde_json::from_str::<Value>(t) { Ok(v) if v.is_object() => if let Some(s) = v["address"].as_str() { addrs.push(s.to_string()) }, _ => addrs.push(t.to_string()) }
        }
    }
    addrs.sort(); addrs.dedup();
    if addrs.is_empty() || addrs.len() > 1000 { die("give 1..1000 addresses") }
    let vchain = if chain == "eth" { "eth" } else { chain.as_str() };
    for x in &addrs { if blocktools_core::validate::validate(vchain, x).is_err() { die("invalid address for chain") } }
    if chain == "ada" { return ada(url.as_deref().unwrap_or("https://api.koios.rest/api/v1"), &addrs) }
    if chain == "xlm" || chain == "algo" || chain == "atom" || chain == "ton" || chain == "dot" { return acct(&chain, url.as_deref(), &addrs) }
    if chain == "eth" { return eth(url.as_deref().unwrap_or("https://ethereum-rpc.publicnode.com"), &addrs) }
    let base = url.unwrap_or_else(|| match chain.as_str() { "btc" => "https://blockstream.info/api".into(), "ltc" => "https://litecoinspace.org/api".into(), _ => die("--url ESPLORA_BASE required for this chain") });
    let base = base.trim_end_matches('/');
    let (mut n, mut total) = (0u64, 0u64);
    for ad in &addrs {
        let body = blocktools_net::get(&format!("{base}/address/{ad}/utxo")).unwrap_or_else(|e| die(&e));
        let list: Vec<Value> = serde_json::from_slice(&body).unwrap_or_else(|_| die("bad utxo response"));
        // Legacy-sighash inputs (anything but a witness program; bare P2SH may wrap a legacy script) need the full previous tx:
        // their signature does not commit to the amount, and tx-build / tx-sign refuse them without it.
        let legacy = blocktools_core::chains::chain(&chain).and_then(|c| blocktools_core::chains::address_to_script(c, ad))
            .map(|s| !(matches!(s.first(), Some(0x00) | Some(0x51..=0x60)) && s.len() >= 4 && s.len() <= 42 && s[1] as usize == s.len() - 2))
            .unwrap_or(true);
        for u in list {
            let txid = u["txid"].as_str().filter(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())).unwrap_or_else(|| die("bad txid from server"));
            let vout = u["vout"].as_u64().filter(|&v| v <= u32::MAX as u64).unwrap_or_else(|| die("bad vout from server"));
            let value = u["value"].as_u64().filter(|&v| v > 0 && v <= i64::MAX as u64).unwrap_or_else(|| die("bad value from server"));
            let mut o = json!({"txid":txid,"vout":vout,"amount":value,"address":ad});
            if prev && legacy {
                let hex = blocktools_net::get(&format!("{base}/tx/{txid}/hex")).unwrap_or_else(|e| die(&e));
                let hex = String::from_utf8(hex).ok().map(|s| s.trim().to_string()).filter(|s| s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit())).unwrap_or_else(|| die("bad tx hex from server"));
                o["prev_tx"] = json!(hex);
            }
            blocktools_io::outln!("{o}"); n += 1; total = total.saturating_add(value);
            if n > 2000 { die("more than 2000 utxos") }
        }
    }
    eprintln!("{}", json!({"tool":"utxo-fetch","status":"done","chain":chain,"count":n,"amount":total}));
}
/// Cardano UTxOs via Koios: one line per UTxO, ready for `acct-tx build --chain ada --utxo TXID#IX:LOVELACE`.
fn ada(url: &str, addrs: &[String]) {
    let body = blocktools_net::post(&format!("{}/address_utxos", url.trim_end_matches('/')), json!({"_addresses":addrs}).to_string().as_bytes(), "application/json").unwrap_or_else(|e| die(&e));
    let list: Vec<Value> = serde_json::from_slice(&body).unwrap_or_else(|_| die("bad utxo response"));
    let (mut n, mut total) = (0u64, 0u64);
    for u in list {
        let txid = u["tx_hash"].as_str().filter(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())).unwrap_or_else(|| die("bad txid from server"));
        let ix = u["tx_index"].as_u64().filter(|&v| v <= u32::MAX as u64).unwrap_or_else(|| die("bad index from server"));
        let value: u64 = u["value"].as_str().and_then(|v| v.parse().ok()).unwrap_or_else(|| die("bad value from server"));
        let assets = u["asset_list"].as_array().is_some_and(|a| !a.is_empty());
        let mut o = json!({"txid":txid,"vout":ix,"amount":value,"address":u["address"],"utxo":format!("{txid}#{ix}:{value}")});
        if assets { o["warning"] = json!("carries_native_assets: acct-tx ada builds ADA-only outputs, spending this would burn/strand the assets; do not pass it (NOT BUILT)") }
        blocktools_io::outln!("{o}"); n += 1; if !assets { total = total.saturating_add(value) }
        if n > 2000 { die("more than 2000 utxos") }
    }
    eprintln!("{}", json!({"tool":"utxo-fetch","status":"done","chain":"ada","count":n,"amount_ada_only":total,"source":url}));
}
fn eth(url: &str, addrs: &[String]) {
    if addrs.len() != 1 { die("eth: give exactly one address") }
    let ad = &addrs[0];
    let q = |m: &str, p: Value| blocktools_net::rpc(url, m, p).and_then(|v| blocktools_net::qty(&v)).unwrap_or_else(|e| die(&e));
    let chain_id = q("eth_chainId", json!([]));
    let nonce = q("eth_getTransactionCount", json!([ad, "pending"]));
    let balance = q("eth_getBalance", json!([ad, "latest"]));
    let gas_price = q("eth_gasPrice", json!([]));
    let prio = blocktools_net::rpc(url, "eth_maxPriorityFeePerGas", json!([])).and_then(|v| blocktools_net::qty(&v)).unwrap_or(1_000_000_000);
    // maxFee = 2 x current gas price (+ tip): headroom for base-fee rises; unused fee is not charged.
    blocktools_io::outln!("{}", json!({"chain_id":chain_id as u64,"nonce":nonce as u64,"balance":balance.to_string(),
        "max_fee_per_gas":gas_price.saturating_mul(2).saturating_add(prio).to_string(),"max_priority_fee_per_gas":prio.to_string()}));
    eprintln!("{}", json!({"tool":"utxo-fetch","status":"done","chain":"eth","count":1}));
}

fn get_json(u: &str) -> Value { serde_json::from_slice(&blocktools_net::get(u).unwrap_or_else(|e| die(&e))).unwrap_or_else(|_| die("bad json from node")) }
/// Account-model balance + the parameters acct-tx build needs. Server data is untrusted: it only feeds build flags the user reviews.
fn acct(chain: &str, url: Option<&str>, addrs: &[String]) {
    if addrs.len() != 1 { die("give exactly one address") }
    let ad = &addrs[0];
    if chain == "dot" {
        let node = url.unwrap_or("https://polkadot-asset-hub-rpc.polkadot.io");
        let r = |m: &str, p: Value| blocktools_net::rpc(node, m, p).unwrap_or_else(|e| die(&e));
        let pk = blocktools_core::chains::ss58_decode(0, ad).unwrap_or_else(|e| die(e));
        // System.Account key = twox128("System") ++ twox128("Account") ++ blake2_128(pk) ++ pk
        let mut k = "0x26aa394eea5630e07c48ae0c9558cef7b99d880ec681799c0cf30e8886371da9".to_string();
        for b in blocktools_core::blake2b::blake2b(16, &[0; 16], &pk).iter().chain(pk.iter()) { k.push_str(&format!("{b:02x}")) }
        let info = r("state_getStorage", json!([k]));
        let free = info.as_str().map(|h| h.trim_start_matches("0x")).filter(|h| h.len() >= 64).map(|h| { let mut b = [0u8; 16]; for i in 0..16 { b[i] = u8::from_str_radix(&h[32 + 2 * i..34 + 2 * i], 16).unwrap_or_else(|_| die("bad account info")) } u128::from_le_bytes(b) }).unwrap_or(0);
        let nonce = r("system_accountNextIndex", json!([ad]));
        let ver = r("state_getRuntimeVersion", json!([]));
        let head = r("chain_getFinalizedHead", json!([]));
        let hdr = r("chain_getHeader", json!([head]));
        let num = u64::from_str_radix(hdr["number"].as_str().unwrap_or("0x0").trim_start_matches("0x"), 16).unwrap_or_else(|_| die("bad header"));
        let mut w = vec![];
        if ver["specVersion"] != json!(2005000) || ver["transactionVersion"] != json!(15) { w.push("runtime_differs_from_tested_2005000/15: acct-tx dot layout unchecked for this runtime") }
        println!("{}", json!({"chain":"dot","network":"Polkadot Asset Hub","address":ad,"free_planck":free.to_string(),"nonce":nonce,"spec":ver["specVersion"],"tx_version":ver["transactionVersion"],
            "block_number":num,"block_hash":head,"warnings":w,"source":node}));
        return
    }
    if chain == "ton" {
        let node = url.unwrap_or("https://toncenter.com/api/v2").trim_end_matches('/');
        let v = get_json(&format!("{node}/getWalletInformation?address={ad}"));
        let r = &v["result"];
        let mut w = vec![];
        if r["wallet_type"].as_str() != Some("wallet v4 r2") { w.push("not_wallet_v4r2: acct-tx builds v4r2 messages only") }
        if r["account_state"].as_str() != Some("active") { w.push("not_active: seqno 0 / undeployed wallets need the deploy message (NOT BUILT)") }
        println!("{}", json!({"chain":"ton","address":ad,"balance_nanoton":r["balance"],"seqno":r["seqno"],"wallet_type":r["wallet_type"],"account_state":r["account_state"],"subwallet_id":r["wallet_id"],"warnings":w,"source":node}));
        return
    }
    if chain == "atom" {
        let node = url.unwrap_or("https://cosmos-rest.publicnode.com").trim_end_matches('/');
        let v = get_json(&format!("{node}/cosmos/auth/v1beta1/accounts/{ad}"));
        let b = get_json(&format!("{node}/cosmos/bank/v1beta1/balances/{ad}/by_denom?denom=uatom"));
        let acc = &v["account"];
        let pk = acc["pub_key"]["key"].as_str().and_then(blocktools_core::b64::decode).map(|k| k.iter().map(|x| format!("{x:02x}")).collect::<String>());
        println!("{}", json!({"chain":"atom","address":ad,"balance_uatom":b["balance"]["amount"],"account_number":acc["account_number"],"sequence":acc["sequence"],"pubkey":pk,"source":node}));
        return
    }
    if chain == "xlm" {
        let node = url.unwrap_or("https://horizon.stellar.org").trim_end_matches('/');
        let v = get_json(&format!("{node}/accounts/{ad}"));
        let bal = v["balances"].as_array().and_then(|b| b.iter().find(|x| x["asset_type"] == "native")).map(|x| x["balance"].clone());
        let seq: i64 = v["sequence"].as_str().and_then(|s| s.parse().ok()).unwrap_or_else(|| die("no sequence (account not funded?)"));
        println!("{}", json!({"chain":"xlm","address":ad,"balance_str":bal,"next_seq":seq + 1,"subentry_count":v["subentry_count"],"source":node}));
    } else {
        let node = url.unwrap_or("https://mainnet-api.algonode.cloud").trim_end_matches('/');
        let v = get_json(&format!("{node}/v2/accounts/{ad}?exclude=all"));
        let p = get_json(&format!("{node}/v2/transactions/params"));
        println!("{}", json!({"chain":"algo","address":ad,"amount_microalgo":v["amount"],"min_balance_microalgo":v["min-balance"],
            "total_assets_opted_in":v["total-assets-opted-in"],"last_round":p["last-round"],"min_fee":p["min-fee"],"genesis_id":p["genesis-id"],"source":node}));
    }
}
