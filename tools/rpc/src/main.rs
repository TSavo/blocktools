//! rpc: pipe filter for node and wallet RPC endpoints (HOST-SIDE, network)
//!   rpc URL METHOD [PARAMS-JSON]       one JSON-RPC call (EVM, bitcoind and forks, Solana); raw response on stdout
//!   ... | rpc URL                      JSON-RPC request(s) on stdin, single object or batch array, sent byte-for-byte
//!   rpc URL /PATH [BODY-JSON]          REST call (Tron, Cosmos LCD, Esplora, Blockbook): GET, or POST when BODY is given
//!   rpc URL SHORTCUT [ARG]             height | chainid | balance ADDR | nonce ADDR | account ADDR | utxos ADDR | tx ID | receipt ID | fee | blockhash
//!   rpc URL rawtx TXID [BLOCKHASH]     bitcoind: {"protocol","txid","tx":HEX[,"blockhash"]}, hash-checked; pipes into tx-decode
//!   rpc URL block [HEIGHT|HASH]        bitcoind: {"protocol","height","hash","time","n_tx","previous","txids":[...]} (default: tip)
//!   rpc URL blockinfo                  bitcoind: {"protocol","chain","blocks","headers","best","progress","pruned"}
//!   ... | rpc URL prevtxs              bitcoind: tx on stdin -> one rawtx line per distinct input txid (tx-decode --prevtxs)
//!   ... | rpc URL sendraw              broadcast ONE signed tx (tx-sign output or hex): decoded summary + typed code on the terminal
//! URL may also be a chain name from the shared endpoint table (btc, ltc, eth, atom, ...) or an EVM chain id with a default (1).
//! The protocol is detected from the URL, then the method name, then (shortcuts only) read-only probes; --protocol overrides.
//! Options:
//!   --protocol evm|btc|sol|tron|cosmos|esplora|blockbook   override detection
//!   --chain-id N          EVM: refuse unless the endpoint's eth_chainId is N (chain_id_mismatch)
//!   --chain C             UTXO chain for utxos/sendraw address checks and decoding (default btc)
//!   --auth-file FILE      credentials: "user:pass" or a bitcoind .cookie (Basic), "Bearer T" or a bare token, or "Header: value" lines
//!   --auth-env NAME       same, read from environment variable NAME (the value is never printed)
//!   --policy FILE         {"version":1,"rpc":{"deny":["method","prefix_*"]}}: adds refusals, cannot remove any
//!   --allow-wallet-sign   open eth_sendTransaction / eth_signTypedData_v4 only: prints a decoded summary to stderr first,
//!                         refuses undecodable requests and chain ids that differ from the endpoint's; the wallet UI confirms
//!   --allow-unlisted      send a method or REST path that is not in the per-protocol read allowlist (default: refused,
//!                         method_not_allowlisted, nothing sent); the deny-list, secret-field and broadcast refusals still apply
//!   --timeout SECONDS     per request, 1..300 (default 30)
//! Params are ONE JSON array argument, e.g. rpc URL getrawtransaction '["TXID",false,"BLOCKHASH"]' (shell-quote
//!  it); `getblockhash 2` or two separate params are bad_input (exit 2), nothing sent: write '[2]'.
//! Two output shapes: shortcuts print one tidy JSON line (fields above); METHOD/stdin passthrough prints the
//! node's raw JSON-RPC envelope, so read .result. A pruned node without -txindex answers getrawtransaction
//! only with the block hash (rawtx TXID BLOCKHASH; prevtxs needs -txindex). getblock at verbosity 2 can
//! exceed the 8 MiB cap: use block (verbosity 1) and fetch txs one at a time.
//! Telling a refusal from a node answer: stderr {"status":"refused","code":...} means rpc sent NOTHING
//! (allowlist, deny-list, secret field, credential flag); "rpc_error" or "http_error" means the node or server
//! answered with an error. All three exit 1. "bad_input" (exit 2) is decided locally before any connection.
//!  Auth fails closed: an empty --auth-file is auth_empty (exit 2) and the secret is never echoed anywhere.
//!  --allow-unlisted lifts only the allowlist: dumpprivkey and the rest of the deny-list stay refused.
//! Scripts: in `rpc ... | tx-decode` the pipe's exit status is tx-decode's, so use `set -o pipefail` or
//! branch on the "status" field (`rpc URL dumpprivkey '["x"]' | cat` exits 0 in bash, PIPESTATUS 1 0).
//! stdout: the response body (JSON-RPC: the raw response) or one JSON line per shortcut result; utxos prints utxo-fetch lines
//! (tx-build --utxos FILE) and account prints the utxo-fetch eth account object (tx-build --account FILE).
//! stderr: one JSON line {"tool":"rpc","status":...} on error or refusal. Exit 0 ok, 2 bad input, 1 everything else (RPC/HTTP error, refused, aborted): docs/EXIT-CODES.md.
//! Fail closed: only methods and REST paths in the per-protocol read allowlist (ALLOW in tools/rpc/src/lib.rs) are sent.
//! Refused even with --allow-unlisted (deny-list, see docs/RPC.md): methods that export, import or unlock keys, wallet
//! signing and wallet spending, requests carrying secret fields, responses carrying keys, broadcasts outside sendraw.
//! Credentials are never accepted as arguments or in the URL, and every credential string is redacted from stdout and stderr.
//! Bounds: 30 s timeout, redirects never followed, 8 MiB response cap, https only (plain http for localhost). No retries.
use rpc::*;
use serde_json::{json, Value};
use std::io::{IsTerminal, Read};

struct Cx { url: String, proto: Option<Proto>, headers: Vec<(String, String)>, secrets: Vec<String>, deny: Vec<String>, wallet_sign: bool, allow_unlisted: bool, chain_id: Option<u64>, chain: String, timeout: u64 }

fn fail(cx: Option<&Cx>, status: &str, extra: Value) -> ! {
    let mut v = json!({"tool":"rpc","status":status});
    v.as_object_mut().unwrap().extend(extra.as_object().cloned().unwrap_or_default());
    let s = v.to_string();
    eprintln!("{}", cx.map_or(s.clone(), |c| redact(&s, &c.secrets)));
    std::process::exit(blocktools_io::exit_code(status))  // docs/EXIT-CODES.md: refused/aborted exit 1
}
fn bad(cx: Option<&Cx>, e: &str) -> ! { fail(cx, "bad_input", json!({"error":e})) }
fn refused(cx: &Cx, r: Refusal) -> ! { fail(Some(cx), "refused", json!({"code":r.code,"detail":r.detail})) }

/// stdout: data only. If stdout is a terminal, control characters (escape sequences) are replaced.
fn emit(cx: &Cx, body: &str) {
    let mut s = redact(body, &cx.secrets);
    if std::io::stdout().is_terminal() { s = s.chars().map(|c| if c.is_control() && c != '\n' && c != '\t' { '?' } else { c }).collect() }
    blocktools_io::outln!("{}", s.trim_end_matches('\n'));
}
fn snippet(b: &[u8]) -> String { String::from_utf8_lossy(&b[..b.len().min(300)]).chars().map(|c| if c.is_control() { ' ' } else { c }).collect() }

fn http(cx: &Cx, method: &str, url: &str, body: Option<&[u8]>) -> (i32, Vec<u8>) {
    blocktools_net::send(method, url, body, &cx.headers, cx.timeout).unwrap_or_else(|e| fail(Some(cx), "http_error", json!({"error":e})))
}
fn withhold_secrets(cx: &Cx, v: &Value) { if let Some(w) = response_secret(v, 0) { refused(cx, Refusal { code: "response_contains_secret", detail: format!("{w}; nothing printed") }) } }

/// One checked JSON-RPC call; returns `result`.
fn jr(cx: &Cx, method: &str, params: Value) -> Value {
    if let Err(r) = check_call_in(cx.proto, cx.allow_unlisted, method, &params, &cx.deny, false, false) { refused(cx, r) }
    let req = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let (code, b) = http(cx, "POST", &cx.url, Some(req.as_bytes()));
    let v: Value = serde_json::from_slice(&b).unwrap_or_else(|_| fail(Some(cx), "http_error", json!({"http_status":code,"error":"response is not JSON","body":snippet(&b)})));
    if !v["error"].is_null() { fail(Some(cx), "rpc_error", json!({"method":method,"error":v["error"]})) }
    withhold_secrets(cx, &v);
    v.get("result").cloned().unwrap_or_else(|| fail(Some(cx), "rpc_error", json!({"method":method,"error":"no result"})))
}
fn base(cx: &Cx) -> String {
    let u = cx.url.trim_end_matches('/');
    if cx.proto == Some(Proto::Blockbook) { u.trim_end_matches("/api/v2").trim_end_matches("/api").to_string() } else { u.to_string() }
}
/// One checked REST call; returns parsed JSON (or a JSON string for text bodies).
fn rest(cx: &Cx, path: &str, body: Option<&Value>) -> Value {
    if let Err(r) = check_call_in(cx.proto, cx.allow_unlisted, path, body.unwrap_or(&Value::Null), &cx.deny, false, body.is_some()) { refused(cx, r) }
    let url = format!("{}/{}", base(cx), path.trim_start_matches('/'));
    let bs = body.map(|b| b.to_string());
    let (code, b) = http(cx, if bs.is_some() { "POST" } else { "GET" }, &url, bs.as_deref().map(str::as_bytes));
    if !(200..300).contains(&code) { fail(Some(cx), "http_error", json!({"http_status":code,"body":snippet(&b)})) }
    let v = serde_json::from_slice(&b).unwrap_or_else(|_| json!(String::from_utf8_lossy(&b).trim()));
    withhold_secrets(cx, &v);
    v
}
fn qty(cx: &Cx, v: &Value) -> u128 { blocktools_net::qty(v).unwrap_or_else(|e| fail(Some(cx), "rpc_error", json!({"error":e}))) }
fn endpoint_chain_id(cx: &Cx) -> u64 { let v = jr(cx, "eth_chainId", json!([])); u64::try_from(qty(cx, &v)).unwrap_or_else(|_| bad(Some(cx), "chain id too large")) }
fn pin_chain(cx: &Cx) { if let Some(want) = cx.chain_id { let got = endpoint_chain_id(cx); if got != want { refused(cx, Refusal { code: "chain_id_mismatch", detail: format!("endpoint eth_chainId {got}, --chain-id {want}") }) } } }

/// Detection for shortcuts: --protocol, URL, then read-only probes (eth_chainId, getVersion, getblockchaininfo).
fn proto_for_shortcut(cx: &Cx) -> Proto {
    if let Some(p) = cx.proto { return p }
    let probe = |m: &str| -> Option<Value> {
        let req = json!({"jsonrpc":"2.0","id":1,"method":m,"params":[]}).to_string();
        let (_, b) = blocktools_net::send("POST", &cx.url, Some(req.as_bytes()), &cx.headers, cx.timeout).ok()?;
        let v: Value = serde_json::from_slice(&b).ok()?;
        v.get("result").filter(|r| !r.is_null()).cloned()
    };
    if probe("eth_chainId").is_some_and(|r| r.is_string()) { return Proto::Evm }
    if probe("getVersion").is_some_and(|r| r.get("solana-core").is_some()) { return Proto::Sol }
    if probe("getblockchaininfo").is_some_and(|r| r.get("chain").is_some()) { return Proto::Btc }
    refused(cx, Refusal { code: "protocol_unknown", detail: "could not detect the protocol; give --protocol".into() })
}
fn unsupported(cx: &Cx, p: Proto, what: &str) -> ! { refused(cx, Refusal { code: "unsupported_for_protocol", detail: format!("{what} on {}", p.name()) }) }
fn out(cx: &Cx, v: Value) { emit(cx, &v.to_string()) }
fn legacy(chain: &str, ad: &str) -> bool {
    // same rule as utxo-fetch: anything but a witness program needs prev_tx
    blocktools_core::chains::chain(chain).and_then(|c| blocktools_core::chains::address_to_script(c, ad))
        .map(|s| !(matches!(s.first(), Some(0x00) | Some(0x51..=0x60)) && s.len() >= 4 && s.len() <= 42 && s[1] as usize == s.len() - 2)).unwrap_or(true)
}
fn check_addr(cx: &Cx, p: Proto, a: &str) {
    let chain = match p { Proto::Evm => "eth", Proto::Btc | Proto::Esplora | Proto::Blockbook => cx.chain.as_str(), Proto::Sol => "sol", Proto::Tron => "tron", Proto::Cosmos => return };
    if a.is_empty() || a.len() > 128 || !a.bytes().all(|b| b.is_ascii_alphanumeric() || b == b':') { bad(Some(cx), "address has characters no address uses") }
    if blocktools_core::validate::validate(chain, a).is_err() && p != Proto::Sol { bad(Some(cx), "invalid address for chain (set --chain for UTXO forks)") }
}
fn check_id(cx: &Cx, id: &str) { if id.is_empty() || id.len() > 128 || !id.bytes().all(|b| b.is_ascii_alphanumeric()) { bad(Some(cx), "id must be hex or base58") } }

fn shortcut(cx: &Cx, name: &str, arg: Option<&str>, arg2: Option<&str>) {
    let p = proto_for_shortcut(cx);
    if p == Proto::Evm { pin_chain(cx) }
    let need = |what: &str| -> String { let a = arg.unwrap_or_else(|| bad(Some(cx), &format!("{name} needs {what}"))).to_string(); a };
    let pn = p.name();
    match (name, p) {
        ("height", Proto::Evm) => { let h = jr(cx, "eth_blockNumber", json!([])); out(cx, json!({"protocol":pn,"height":qty(cx, &h) as u64})) }
        ("height", Proto::Btc) => out(cx, json!({"protocol":pn,"height":jr(cx, "getblockcount", json!([]))})),
        ("height", Proto::Sol) => out(cx, json!({"protocol":pn,"height":jr(cx, "getBlockHeight", json!([]))})),
        ("height", Proto::Tron) => { let v = rest(cx, "wallet/getnowblock", Some(&json!({}))); out(cx, json!({"protocol":pn,"height":v["block_header"]["raw_data"]["number"]})) }
        ("height", Proto::Cosmos) => { let v = rest(cx, "cosmos/base/tendermint/v1beta1/blocks/latest", None); out(cx, json!({"protocol":pn,"height":v["block"]["header"]["height"].as_str().and_then(|s| s.parse::<u64>().ok())})) }
        ("height", Proto::Esplora) => { let v = rest(cx, "blocks/tip/height", None); out(cx, json!({"protocol":pn,"height":v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))})) }
        ("height", Proto::Blockbook) => { let v = rest(cx, "api/v2", None); out(cx, json!({"protocol":pn,"height":v["blockbook"]["bestHeight"]})) }
        ("chainid", Proto::Evm) => out(cx, json!({"protocol":pn,"chain_id":endpoint_chain_id(cx)})),
        ("balance", _) | ("nonce", _) | ("account", _) | ("utxos", _) => {
            let a = need("an address"); check_addr(cx, p, &a);
            match (name, p) {
                ("balance", Proto::Evm) => { let b = jr(cx, "eth_getBalance", json!([a, "latest"])); out(cx, json!({"protocol":pn,"address":a,"balance":qty(cx, &b).to_string(),"unit":"wei"})) }
                ("nonce", Proto::Evm) => { let n = jr(cx, "eth_getTransactionCount", json!([a, "pending"])); out(cx, json!({"protocol":pn,"address":a,"nonce":qty(cx, &n) as u64})) }
                ("account", Proto::Evm) => {
                    // the utxo-fetch --chain eth object (tx-build --account FILE)
                    let q = |m: &str, p: Value| qty(cx, &jr(cx, m, p));
                    let chain_id = q("eth_chainId", json!([])); let nonce = q("eth_getTransactionCount", json!([a, "pending"]));
                    let balance = q("eth_getBalance", json!([a, "latest"])); let gas = q("eth_gasPrice", json!([])); let prio = q("eth_maxPriorityFeePerGas", json!([]));
                    out(cx, json!({"chain_id":chain_id as u64,"nonce":nonce as u64,"balance":balance.to_string(),"max_fee_per_gas":gas.saturating_mul(2).saturating_add(prio).to_string(),"max_priority_fee_per_gas":prio.to_string()}))
                }
                ("balance", Proto::Btc) | ("utxos", Proto::Btc) => {
                    let r = jr(cx, "scantxoutset", json!(["start", [format!("addr({a})")]]));
                    if name == "balance" { out(cx, json!({"protocol":pn,"address":a,"balance":coins_to_units(&r["total_amount"]).unwrap_or_else(|| bad(Some(cx), "bad amount from node")),"height":r["height"]})); return }
                    let lg = legacy(&cx.chain, &a);
                    for u in r["unspents"].as_array().cloned().unwrap_or_default() {
                        let txid = u["txid"].as_str().filter(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())).unwrap_or_else(|| bad(Some(cx), "bad txid from node")).to_string();
                        let amount = coins_to_units(&u["amount"]).filter(|&v| v > 0).unwrap_or_else(|| bad(Some(cx), "bad amount from node"));
                        let mut o = json!({"txid":txid,"vout":u["vout"],"amount":amount,"address":a});
                        if lg {
                            let hash = jr(cx, "getblockhash", json!([u["height"]]));
                            let hex = jr(cx, "getrawtransaction", json!([txid, false, hash]));
                            o["prev_tx"] = json!(hex.as_str().filter(|h| h.len() % 2 == 0 && h.bytes().all(|b| b.is_ascii_hexdigit())).unwrap_or_else(|| bad(Some(cx), "bad tx hex from node")));
                        }
                        out(cx, o)
                    }
                }
                ("utxos", Proto::Esplora) => for o in blocktools_net::esplora_utxos(&base(cx), &a, legacy(&cx.chain, &a)).unwrap_or_else(|e| fail(Some(cx), "http_error", json!({"error":e}))) { out(cx, o) },
                ("utxos", Proto::Blockbook) => {
                    let v = rest(cx, &format!("api/v2/utxo/{a}"), None); let lg = legacy(&cx.chain, &a);
                    for u in v.as_array().cloned().unwrap_or_default() {
                        let txid = u["txid"].as_str().filter(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())).unwrap_or_else(|| bad(Some(cx), "bad txid from server")).to_string();
                        let amount: u64 = u["value"].as_str().and_then(|s| s.parse().ok()).filter(|&v| v > 0).unwrap_or_else(|| bad(Some(cx), "bad value from server"));
                        let mut o = json!({"txid":txid,"vout":u["vout"],"amount":amount,"address":a,"confirmations":u["confirmations"]});
                        if lg { let t = rest(cx, &format!("api/v2/tx/{txid}"), None); o["prev_tx"] = json!(t["hex"].as_str().filter(|h| h.len() % 2 == 0 && h.bytes().all(|b| b.is_ascii_hexdigit())).unwrap_or_else(|| bad(Some(cx), "bad tx hex from server"))) }
                        out(cx, o)
                    }
                }
                ("balance", Proto::Esplora) => {
                    let v = rest(cx, &format!("address/{a}"), None);
                    let s = |k: &str, f: &str| v[k][f].as_i64().unwrap_or(0);
                    out(cx, json!({"protocol":pn,"address":a,"balance":s("chain_stats","funded_txo_sum") - s("chain_stats","spent_txo_sum"),"unconfirmed":s("mempool_stats","funded_txo_sum") - s("mempool_stats","spent_txo_sum")}))
                }
                ("balance", Proto::Blockbook) => { let v = rest(cx, &format!("api/v2/address/{a}?details=basic"), None); out(cx, json!({"protocol":pn,"address":a,"balance":v["balance"],"unconfirmed":v["unconfirmedBalance"]})) }
                ("balance", Proto::Sol) => { let v = jr(cx, "getBalance", json!([a])); out(cx, json!({"protocol":pn,"address":a,"balance":v["value"],"unit":"lamports"})) }
                ("balance", Proto::Tron) => { let v = rest(cx, "wallet/getaccount", Some(&json!({"address":a,"visible":true}))); out(cx, json!({"protocol":pn,"address":a,"balance":v["balance"].as_u64().unwrap_or(0),"unit":"sun","activated":v.get("address").is_some()})) }
                ("balance", Proto::Cosmos) => { let v = rest(cx, &format!("cosmos/bank/v1beta1/balances/{a}"), None); out(cx, json!({"protocol":pn,"address":a,"balances":v["balances"]})) }
                ("nonce", Proto::Cosmos) | ("account", Proto::Cosmos) => { let v = rest(cx, &format!("cosmos/auth/v1beta1/accounts/{a}"), None); let ac = &v["account"]; out(cx, json!({"protocol":pn,"address":a,"account_number":ac["account_number"],"sequence":ac["sequence"]})) }
                _ => unsupported(cx, p, name),
            }
        }
        ("tx", _) | ("receipt", _) => {
            let id = need("a transaction id"); check_id(cx, &id);
            let v = match (name, p) {
                ("tx", Proto::Evm) => jr(cx, "eth_getTransactionByHash", json!([id])),
                ("receipt", Proto::Evm) => jr(cx, "eth_getTransactionReceipt", json!([id])),
                ("tx", Proto::Btc) | ("receipt", Proto::Btc) => jr(cx, "getrawtransaction", json!([id, true])),
                ("tx", Proto::Sol) => jr(cx, "getTransaction", json!([id, {"encoding":"json","maxSupportedTransactionVersion":0}])),
                ("receipt", Proto::Sol) => jr(cx, "getSignatureStatuses", json!([[id], {"searchTransactionHistory":true}])),
                ("tx", Proto::Tron) => rest(cx, "wallet/gettransactionbyid", Some(&json!({"value":id}))),
                ("receipt", Proto::Tron) => rest(cx, "wallet/gettransactioninfobyid", Some(&json!({"value":id}))),
                ("tx", Proto::Cosmos) | ("receipt", Proto::Cosmos) => rest(cx, &format!("cosmos/tx/v1beta1/txs/{id}"), None),
                ("tx", Proto::Esplora) => rest(cx, &format!("tx/{id}"), None),
                ("receipt", Proto::Esplora) => rest(cx, &format!("tx/{id}/status"), None),
                (_, Proto::Blockbook) => rest(cx, &format!("api/v2/tx/{id}"), None),
                _ => unsupported(cx, p, name),
            };
            out(cx, v)
        }
        ("fee", Proto::Evm) => {
            let g = qty(cx, &jr(cx, "eth_gasPrice", json!([]))); let pr = qty(cx, &jr(cx, "eth_maxPriorityFeePerGas", json!([])));
            out(cx, json!({"protocol":pn,"gas_price":g.to_string(),"max_fee_per_gas":g.saturating_mul(2).saturating_add(pr).to_string(),"max_priority_fee_per_gas":pr.to_string(),"unit":"wei"}))
        }
        ("fee", Proto::Btc) => {
            let r = jr(cx, "estimatesmartfee", json!([6]));
            let per_kvb = coins_to_units(&r["feerate"]).unwrap_or_else(|| fail(Some(cx), "rpc_error", json!({"error":"no feerate (node has no estimate yet)","errors":r["errors"]})));
            out(cx, json!({"protocol":pn,"sat_per_vb":per_kvb as f64 / 1000.0,"blocks":r["blocks"]}))
        }
        ("fee", Proto::Esplora) => out(cx, json!({"protocol":pn,"sat_per_vb_by_target":rest(cx, "fee-estimates", None)})),
        ("fee", Proto::Blockbook) => out(cx, json!({"protocol":pn,"per_kb_coin":rest(cx, "api/v2/estimatefee/6", None)["result"]})),
        ("fee", Proto::Sol) => out(cx, json!({"protocol":pn,"recent_prioritization_fees":jr(cx, "getRecentPrioritizationFees", json!([]))})),
        ("rawtx", Proto::Btc) => {
            let id = need("a transaction id"); check_hex32(cx, &id);
            let bh = arg2; if let Some(h) = bh { check_hex32(cx, h) }
            out(cx, rawtx(cx, &id, bh))
        }
        ("prevtxs", Proto::Btc) => {
            let mut s = String::new();
            if std::io::stdin().take(blocktools_tx::MAX_INPUT as u64 + 1).read_to_string(&mut s).is_err() { bad(Some(cx), "stdin") }
            let raw = blocktools_tx::input_bytes(&s).unwrap_or_else(|e| bad(Some(cx), e));
            let d = blocktools_tx::decode_bytes(&raw, &cx.chain).unwrap_or_else(|e| bad(Some(cx), e));
            if d.ty != "btc-tx" { bad(Some(cx), "prevtxs takes a raw UTXO transaction") }
            let mut seen = vec![];
            for i in &d.inputs { if let Some(t) = &i.txid { if !seen.contains(t) { seen.push(t.clone()) } } }
            if seen.len() > 2000 { bad(Some(cx), "too many inputs") }
            for t in seen { out(cx, rawtx(cx, &t, None)) }
        }
        ("block", Proto::Btc) => {
            let h = match arg {
                None => jr(cx, "getbestblockhash", json!([])),
                Some(a) if !a.is_empty() && a.len() <= 10 && a.bytes().all(|b| b.is_ascii_digit()) => jr(cx, "getblockhash", json!([a.parse::<u64>().unwrap_or_else(|_| bad(Some(cx), "height"))])),
                Some(a) => { check_hex32(cx, a); json!(a) }
            };
            let b = jr(cx, "getblock", json!([h, 1]));
            out(cx, json!({"protocol":pn,"height":b["height"],"hash":b["hash"],"time":b["time"],"n_tx":b["nTx"],"previous":b["previousblockhash"],"txids":b["tx"]}))
        }
        ("blockinfo", Proto::Btc) => {
            let v = jr(cx, "getblockchaininfo", json!([]));
            out(cx, json!({"protocol":pn,"chain":v["chain"],"blocks":v["blocks"],"headers":v["headers"],"best":v["bestblockhash"],"progress":v["verificationprogress"],"pruned":v["pruned"]}))
        }
        ("blockhash", Proto::Sol) => { let v = jr(cx, "getLatestBlockhash", json!([{"commitment":"finalized"}])); out(cx, json!({"protocol":pn,"blockhash":v["value"]["blockhash"],"last_valid_block_height":v["value"]["lastValidBlockHeight"]})) }
        _ => unsupported(cx, p, name),
    }
}

fn check_hex32(cx: &Cx, h: &str) { if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) { bad(Some(cx), "expected a 64-hex txid / block hash") } }
/// getrawtransaction [txid, false(, blockhash)] -> {"protocol","txid","tx"(,"blockhash")}; the hex must hash to txid.
fn rawtx(cx: &Cx, id: &str, bh: Option<&str>) -> Value {
    let params = match bh { Some(h) => json!([id, false, h]), None => json!([id, false]) };
    if let Err(r) = check_call_in(cx.proto, cx.allow_unlisted, "getrawtransaction", &params, &cx.deny, false, false) { refused(cx, r) }
    let req = json!({"jsonrpc":"2.0","id":1,"method":"getrawtransaction","params":params}).to_string();
    let (code, b) = http(cx, "POST", &cx.url, Some(req.as_bytes()));
    let v: Value = serde_json::from_slice(&b).unwrap_or_else(|_| fail(Some(cx), "http_error", json!({"http_status":code,"error":"response is not JSON","body":snippet(&b)})));
    if !v["error"].is_null() {
        let hint = if bh.is_none() { "pruned node or no -txindex: give the block hash (rpc URL rawtx TXID BLOCKHASH)" } else { "transaction not in that block" };
        fail(Some(cx), "rpc_error", json!({"method":"getrawtransaction","error":v["error"],"hint":hint}))
    }
    withhold_secrets(cx, &v);
    let hex = v["result"].as_str().filter(|h| h.len() % 2 == 0 && h.bytes().all(|b| b.is_ascii_hexdigit())).unwrap_or_else(|| bad(Some(cx), "bad tx hex from node")).to_ascii_lowercase();
    let raw = blocktools_core::hex_dec(&hex).unwrap_or_else(|| bad(Some(cx), "bad tx hex from node"));
    let got = blocktools_tx::decode_bytes(&raw, &cx.chain).ok().and_then(|d| d.txid).unwrap_or_default();
    if !got.eq_ignore_ascii_case(id) { fail(Some(cx), "error", json!({"error":"node_tx_hash_differs","txid":id})) }
    let mut o = json!({"protocol":"btc","txid":id.to_ascii_lowercase(),"tx":hex});
    if let Some(h) = bh { o["blockhash"] = json!(h.to_ascii_lowercase()) }
    o
}
/// Broadcast one signed tx after the human types the code (same check and prompt as tx-broadcast).
fn sendraw(cx: &Cx) {
    let mut s = String::new();
    if std::io::stdin().take(blocktools_tx::MAX_INPUT as u64 + 1).read_to_string(&mut s).is_err() { bad(Some(cx), "stdin") }
    let raw = match serde_json::from_str::<Value>(s.trim()).ok().and_then(|v| v["signed_tx"].as_str().map(String::from)) {
        Some(h) => blocktools_core::hex_dec(h.trim_start_matches("0x")).unwrap_or_else(|| bad(Some(cx), "signed_tx hex")),
        None => blocktools_tx::input_bytes(&s).unwrap_or_else(|e| bad(Some(cx), e)),
    };
    let d = blocktools_tx::decode_bytes(&raw, &cx.chain).unwrap_or_else(|e| bad(Some(cx), e));
    if !d.signed { refused(cx, Refusal { code: "not_signed", detail: "sendraw takes a signed transaction".into() }) }
    let p = cx.proto.unwrap_or(if d.evm.is_some() { Proto::Evm } else { proto_for_shortcut(cx) });
    if d.evm.is_some() != (p == Proto::Evm) { refused(cx, Refusal { code: "chain_or_signature_mismatch", detail: format!("tx type {} vs endpoint protocol {}", d.ty, p.name()) }) }
    if let Some(e) = &d.evm {
        let got = endpoint_chain_id(cx);
        if e.chain_id != Some(got) || cx.chain_id.is_some_and(|c| c != got) { refused(cx, Refusal { code: "chain_id_mismatch", detail: format!("tx chain id {:?}, endpoint {got}", e.chain_id) }) }
    }
    let host = cx.url.split('/').take(3).collect::<Vec<_>>().join("/");
    let summary = format!("{}\nBROADCAST to {host} ({})\nThis is irreversible.\n", d.text().trim_end(), p.name());
    if !blocktools_tty::confirm(&summary) { fail(Some(cx), "aborted", json!({"detail":"no terminal or wrong code; nothing sent"})) }
    let hex = blocktools_core::hex_enc(&raw);
    let got = match p {
        Proto::Evm => jr_send(cx, "eth_sendRawTransaction", json!([format!("0x{hex}")])),
        Proto::Btc => jr_send(cx, "sendrawtransaction", json!([hex])),
        Proto::Esplora | Proto::Blockbook => {
            let url = if p == Proto::Esplora { format!("{}/tx", base(cx)) } else { format!("{}/api/v2/sendtx/", base(cx)) };
            let (code, b) = http(cx, "POST", &url, Some(hex.as_bytes()));
            if !(200..300).contains(&code) { fail(Some(cx), "http_error", json!({"http_status":code,"body":snippet(&b)})) }
            let t = String::from_utf8_lossy(&b).trim().to_string();
            serde_json::from_str::<Value>(&t).ok().and_then(|v| v["result"].as_str().map(String::from)).unwrap_or(t)
        }
        _ => unsupported(cx, p, "sendraw"),
    };
    let want = d.txid.clone().unwrap_or_default().trim_start_matches("0x").to_ascii_lowercase();
    let got = got.trim_start_matches("0x").to_ascii_lowercase();
    if got != want { fail(Some(cx), "error", json!({"error":"server_id_differs_from_local","txid":want})) }
    out(cx, json!({"tool":"rpc","status":"ok","txid":want}))
}
fn jr_send(cx: &Cx, m: &str, params: Value) -> String {
    let req = json!({"jsonrpc":"2.0","id":1,"method":m,"params":params}).to_string();
    let (code, b) = http(cx, "POST", &cx.url, Some(req.as_bytes()));
    let v: Value = serde_json::from_slice(&b).unwrap_or_else(|_| fail(Some(cx), "http_error", json!({"http_status":code,"body":snippet(&b)})));
    if !v["error"].is_null() { fail(Some(cx), "rpc_error", json!({"method":m,"error":v["error"]})) }
    v["result"].as_str().unwrap_or("").to_string()
}

/// Raw JSON-RPC: check every call, send the exact bytes, print the raw response.
fn passthrough(cx: &Cx, body: Vec<u8>) {
    let v: Value = serde_json::from_slice(&body).unwrap_or_else(|_| bad(Some(cx), "stdin is not JSON"));
    let calls: Vec<&Value> = match &v { Value::Array(a) if !a.is_empty() && a.len() <= 1000 => a.iter().collect(), Value::Object(_) => vec![&v], _ => bad(Some(cx), "expected a JSON-RPC object or a batch array of 1..1000") };
    let mut pinned = false;
    for c in &calls {
        let m = c["method"].as_str().unwrap_or_else(|| bad(Some(cx), "request without method"));
        let params = c.get("params").cloned().unwrap_or(Value::Null);
        match check_call_in(cx.proto, cx.allow_unlisted, m, &params, &cx.deny, cx.wallet_sign, false) {
            Err(r) => refused(cx, r),
            Ok(Pass::WalletSign) => {
                let (summary, cid) = wallet_sign_summary(m, &params).unwrap_or_else(|r| refused(cx, r));
                let got = endpoint_chain_id(cx);
                let want = cid.or(cx.chain_id).unwrap_or_else(|| refused(cx, Refusal { code: "wallet_sign_chain_unknown", detail: "request carries no chain id; give --chain-id N".into() }));
                if want != got || cx.chain_id.is_some_and(|c| c != got) { refused(cx, Refusal { code: "wallet_sign_chain_mismatch", detail: format!("request chain id {want}, endpoint eth_chainId {got}") }) }
                eprint!("{}  endpoint chain id: {got} (matches)\n", summary); pinned = true;
            }
            Ok(Pass::Plain) => {
                if m == "eth_getLogs" && params.get(0).is_some_and(|f| f.get("blockHash").is_none() && matches!(f.get("fromBlock").and_then(|b| b.as_str()), None | Some("earliest" | "0x0"))) {
                    eprintln!("{}", json!({"tool":"rpc","status":"warning","warning":"getlogs_full_range: public RPCs usually refuse full-range eth_getLogs; give fromBlock/toBlock"}));
                }
            }
        }
    }
    if !pinned && cx.chain_id.is_some() { pin_chain(cx) }
    let (code, b) = http(cx, "POST", &cx.url, Some(&body));
    let r: Value = serde_json::from_slice(&b).unwrap_or_else(|_| fail(Some(cx), "http_error", json!({"http_status":code,"error":"response is not JSON","body":snippet(&b)})));
    withhold_secrets(cx, &r);
    let errs: Vec<Value> = match &r { Value::Array(a) => a.iter().filter(|x| !x["error"].is_null()).map(|x| json!({"id":x["id"],"error":x["error"]})).collect(), o if !o["error"].is_null() => vec![json!({"id":o["id"],"error":o["error"]})], _ => vec![] };
    if matches!(r, Value::Object(_)) && !errs.is_empty() { fail(Some(cx), "rpc_error", json!({"error":errs[0]["error"]})) }
    emit(cx, &String::from_utf8_lossy(&b));
    if !errs.is_empty() { fail(Some(cx), "rpc_error", json!({"errors":errs})) }
    if !(200..300).contains(&code) { fail(Some(cx), "http_error", json!({"http_status":code})) }
}

fn rest_call(cx: &Cx, path: &str, body: Option<&str>) {
    let b: Option<Value> = body.map(|s| serde_json::from_str(s).unwrap_or_else(|_| bad(Some(cx), "BODY must be JSON")));
    if let Err(r) = check_call_in(cx.proto, cx.allow_unlisted, path, b.as_ref().unwrap_or(&Value::Null), &cx.deny, false, b.is_some()) { refused(cx, r) }
    let url = format!("{}/{}", base(cx), path.trim_start_matches('/'));
    let bs = b.map(|v| v.to_string());
    let (code, resp) = http(cx, if bs.is_some() { "POST" } else { "GET" }, &url, bs.as_deref().map(str::as_bytes));
    if let Ok(v) = serde_json::from_slice::<Value>(&resp) { withhold_secrets(cx, &v) }
    if !(200..300).contains(&code) { fail(Some(cx), "http_error", json!({"http_status":code,"body":snippet(&resp)})) }
    emit(cx, &String::from_utf8_lossy(&resp));
}

const SHORTCUTS: &[&str] = &["height", "chainid", "balance", "nonce", "account", "utxos", "tx", "receipt", "fee", "blockhash", "sendraw", "rawtx", "block", "blockinfo", "prevtxs"];
fn main() {
    let usage = header();
    blocktools_io::help(&usage);
    let mut pos = vec![]; let mut proto = None; let mut chain_id = None; let mut chain = "btc".to_string(); let mut auth: Option<String> = None;
    let mut deny = vec![]; let mut wallet_sign = false; let mut allow_unlisted = false; let mut timeout = 30;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut val = |k: &str| it.next().unwrap_or_else(|| bad(None, &format!("{k} needs a value")));
        match a.as_str() {
            "--protocol" => proto = Some(Proto::parse(&val("--protocol")).unwrap_or_else(|| bad(None, "unknown --protocol"))),
            "--chain-id" => chain_id = Some(val("--chain-id").parse::<u64>().unwrap_or_else(|_| bad(None, "--chain-id must be a number"))),
            "--chain" => chain = val("--chain"),
            "--auth-file" => { let f = val("--auth-file"); auth = Some(std::fs::read_to_string(&f).unwrap_or_else(|_| bad(None, "cannot read --auth-file"))) }
            "--auth-env" => { let n = val("--auth-env"); auth = Some(std::env::var(&n).unwrap_or_else(|_| bad(None, "--auth-env variable is not set"))) }
            "--policy" => { let f = val("--policy"); deny = parse_policy(&std::fs::read_to_string(&f).unwrap_or_else(|_| bad(None, "cannot read --policy"))).unwrap_or_else(|e| bad(None, &e)) }
            "--allow-wallet-sign" => wallet_sign = true,
            "--allow-unlisted" => allow_unlisted = true,
            "--timeout" => timeout = val("--timeout").parse::<u64>().ok().filter(|t| (1..=300).contains(t)).unwrap_or_else(|| bad(None, "--timeout 1..300")),
            "--user" | "--password" | "--pass" | "--auth" | "--token" | "--header" | "-H" | "-u" | "--bearer" | "--cookie" =>
                fail(None, "refused", json!({"code":"credential_on_command_line","detail":"use --auth-file FILE or --auth-env NAME"})),
            s if s.starts_with("--") => bad(None, "unknown flag"),
            _ => pos.push(a),
        }
    }
    let url_arg = pos.first().cloned().unwrap_or_else(|| bad(None, "usage: rpc URL [METHOD [PARAMS]]  (see --help)"));
    let url = if url_arg.contains("://") { url_arg.clone() } else if url_arg == "1" { "https://ethereum-rpc.publicnode.com".into() } else {
        blocktools_net::default_endpoint(&url_arg).map(String::from).unwrap_or_else(|| bad(None, "not a URL, and no default endpoint for that chain name / id"))
    };
    if url.split("://").nth(1).and_then(|r| r.split('/').next()).is_some_and(|auth| auth.contains('@')) {
        fail(None, "refused", json!({"code":"credential_on_command_line","detail":"credentials in the URL; use --auth-file FILE or --auth-env NAME"}))
    }
    if let Err(e) = blocktools_net::check_url(&url) { bad(None, &e) }
    let (headers, secrets) = match &auth { Some(a) => parse_auth(a).unwrap_or_else(|e| bad(None, e)), None => (vec![], vec![]) };
    let method = pos.get(1).cloned();
    let proto = proto.or_else(|| detect_url(&url)).or_else(|| method.as_deref().filter(|m| !SHORTCUTS.contains(m) && !m.starts_with('/')).and_then(detect_method));
    let cx = Cx { url, proto, headers, secrets, deny, wallet_sign, allow_unlisted, chain_id, chain, timeout };
    if pos.len() > 4 || (pos.len() == 4 && pos[1] != "rawtx") { bad(Some(&cx), "too many arguments") }
    match method.as_deref() {
        None => {
            let mut b = Vec::new();
            if std::io::stdin().take((4 << 20) + 1).read_to_end(&mut b).is_err() || b.len() > 4 << 20 { bad(Some(&cx), "stdin over 4 MiB") }
            passthrough(&cx, b)
        }
        Some("sendraw") => sendraw(&cx),
        Some(m) if SHORTCUTS.contains(&m) => shortcut(&cx, m, pos.get(2).map(String::as_str), pos.get(3).map(String::as_str)),
        Some(m) if m.starts_with('/') => rest_call(&cx, m, pos.get(2).map(String::as_str)),
        Some(m) => {
            let params: Value = match pos.get(2) { Some(p) => serde_json::from_str(p).unwrap_or_else(|_| bad(Some(&cx), "PARAMS must be JSON")), None => json!([]) };
            // JSON-RPC 2.0: params is one structured value. `getblockhash 1` would send params:1, which nodes reject.
            if !(params.is_array() || params.is_object()) { bad(Some(&cx), "PARAMS must be one JSON array (or object) argument, e.g. '[1]'") }
            let body = json!({"jsonrpc":"2.0","id":1,"method":m,"params":params}).to_string().into_bytes();
            passthrough(&cx, body)
        }
    }
}
/// --help: synopsis lines and the option block of the //! header (gen-man builds man/man1/rpc.1 from this).
fn header() -> String {
    let doc: Vec<&str> = include_str!("main.rs").lines().take_while(|l| l.starts_with("//!")).map(|l| l.trim_start_matches("//!")).collect();
    let syn = doc.iter().map(|l| l.trim()).filter(|l| l.starts_with("rpc URL") || l.starts_with("... | rpc"));
    let opts = doc.iter().skip_while(|l| l.trim() != "Options:").skip(1).take_while(|l| !l.trim_start().starts_with("stdout:")).map(|l| l.strip_prefix("   ").unwrap_or(l));
    syn.map(String::from).chain(opts.map(String::from)).collect::<Vec<_>>().join("\n")
}
