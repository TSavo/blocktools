//! contract-call: read EVM contract state with eth_call and decode the return data (HOST-SIDE, network)
//!   contract-call URL ADDRESS SIGNATURE [ARG...]   one call; SIGNATURE with `returns (...)` decodes the result
//!   contract-call URL ADDRESS --abi FILE --read    one-shot state read: every view/pure function with no inputs
//!   ... | contract-call URL                        JSON lines {"to","sig","args":[...],"block"?,"from"?} on stdin
//! Any EVM-style chain: URL is the endpoint (or a chain name from the shared endpoint table); the chain id is read
//! from the endpoint (eth_chainId) and printed on every line; --chain-id N refuses any other chain.
//! ARGs are ABI values: decimal or 0x integers, 0x addresses and bytes, true/false, JSON arrays for arrays/tuples.
//! A revert is decoded (Error(string), Panic(uint256), and custom errors from --abi or --error) and exits 1.
//! Options:
//!   --block TAG           latest (default), pending, safe, finalized, earliest, a block number, or a 32-byte block hash
//!   --from ADDR           msg.sender for the call
//!   --abi FILE            ABI JSON (array or {"abi": [...]}) or one signature per line: functions for --read, errors for reverts
//!   --error SIGNATURE     a custom error signature to decode reverts with (repeatable)
//!   --read                with --abi: call every function that takes no inputs and returns something (view/pure when the ABI says)
//!   --chain-id N          refuse unless the endpoint's eth_chainId is N (chain_id_mismatch); nothing else is sent
//!   --auth-file FILE      credentials, same formats as rpc --auth-file; never printed
//!   --auth-env NAME       same, from environment variable NAME
//!   --policy FILE         rpc policy file: adds refusals (deny eth_call and nothing is sent)
//!   --timeout SECONDS     per request, 1..300 (default 30)
//! stdout: one JSON line per call {"tool","status":"ok","chain_id","to","block","function","selector","calldata",
//! "returndata","returns","outputs":[{name,type,value}]}; no returns list: returndata only.
//! stderr: {"tool":"contract-call","status":...}: reverted (with the decoded revert), empty_return (no code at the address
//! or no such function), bad_return, refused (nothing sent), rpc_error, http_error. Exit 0 ok, 2 bad input, 1 everything else.
//! Only eth_chainId and eth_call are sent, each through rpc's checks (read allowlist, deny-list, policy, secret fields);
//! responses carrying key material are withheld; credentials are redacted from all output. Same bounds as rpc: no redirects,
//! 8 MiB response cap, https only (plain http for localhost). No signing, no broadcast, no trace (state overrides and debug_traceCall: contract-trace).
use blocktools_evm::{abi, api, sig::{Kind, Sig}, checksum_address, hex, parse_address, unhex};
use rpc::{check_call_in, parse_auth, parse_policy, redact, response_secret, Proto};
use serde_json::{json, Value};
use std::io::Read;

struct Cx { url: String, headers: Vec<(String, String)>, secrets: Vec<String>, deny: Vec<String>, timeout: u64 }

fn fail(cx: Option<&Cx>, status: &str, extra: Value) -> ! {
    let mut v = json!({"tool":"contract-call","status":status});
    v.as_object_mut().unwrap().extend(extra.as_object().cloned().unwrap_or_default());
    let s = v.to_string();
    eprintln!("{}", cx.map_or(s.clone(), |c| redact(&s, &c.secrets)));
    std::process::exit(blocktools_io::exit_code(status))
}
fn bad(cx: Option<&Cx>, e: &str) -> ! { fail(cx, "bad_input", json!({"error":e})) }

/// One checked JSON-RPC call: Ok(result) or Err(error object) when the node answered with an error.
fn jr(cx: &Cx, method: &str, params: Value) -> Result<Value, Value> {
    if let Err(r) = check_call_in(Some(Proto::Evm), false, method, &params, &cx.deny, false, false) { fail(Some(cx), "refused", json!({"code":r.code,"detail":r.detail})) }
    let req = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let (code, b) = blocktools_net::send("POST", &cx.url, Some(req.as_bytes()), &cx.headers, cx.timeout).unwrap_or_else(|e| fail(Some(cx), "http_error", json!({"error":e})));
    let v: Value = serde_json::from_slice(&b).unwrap_or_else(|_| fail(Some(cx), "http_error", json!({"http_status":code,"error":"response is not JSON"})));
    if let Some(w) = response_secret(&v, 0) { fail(Some(cx), "refused", json!({"code":"response_contains_secret","detail":format!("{w}; nothing printed")})) }
    if !v["error"].is_null() { return Err(v["error"].clone()) }
    v.get("result").cloned().ok_or_else(|| json!("no result"))
}

pub fn block_param(b: &str) -> Result<Value, String> {
    let b = b.trim();
    if ["latest", "pending", "safe", "finalized", "earliest"].contains(&b) { return Ok(json!(b)) }
    if !b.is_empty() && b.len() <= 20 && b.bytes().all(|c| c.is_ascii_digit()) { return Ok(json!(format!("0x{:x}", b.parse::<u64>().map_err(|_| "bad_block")?))) }
    if let Some(h) = b.strip_prefix("0x") {
        if h.len() == 64 && h.bytes().all(|c| c.is_ascii_hexdigit()) { return Ok(json!({"blockHash": b.to_ascii_lowercase()})) }
        if !h.is_empty() && h.len() <= 16 && h.bytes().all(|c| c.is_ascii_hexdigit()) { return Ok(json!(format!("0x{:x}", u64::from_str_radix(h, 16).unwrap()))) }
    }
    Err("bad_block: latest|pending|safe|finalized|earliest, a number or a 32-byte hash".into())
}

struct Call { to: [u8; 20], sig: Sig, args: Vec<Value>, block: Value, from: Option<[u8; 20]> }

fn do_call(cx: &Cx, chain_id: u64, c: &Call, errors: &[Sig]) -> i32 {
    let mut data = c.sig.selector().to_vec();
    data.extend(abi::encode(&c.sig.inputs, &c.args).unwrap_or_else(|e| bad(Some(cx), &e)));
    let mut tx = json!({"to": checksum_address(&c.to), "data": hex(&data)});
    if let Some(f) = &c.from { tx["from"] = json!(checksum_address(f)) }
    let mut o = json!({"tool":"contract-call","status":"ok","chain_id":chain_id,"to":checksum_address(&c.to),"block":c.block,
        "function":c.sig.canonical(),"selector":hex(&c.sig.selector()),"calldata":hex(&data)});
    match jr(cx, "eth_call", json!([tx, c.block])) {
        Err(e) => {
            let rev = e.get("data").and_then(Value::as_str).and_then(|d| unhex(d).ok());
            let decoded = rev.as_ref().map(|d| if d.is_empty() { json!({"status":"empty_revert"}) } else {
                api::decode_selector_data(d, errors).unwrap_or_else(|er| json!({"status":"bad_revert_data","error":er})) });
            o["status"] = json!(if rev.is_some() { "reverted" } else { "rpc_error" });
            o["error"] = e; if let Some(d) = decoded { o["revert"] = d }
            eprintln!("{}", redact(&o.to_string(), &cx.secrets)); 1
        }
        Ok(r) => {
            let rd = r.as_str().and_then(|s| unhex(s).ok()).unwrap_or_else(|| fail(Some(cx), "rpc_error", json!({"error":"eth_call result is not hex"})));
            o["returndata"] = json!(hex(&rd));
            if c.sig.outputs.is_empty() { o["returns"] = Value::Null; blocktools_io::outln!("{}", redact(&o.to_string(), &cx.secrets)); return 0 }
            o["returns"] = json!(format!("({})", c.sig.outputs.iter().map(|p| p.ty.canon()).collect::<Vec<_>>().join(",")));
            if rd.is_empty() { o["status"] = json!("empty_return"); o["hint"] = json!("no contract code at this address on this chain/block, or no such function (fallback returned nothing)"); eprintln!("{}", redact(&o.to_string(), &cx.secrets)); return 1 }
            match abi::decode(&c.sig.outputs, &rd) {
                Ok(v) => { o["outputs"] = abi::labelled(&c.sig.outputs, v); blocktools_io::outln!("{}", redact(&o.to_string(), &cx.secrets)); 0 }
                Err(e) => { o["status"] = json!("bad_return"); o["error"] = json!(e); eprintln!("{}", redact(&o.to_string(), &cx.secrets)); 1 }
            }
        }
    }
}

/// Zero-input functions with outputs; when the ABI JSON says stateMutability, only view/pure (or constant).
fn getters(text: &str) -> Result<Vec<Sig>, String> {
    let t = text.trim_start();
    let all = api::load_sigs(t)?;
    let mut ok_names: Option<Vec<String>> = None;
    if t.starts_with('[') || t.starts_with('{') {
        let v: Value = serde_json::from_str(t).map_err(|_| "bad_abi_json")?;
        let arr = v.as_array().cloned().or_else(|| v.get("abi").and_then(Value::as_array).cloned()).unwrap_or_default();
        ok_names = Some(arr.iter().filter(|i| i["type"] == "function" && (matches!(i["stateMutability"].as_str(), Some("view" | "pure")) || i["constant"] == true))
            .filter_map(|i| i["name"].as_str().map(String::from)).collect());
    }
    Ok(all.into_iter().filter(|s| s.kind == Kind::Function && s.inputs.is_empty() && !s.outputs.is_empty() && ok_names.as_ref().is_none_or(|n| n.contains(&s.name))).collect())
}

fn main() {
    let doc: Vec<&str> = include_str!("main.rs").lines().take_while(|l| l.starts_with("//!")).map(|l| l.trim_start_matches("//!")).collect();
    let syn = doc.iter().map(|l| l.trim()).filter(|l| l.starts_with("contract-call URL") || l.starts_with("... | contract-call"));
    let opts = doc.iter().skip_while(|l| l.trim() != "Options:").skip(1).take_while(|l| !l.trim_start().starts_with("stdout:")).map(|l| l.strip_prefix("   ").unwrap_or(l));
    blocktools_io::help(&syn.map(String::from).chain(opts.map(String::from)).collect::<Vec<_>>().join("\n"));
    let mut pos = vec![]; let (mut block, mut from, mut abi_text, mut errs, mut read, mut chain_id, mut auth, mut deny, mut timeout) = ("latest".to_string(), None, None, vec![], false, None, None, vec![], 30u64);
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut val = |k: &str| it.next().unwrap_or_else(|| bad(None, &format!("{k} needs a value")));
        match a.as_str() {
            "--block" => block = val("--block"),
            "--from" => from = Some(parse_address(&val("--from")).unwrap_or_else(|e| bad(None, &e))),
            "--abi" => abi_text = Some(std::fs::read_to_string(val("--abi")).unwrap_or_else(|_| bad(None, "cannot read --abi"))),
            "--error" => errs.push(Sig::parse_as(&val("--error"), Kind::Error).unwrap_or_else(|e| bad(None, &e))),
            "--read" => read = true,
            "--chain-id" => chain_id = Some(val("--chain-id").parse::<u64>().unwrap_or_else(|_| bad(None, "--chain-id must be a number"))),
            "--auth-file" => auth = Some(std::fs::read_to_string(val("--auth-file")).unwrap_or_else(|_| bad(None, "cannot read --auth-file"))),
            "--auth-env" => { let n = val("--auth-env"); auth = Some(std::env::var(&n).unwrap_or_else(|_| bad(None, "--auth-env variable is not set"))) }
            "--policy" => deny = parse_policy(&std::fs::read_to_string(val("--policy")).unwrap_or_else(|_| bad(None, "cannot read --policy"))).unwrap_or_else(|e| bad(None, &e)),
            "--timeout" => timeout = val("--timeout").parse::<u64>().ok().filter(|t| (1..=300).contains(t)).unwrap_or_else(|| bad(None, "--timeout 1..300")),
            "--user" | "--password" | "--pass" | "--auth" | "--token" | "--header" | "-H" | "-u" | "--bearer" | "--cookie" =>
                fail(None, "refused", json!({"code":"credential_on_command_line","detail":"use --auth-file FILE or --auth-env NAME"})),
            s if s.starts_with("--") && s.len() > 2 && !s[2..].starts_with(|c: char| c.is_ascii_digit()) => bad(None, "unknown flag"),
            _ => pos.push(a),
        }
    }
    let url_arg = pos.first().cloned().unwrap_or_else(|| bad(None, "usage: contract-call URL ADDRESS SIGNATURE [ARG...]  (see --help)"));
    let url = if url_arg.contains("://") { url_arg } else { blocktools_net::default_endpoint(&url_arg).map(String::from).unwrap_or_else(|| bad(None, "not a URL, and no default endpoint for that chain name")) };
    if url.split("://").nth(1).and_then(|r| r.split('/').next()).is_some_and(|h| h.contains('@')) { fail(None, "refused", json!({"code":"credential_on_command_line","detail":"credentials in the URL; use --auth-file FILE or --auth-env NAME"})) }
    if let Err(e) = blocktools_net::check_url(&url) { bad(None, &e) }
    let (headers, secrets) = match &auth { Some(a) => parse_auth(a).unwrap_or_else(|e| bad(None, e)), None => (vec![], vec![]) };
    let cx = Cx { url, headers, secrets, deny, timeout };
    let blk = block_param(&block).unwrap_or_else(|e| bad(Some(&cx), &e));
    let mut errors = errs;
    if let Some(t) = &abi_text { errors.extend(api::load_sigs(t).unwrap_or_else(|e| bad(Some(&cx), &e)).into_iter().filter(|s| s.kind == Kind::Error)) }
    // build every call before anything is sent: bad input is decided locally
    let mut calls = vec![];
    if pos.len() == 1 {
        if read { bad(Some(&cx), "--read needs ADDRESS") }
        let mut s = String::new();
        if std::io::stdin().take((4 << 20) + 1).read_to_string(&mut s).is_err() || s.len() > 4 << 20 { bad(Some(&cx), "stdin over 4 MiB") }
        for l in s.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let v: Value = serde_json::from_str(l).unwrap_or_else(|_| bad(Some(&cx), "stdin: one JSON object per line"));
            let to = parse_address(v["to"].as_str().unwrap_or_else(|| bad(Some(&cx), "line needs \"to\""))).unwrap_or_else(|e| bad(Some(&cx), &e));
            let sig = Sig::parse(v["sig"].as_str().unwrap_or_else(|| bad(Some(&cx), "line needs \"sig\""))).unwrap_or_else(|e| bad(Some(&cx), &e));
            if sig.kind != Kind::Function { bad(Some(&cx), "sig must be a function") }
            let args = v.get("args").map(|a| a.as_array().cloned().unwrap_or_else(|| bad(Some(&cx), "\"args\" must be an array"))).unwrap_or_default();
            let block = v.get("block").map(|b| block_param(&b.as_str().map(String::from).unwrap_or(b.to_string())).unwrap_or_else(|e| bad(Some(&cx), &e))).unwrap_or(blk.clone());
            let from = v.get("from").and_then(Value::as_str).map(|f| parse_address(f).unwrap_or_else(|e| bad(Some(&cx), &e))).or(from);
            calls.push(Call { to, sig, args, block, from });
        }
        if calls.is_empty() { bad(Some(&cx), "empty stdin") }
        if calls.len() > 1000 { bad(Some(&cx), "more than 1000 calls") }
    } else {
        let to = parse_address(&pos[1]).unwrap_or_else(|e| bad(Some(&cx), &e));
        if read {
            if pos.len() > 2 { bad(Some(&cx), "--read takes no SIGNATURE") }
            let gs = getters(abi_text.as_deref().unwrap_or_else(|| bad(Some(&cx), "--read needs --abi FILE"))).unwrap_or_else(|e| bad(Some(&cx), &e));
            if gs.is_empty() { bad(Some(&cx), "the ABI has no view/pure function without inputs") }
            for sig in gs { calls.push(Call { to, sig, args: vec![], block: blk.clone(), from }) }
        } else {
            let s = pos.get(2).unwrap_or_else(|| bad(Some(&cx), "SIGNATURE needed (or --abi FILE --read)"));
            let sig = Sig::parse(s).unwrap_or_else(|e| bad(Some(&cx), &e));
            if sig.kind != Kind::Function { bad(Some(&cx), "SIGNATURE must be a function") }
            let args: Vec<Value> = pos[3..].iter().map(|a| json!(a)).collect();
            if args.len() != sig.inputs.len() { bad(Some(&cx), &format!("{} takes {} args, got {}", sig.canonical(), sig.inputs.len(), args.len())) }
            calls.push(Call { to, sig, args, block: blk, from });
        }
    }
    for c in &calls { let mut d = vec![]; if let Err(e) = abi::encode(&c.sig.inputs, &c.args).map(|x| d = x) { bad(Some(&cx), &format!("{}: {e}", c.sig.canonical())) } }
    let got = jr(&cx, "eth_chainId", json!([])).unwrap_or_else(|e| fail(Some(&cx), "rpc_error", json!({"method":"eth_chainId","error":e})));
    let got = blocktools_net::qty(&got).ok().and_then(|x| u64::try_from(x).ok()).unwrap_or_else(|| fail(Some(&cx), "refused", json!({"code":"protocol_unknown","detail":"endpoint did not answer eth_chainId with a chain id; not an EVM endpoint"})));
    if let Some(w) = chain_id { if w != got { fail(Some(&cx), "refused", json!({"code":"chain_id_mismatch","detail":format!("endpoint eth_chainId {got}, --chain-id {w}")})) } }
    let mut rc = 0;
    for c in &calls { rc = rc.max(do_call(&cx, got, c, &errors)) }
    std::process::exit(rc)
}

#[cfg(test)]
mod t {
    #[test]
    fn blocks() {
        assert_eq!(super::block_param("latest").unwrap(), "latest");
        assert_eq!(super::block_param("16").unwrap(), "0x10");
        assert_eq!(super::block_param("0x0010").unwrap(), "0x10");
        assert!(super::block_param(&format!("0x{}", "ab".repeat(32))).unwrap().get("blockHash").is_some());
        assert!(super::block_param("lates").is_err());
    }
}
