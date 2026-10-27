//! contract-trace: simulate an EVM call with state overrides, or trace it with debug_traceCall (HOST-SIDE, network)
//!   contract-trace URL ADDRESS SIGNATURE [ARG...]   trace one call; calldata from the signature, as contract-call
//!   contract-trace URL ADDRESS --data HEX|@FILE     trace raw calldata (e.g. the data field of an unsigned tx)
//! Any EVM-style chain: URL is the endpoint (or a chain name from the shared endpoint table); the chain id is read
//! from the endpoint (eth_chainId) and printed on every line; --chain-id N refuses any other chain.
//! debug_traceCall is not in rpc's read allowlist: it is sent only with --allow-unlisted (refused otherwise, nothing
//! sent). --call-only sends eth_call with the state overrides instead, which the allowlist admits.
//! Options:
//!   --block TAG           latest (default), pending, safe, finalized, earliest, a block number, or a 32-byte block hash
//!   --from ADDR           msg.sender for the call
//!   --value WEI           call value (decimal or 0x)
//!   --gas N               gas limit for the simulated call
//!   --state FILE          state overrides: {"0xADDR": {"balance","nonce","code","state"|"stateDiff"}}; checked locally
//!   --abi FILE            ABI JSON or signatures: frames whose selector matches are decoded ("call" field)
//!   --tracer NAME         callTracer (default: one JSON line per call frame), prestateTracer, or any tracer name the node
//!                         knows (one line with the raw result); "struct" sends no tracer (the node's opcode logger)
//!   --tracer-config JSON  tracerConfig object passed through (e.g. {"onlyTopCall":true})
//!   --call-only           eth_call with the overrides; no trace (no --allow-unlisted needed)
//!   --allow-unlisted      send debug_traceCall (not in rpc's read allowlist)
//!   --chain-id N          refuse unless the endpoint's eth_chainId is N (chain_id_mismatch); nothing else is sent
//!   --auth-file FILE      credentials, same formats as rpc --auth-file; never printed
//!   --auth-env NAME       same, from environment variable NAME
//!   --policy FILE         rpc policy file: adds refusals
//!   --timeout SECONDS     per request, 1..300 (default 30)
//! stdout: callTracer: one JSON line per frame {"tool","status":"ok","chain_id","frame","depth","type","from","to","value",
//! "gas","gasUsed","input","output","error"?,"revertReason"?,"call"?}, depth-first; other tracers: one line {"tool","status",
//! "chain_id","tracer","result"}; --call-only: one line {"tool","status","chain_id","to","calldata","returndata"}.
//! A reverted top frame still prints its frames and exits 1 with {"status":"reverted"} on stderr.
//! stderr: {"tool":"contract-trace","status":...}: reverted, refused (nothing sent), rpc_error, http_error, bad_input.
//! Exit 0 ok, 2 bad input, 1 everything else. Same bounds as rpc: no redirects, 8 MiB response cap, https only (plain
//! http for localhost); responses carrying key material are withheld; credentials are redacted from all output.
//! No signing, no broadcast. Not measured against a live node: tests use a 127.0.0.1 mock.
use blocktools_evm::{abi, api, sig::{Kind, Sig}, checksum_address, hex, parse_address, unhex};
use rpc::{check_call_in, parse_auth, parse_policy, redact, response_secret, Proto};
use serde_json::{json, Map, Value};

struct Cx { url: String, headers: Vec<(String, String)>, secrets: Vec<String>, deny: Vec<String>, timeout: u64, unlisted: bool }

fn fail(cx: Option<&Cx>, status: &str, extra: Value) -> ! {
    let mut v = json!({"tool":"contract-trace","status":status});
    v.as_object_mut().unwrap().extend(extra.as_object().cloned().unwrap_or_default());
    let s = v.to_string();
    eprintln!("{}", cx.map_or(s.clone(), |c| redact(&s, &c.secrets)));
    std::process::exit(blocktools_io::exit_code(status))
}
fn bad(cx: Option<&Cx>, e: &str) -> ! { fail(cx, "bad_input", json!({"error":e})) }

fn jr(cx: &Cx, method: &str, params: Value) -> Result<Value, Value> {
    if let Err(r) = check_call_in(Some(Proto::Evm), cx.unlisted, method, &params, &cx.deny, false, false) {
        let hint = if method == "debug_traceCall" && !cx.unlisted { " (or --call-only for eth_call with overrides)" } else { "" };
        fail(Some(cx), "refused", json!({"code":r.code,"detail":format!("{}{hint}", r.detail)}))
    }
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

/// A decimal or 0x quantity as a canonical 0x hex quantity (up to 256 bits).
pub fn qty(s: &str) -> Result<String, String> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x") {
        let h = h.trim_start_matches('0');
        if h.len() > 64 || !h.bytes().all(|c| c.is_ascii_hexdigit()) || s.len() == 2 { return Err(format!("bad quantity {s}")) }
        return Ok(format!("0x{}", if h.is_empty() { "0" } else { h }).to_ascii_lowercase())
    }
    if s.is_empty() || s.len() > 78 || !s.bytes().all(|c| c.is_ascii_digit()) { return Err(format!("bad quantity {s}")) }
    // decimal -> hex by repeated division on a digit vector
    let mut d: Vec<u32> = s.bytes().map(|c| (c - b'0') as u32).collect(); let mut out = vec![];
    while d.iter().any(|&x| x != 0) {
        let mut r = 0; let mut q = vec![];
        for x in &d { let c = r * 10 + x; q.push(c / 16); r = c % 16 }
        out.push(std::char::from_digit(r, 16).unwrap());
        d = q.into_iter().skip_while(|&x| x == 0).collect();
    }
    if out.len() > 64 { return Err(format!("quantity over 256 bits: {s}")) }
    Ok(format!("0x{}", if out.is_empty() { "0".into() } else { out.iter().rev().collect::<String>() }))
}

fn word(s: &str, what: &str) -> Result<String, String> {
    let h = s.strip_prefix("0x").ok_or(format!("{what} must be 0x-prefixed 32-byte hex"))?;
    if h.len() != 64 || !h.bytes().all(|c| c.is_ascii_hexdigit()) { return Err(format!("{what} must be 32 bytes of hex: {s}")) }
    Ok(s.to_ascii_lowercase())
}

/// Check a state-override object locally; returns the normalized object to send.
pub fn check_state(v: &Value) -> Result<Value, String> {
    let m = v.as_object().ok_or("--state: a JSON object keyed by address")?;
    if m.len() > 1000 { return Err("--state: more than 1000 accounts".into()) }
    let mut out = Map::new();
    for (a, o) in m {
        let addr = parse_address(a).map_err(|e| format!("--state key {a}: {e}"))?;
        let o = o.as_object().ok_or(format!("--state {a}: an object"))?;
        let mut n = Map::new();
        for (k, x) in o {
            let s = |x: &Value| x.as_str().map(String::from).or_else(|| x.as_u64().map(|u| u.to_string())).ok_or(format!("--state {a}.{k}: a string"));
            match k.as_str() {
                "balance" | "nonce" => { n.insert(k.clone(), json!(qty(&s(x)?)?)); }
                "code" => { let c = s(x)?; let b = unhex(&c).map_err(|_| format!("--state {a}.code: hex"))?; if b.len() > 49152 { return Err(format!("--state {a}.code over 48 KiB")) } n.insert(k.clone(), json!(hex(&b))); }
                "state" | "stateDiff" => {
                    let slots = x.as_object().ok_or(format!("--state {a}.{k}: an object of slot -> value"))?;
                    let mut sm = Map::new();
                    for (sk, sv) in slots { sm.insert(word(sk, "slot")?, json!(word(sv.as_str().ok_or("slot value: a string")?, "slot value")?)); }
                    n.insert(k.clone(), Value::Object(sm));
                }
                _ => return Err(format!("--state {a}: unknown field {k} (balance, nonce, code, state, stateDiff)")),
            }
        }
        if n.contains_key("state") && n.contains_key("stateDiff") { return Err(format!("--state {a}: state and stateDiff are exclusive")) }
        out.insert(checksum_address(&addr), Value::Object(n));
    }
    Ok(Value::Object(out))
}

/// Depth-first flattening of a callTracer result into frames (without their nested "calls").
pub fn frames(root: &Value) -> Vec<(usize, Value)> {
    let mut out = vec![]; let mut st = vec![(0usize, root)];
    while let Some((d, f)) = st.pop() {
        if out.len() >= 100_000 { break }
        let mut o = f.as_object().cloned().unwrap_or_default();
        o.remove("calls");
        out.push((d, Value::Object(o)));
        if let Some(k) = f.get("calls").and_then(Value::as_array) { for c in k.iter().rev() { st.push((d + 1, c)) } }
    }
    out
}

fn read_data(s: &str) -> Vec<u8> {
    let t = if let Some(p) = s.strip_prefix('@') { std::fs::read_to_string(p).unwrap_or_else(|_| bad(None, "cannot read --data file")) } else { s.to_string() };
    unhex(t.trim()).unwrap_or_else(|_| bad(None, "--data: hex"))
}

fn main() {
    let doc: Vec<&str> = include_str!("main.rs").lines().take_while(|l| l.starts_with("//!")).map(|l| l.trim_start_matches("//!")).collect();
    let syn = doc.iter().map(|l| l.trim()).filter(|l| l.starts_with("contract-trace URL"));
    let opts = doc.iter().skip_while(|l| l.trim() != "Options:").skip(1).take_while(|l| !l.trim_start().starts_with("stdout:")).map(|l| l.strip_prefix("   ").unwrap_or(l));
    blocktools_io::help(&syn.map(String::from).chain(opts.map(String::from)).collect::<Vec<_>>().join("\n"));
    let mut pos = vec![];
    let (mut block, mut from, mut value, mut gas, mut state, mut abi_text, mut tracer, mut tcfg, mut call_only, mut unlisted, mut chain_id, mut auth, mut deny, mut timeout, mut data)
        = ("latest".to_string(), None, None, None, None, None, "callTracer".to_string(), None, false, false, None, None, vec![], 30u64, None);
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut val = |k: &str| it.next().unwrap_or_else(|| bad(None, &format!("{k} needs a value")));
        match a.as_str() {
            "--block" => block = val("--block"),
            "--from" => from = Some(parse_address(&val("--from")).unwrap_or_else(|e| bad(None, &e))),
            "--value" => value = Some(qty(&val("--value")).unwrap_or_else(|e| bad(None, &e))),
            "--gas" => gas = Some(qty(&val("--gas")).unwrap_or_else(|e| bad(None, &e))),
            "--state" => { let t = std::fs::read_to_string(val("--state")).unwrap_or_else(|_| bad(None, "cannot read --state"));
                let v: Value = serde_json::from_str(&t).unwrap_or_else(|_| bad(None, "--state: not JSON"));
                state = Some(check_state(&v).unwrap_or_else(|e| bad(None, &e))) }
            "--abi" => abi_text = Some(std::fs::read_to_string(val("--abi")).unwrap_or_else(|_| bad(None, "cannot read --abi"))),
            "--tracer" => { tracer = val("--tracer"); if tracer.is_empty() || tracer.len() > 64 || !tracer.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') { bad(None, "--tracer: a tracer name (letters, digits, _)") } }
            "--tracer-config" => { let v: Value = serde_json::from_str(&val("--tracer-config")).unwrap_or_else(|_| bad(None, "--tracer-config: JSON"));
                if !v.is_object() { bad(None, "--tracer-config: a JSON object") } tcfg = Some(v) }
            "--data" => data = Some(read_data(&val("--data"))),
            "--call-only" => call_only = true,
            "--allow-unlisted" => unlisted = true,
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
    if call_only && (tcfg.is_some() || tracer != "callTracer") { bad(None, "--call-only takes no --tracer/--tracer-config") }
    let url_arg = pos.first().cloned().unwrap_or_else(|| bad(None, "usage: contract-trace URL ADDRESS SIGNATURE [ARG...] | --data HEX  (see --help)"));
    let url = if url_arg.contains("://") { url_arg } else { blocktools_net::default_endpoint(&url_arg).map(String::from).unwrap_or_else(|| bad(None, "not a URL, and no default endpoint for that chain name")) };
    if url.split("://").nth(1).and_then(|r| r.split('/').next()).is_some_and(|h| h.contains('@')) { fail(None, "refused", json!({"code":"credential_on_command_line","detail":"credentials in the URL; use --auth-file FILE or --auth-env NAME"})) }
    if let Err(e) = blocktools_net::check_url(&url) { bad(None, &e) }
    let (headers, secrets) = match &auth { Some(a) => parse_auth(a).unwrap_or_else(|e| bad(None, e)), None => (vec![], vec![]) };
    let cx = Cx { url, headers, secrets, deny, timeout, unlisted };
    let blk = block_param(&block).unwrap_or_else(|e| bad(Some(&cx), &e));
    let to = parse_address(pos.get(1).unwrap_or_else(|| bad(Some(&cx), "ADDRESS needed"))).unwrap_or_else(|e| bad(Some(&cx), &e));
    let mut top_fn = None;
    let calldata = match (&data, pos.get(2)) {
        (Some(_), Some(_)) => bad(Some(&cx), "SIGNATURE and --data are exclusive"),
        (Some(d), None) => d.clone(),
        (None, None) => bad(Some(&cx), "SIGNATURE [ARG...] or --data HEX needed"),
        (None, Some(s)) => {
            let sig = Sig::parse(s).unwrap_or_else(|e| bad(Some(&cx), &e));
            if sig.kind != Kind::Function { bad(Some(&cx), "SIGNATURE must be a function") }
            let args: Vec<Value> = pos[3..].iter().map(|a| json!(a)).collect();
            if args.len() != sig.inputs.len() { bad(Some(&cx), &format!("{} takes {} args, got {}", sig.canonical(), sig.inputs.len(), args.len())) }
            let mut d = sig.selector().to_vec(); d.extend(abi::encode(&sig.inputs, &args).unwrap_or_else(|e| bad(Some(&cx), &e)));
            top_fn = Some(sig.canonical()); d
        }
    };
    if data.is_some() && pos.len() > 2 { bad(Some(&cx), "extra arguments") }
    let sigs: Vec<Sig> = abi_text.as_deref().map(|t| api::load_sigs(t).unwrap_or_else(|e| bad(Some(&cx), &e)).into_iter().filter(|s| s.kind == Kind::Function).collect()).unwrap_or_default();
    let mut tx = json!({"to": checksum_address(&to), "data": hex(&calldata)});
    if let Some(f) = &from { tx["from"] = json!(checksum_address(f)) }
    if let Some(v) = &value { tx["value"] = json!(v) }
    if let Some(g) = &gas { tx["gas"] = json!(g) }
    let (method, params) = if call_only {
        let mut p = vec![tx, blk.clone()]; if let Some(s) = &state { p.push(s.clone()) } ("eth_call", Value::Array(p))
    } else {
        let mut cfg = Map::new();
        if tracer != "struct" { cfg.insert("tracer".into(), json!(tracer)); }
        if let Some(c) = &tcfg { cfg.insert("tracerConfig".into(), c.clone()); }
        if let Some(s) = &state { cfg.insert("stateOverrides".into(), s.clone()); }
        ("debug_traceCall", json!([tx, blk, Value::Object(cfg)]))
    };
    // refuse before anything is sent when the method is not admitted
    if let Err(r) = check_call_in(Some(Proto::Evm), cx.unlisted, method, &params, &cx.deny, false, false) {
        let hint = if method == "debug_traceCall" && !cx.unlisted { " (or --call-only for eth_call with overrides)" } else { "" };
        fail(Some(&cx), "refused", json!({"code":r.code,"detail":format!("{}{hint}", r.detail)}))
    }
    let got = jr(&cx, "eth_chainId", json!([])).unwrap_or_else(|e| fail(Some(&cx), "rpc_error", json!({"method":"eth_chainId","error":e})));
    let cid = blocktools_net::qty(&got).ok().and_then(|x| u64::try_from(x).ok()).unwrap_or_else(|| fail(Some(&cx), "refused", json!({"code":"protocol_unknown","detail":"endpoint did not answer eth_chainId with a chain id; not an EVM endpoint"})));
    if let Some(w) = chain_id { if w != cid { fail(Some(&cx), "refused", json!({"code":"chain_id_mismatch","detail":format!("endpoint eth_chainId {cid}, --chain-id {w}")})) } }
    let out = |v: &Value| blocktools_io::outln!("{}", redact(&v.to_string(), &cx.secrets));
    let r = match jr(&cx, method, params) {
        Ok(r) => r,
        Err(e) => {
            let rev = call_only.then(|| e.get("data").and_then(Value::as_str).and_then(|d| unhex(d).ok())).flatten();
            let mut o = json!({"chain_id":cid,"method":method,"error":e});
            if let Some(d) = rev { o["revert"] = if d.is_empty() { json!({"status":"empty_revert"}) } else { api::decode_selector_data(&d, &[]).unwrap_or_else(|er| json!({"status":"bad_revert_data","error":er})) } }
            fail(Some(&cx), if call_only && o.get("revert").is_some() { "reverted" } else { "rpc_error" }, o)
        }
    };
    if call_only {
        let rd = r.as_str().and_then(|s| unhex(s).ok()).unwrap_or_else(|| fail(Some(&cx), "rpc_error", json!({"error":"eth_call result is not hex"})));
        let mut o = json!({"tool":"contract-trace","status":"ok","chain_id":cid,"to":checksum_address(&to),"block":blk,"calldata":hex(&calldata),"returndata":hex(&rd),"state_overrides":state.as_ref().map_or(0, |s| s.as_object().unwrap().len())});
        if let Some(f) = &top_fn { o["function"] = json!(f) }
        out(&o); std::process::exit(0)
    }
    if tracer != "callTracer" {
        out(&json!({"tool":"contract-trace","status":"ok","chain_id":cid,"tracer":tracer,"result":r})); std::process::exit(0)
    }
    if !r.is_object() { fail(Some(&cx), "rpc_error", json!({"error":"callTracer result is not an object"})) }
    let fs = frames(&r);
    for (i, (d, f)) in fs.iter().enumerate() {
        let mut o = json!({"tool":"contract-trace","status":"ok","chain_id":cid,"frame":i,"depth":d});
        o.as_object_mut().unwrap().extend(f.as_object().cloned().unwrap_or_default());
        if i == 0 { if let Some(t) = &top_fn { o["function"] = json!(t) } }
        if !sigs.is_empty() { if let Some(inp) = f["input"].as_str().and_then(|s| unhex(s).ok()).filter(|b| b.len() >= 4) {
            if let Ok(c) = api::decode_selector_data(&inp, &sigs) { o["call"] = c }
        } }
        out(&o);
    }
    if r.get("error").is_some_and(|e| !e.is_null()) {
        fail(Some(&cx), "reverted", json!({"chain_id":cid,"error":r["error"],"revertReason":r.get("revertReason").cloned().unwrap_or(Value::Null),"frames":fs.len()}))
    }
}

#[cfg(test)]
mod t {
    use super::*;
    #[test]
    fn quantities() {
        assert_eq!(qty("0").unwrap(), "0x0"); assert_eq!(qty("255").unwrap(), "0xff"); assert_eq!(qty("0x00ff").unwrap(), "0xff");
        assert_eq!(qty("1000000000000000000").unwrap(), "0xde0b6b3a7640000");
        assert!(qty("0x").is_err()); assert!(qty("-1").is_err()); assert!(qty(&"9".repeat(79)).is_err());
    }
    #[test]
    fn state_checked() {
        let a = "0x00000000000000000000000000000000000000aa";
        let ok = check_state(&json!({a: {"balance":"1000","code":"0x6000","stateDiff":{format!("0x{}", "0".repeat(64)): format!("0x{}", "0".repeat(63) + "1")}}})).unwrap();
        assert_eq!(ok[checksum_address(&parse_address(a).unwrap())]["balance"], "0x3e8");
        assert!(check_state(&json!({a: {"bogus":1}})).is_err());
        assert!(check_state(&json!({a: {"state":{}, "stateDiff":{}}})).is_err());
        assert!(check_state(&json!({"0x12": {}})).is_err());
        assert!(check_state(&json!({a: {"state":{"0x01":"0x02"}}})).is_err());
    }
    #[test]
    fn flatten() {
        let r = json!({"type":"CALL","calls":[{"type":"STATICCALL","calls":[{"type":"CALL"}]},{"type":"DELEGATECALL"}]});
        let f = frames(&r);
        assert_eq!(f.iter().map(|(d, v)| (*d, v["type"].as_str().unwrap())).collect::<Vec<_>>(), vec![(0,"CALL"),(1,"STATICCALL"),(2,"CALL"),(1,"DELEGATECALL")]);
        assert!(f[0].1.get("calls").is_none());
    }
}
