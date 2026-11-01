//! JSON-in/JSON-out entry points shared by the CLI tools and the wasm facade (see EXPORTS.md).
//! Each returns `{status:"ok", ...}` or Err(code); callers wrap errors as `{status, error}`.
use crate::abi::{self, Param, Ty};
use crate::sig::{self, Kind, Sig};
use crate::{checksum_address, hex, keccak, parse_address, unhex};
use serde_json::{json, Value};

pub fn keccak256_hex(data_hex: &str) -> Result<String, String> { Ok(hex(&keccak(&unhex(data_hex)?))) }

/// `{kind, signature, hash, selector|topic}` for one signature (`function`/`event`/`error` keyword optional).
pub fn sig_info(s: &Sig) -> Value {
    let h = s.hash();
    let mut o = json!({"status": "ok", "kind": s.kind.as_str(), "signature": s.canonical(), "hash": hex(&h)});
    match s.kind {
        Kind::Event => { o["topic"] = json!(hex(&h)); if s.anonymous { o["anonymous"] = json!(true); } }
        _ => o["selector"] = json!(hex(&h[..4])),
    }
    o
}

pub fn sig_hash(signature: &str) -> Result<Value, String> { Ok(sig_info(&Sig::parse(signature)?)) }

/// Load signatures from a user-supplied file: Solidity-JSON ABI, or one human-readable signature per line ('#' comments).
pub fn load_sigs(text: &str) -> Result<Vec<Sig>, String> {
    let t = text.trim_start();
    if t.starts_with('[') || t.starts_with('{') { return sig::parse_abi_json(t); }
    t.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(Sig::parse).collect()
}

/// Reverse lookup of a 4-byte selector or 32-byte topic against `sigs` only (no network, no built-in database).
pub fn lookup(hash_hex: &str, sigs: &[Sig]) -> Result<Value, String> {
    let h = unhex(hash_hex)?;
    if h.len() != 4 && h.len() != 32 { return Err("lookup_needs_4_or_32_bytes".into()); }
    let mut m: Vec<String> = sigs.iter().filter(|s| (s.kind == Kind::Event) == (h.len() == 32) && s.hash()[..h.len()] == h[..]).map(|s| format!("{} {}", s.kind.as_str(), s.canonical())).collect();
    m.sort(); m.dedup();
    Ok(json!({"status": if m.is_empty() { "no_match" } else { "ok" }, "query": hex(&h), "matches": m}))
}

/// What a JSON input object carries, auto-detected: eth_getTransactionByHash result (`input`), a log (`topics`+`data`),
/// an eth_call result string, or `{data}`. JSON-RPC envelopes (`{"result": ...}`) are unwrapped. Plain hex is calldata/data.
pub enum Input { Data(Vec<u8>), Log(Vec<[u8; 32]>, Vec<u8>) }

pub fn parse_input(text: &str) -> Result<Input, String> {
    let t = text.trim();
    if !t.starts_with('{') { return Ok(Input::Data(unhex(t)?)); }
    let mut v: Value = serde_json::from_str(t).map_err(|_| "bad_input_json")?;
    if let Some(e) = v.get("error") {
        // a JSON-RPC revert: error.data carries the revert bytes
        if let Some(d) = e.get("data").and_then(Value::as_str) { return Ok(Input::Data(unhex(d)?)); }
        return Err("rpc_error_without_data".into());
    }
    if let Some(r) = v.get("result").cloned() { v = r; }
    if let Value::String(s) = &v { return Ok(Input::Data(unhex(s)?)); }
    if let Some(Value::Array(ts)) = v.get("topics") {
        let mut topics = vec![];
        for x in ts { let b = unhex(x.as_str().ok_or("bad_topic")?)?; topics.push(<[u8; 32]>::try_from(b.as_slice()).map_err(|_| "topic_not_32_bytes")?); }
        if topics.len() > 4 { return Err("more_than_4_topics".into()); }
        return Ok(Input::Log(topics, unhex(v.get("data").and_then(Value::as_str).unwrap_or("0x"))?));
    }
    for k in ["input", "data"] { if let Some(s) = v.get(k).and_then(Value::as_str) { return Ok(Input::Data(unhex(s)?)); } }
    Err("input_json_has_no_input_data_or_topics".into())
}

fn builtin_errors() -> Vec<Sig> {
    vec![Sig::parse_as("error Error(string message)", Kind::Error).unwrap(), Sig::parse_as("error Panic(uint256 code)", Kind::Error).unwrap()]
}

/// Solidity panic codes (docs.soliditylang.org, "Panic via assert and Error via require").
pub fn panic_reason(code: &str) -> Option<&'static str> {
    Some(match code {
        "0" => "generic compiler panic", "1" => "assert(false)", "17" => "arithmetic overflow or underflow",
        "18" => "division or modulo by zero", "33" => "invalid enum value", "34" => "bad storage byte array encoding",
        "49" => "pop() on empty array", "50" => "array index out of bounds", "65" => "too much memory allocated",
        "81" => "call to zero-initialised internal function", _ => return None,
    })
}

/// Decode calldata or revert data with a 4-byte selector against `sigs` (+ Error(string)/Panic(uint256)).
pub fn decode_selector_data(d: &[u8], sigs: &[Sig]) -> Result<Value, String> { decode_selector_data_t(d, sigs, false) }

/// Strict decode, or with `allow_trailing` the [`abi::decode_prefix`] form that also returns the unconsumed suffix as hex.
fn dec_t(ps: &[Param], d: &[u8], allow_trailing: bool) -> Result<(Vec<Value>, Option<String>), String> {
    if !allow_trailing { return Ok((abi::decode(ps, d)?, None)); }
    let (v, end) = abi::decode_prefix(ps, d)?;
    Ok((v, Some(hex(&d[end..]))))
}

fn decode_selector_data_t(d: &[u8], sigs: &[Sig], allow_trailing: bool) -> Result<Value, String> {
    if d.len() < 4 { return Err("data_shorter_than_selector".into()); }
    let all: Vec<Sig> = sigs.iter().cloned().chain(builtin_errors()).filter(|s| s.kind != Kind::Event && s.kind != Kind::Constructor).collect();
    let cands: Vec<&Sig> = all.iter().filter(|s| s.selector()[..] == d[..4]).collect();
    if cands.is_empty() { return Ok(json!({"status": "no_match", "selector": hex(&d[..4])})); }
    let mut last = String::new();
    for s in cands {
        match dec_t(&s.inputs, &d[4..], allow_trailing) {
            Ok((vals, tr)) => {
                let mut o = sig_info(s);
                let panic = (s.name == "Panic" && s.canonical() == "Panic(uint256)").then(|| vals[0].as_str().and_then(panic_reason)).flatten();
                o["args"] = abi::labelled(&s.inputs, vals);
                if let Some(r) = panic { o["panic_reason"] = json!(r); }
                if let Some(t) = tr { o["trailing_hex"] = json!(t); }
                return Ok(o);
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Decode a log: topic0 selects the event among `sigs` (anonymous events: tried by shape).
pub fn decode_log(topics: &[[u8; 32]], data: &[u8], sigs: &[Sig]) -> Result<Value, String> { decode_log_t(topics, data, sigs, false) }

fn decode_log_t(topics: &[[u8; 32]], data: &[u8], sigs: &[Sig], allow_trailing: bool) -> Result<Value, String> {
    let evs: Vec<&Sig> = sigs.iter().filter(|s| s.kind == Kind::Event).collect();
    let mut last = String::from("no_matching_event");
    for s in evs {
        let named = !s.anonymous;
        if named && topics.first() != Some(&s.hash()) { continue; }
        let idx: Vec<&Param> = s.inputs.iter().filter(|p| p.indexed).collect();
        if topics.len() != idx.len() + named as usize { last = "topic_count_mismatch".into(); continue; }
        let non: Vec<Param> = s.inputs.iter().filter(|p| !p.indexed).cloned().collect();
        let res = (|| -> Result<Value, String> {
            let (dvals, tr) = dec_t(&non, data, allow_trailing)?;
            let mut dv = dvals.into_iter();
            let mut tv = topics[named as usize..].iter();
            let mut args = vec![];
            for p in &s.inputs {
                let mut o = json!({"type": p.ty.canon(), "indexed": p.indexed});
                if !p.name.is_empty() { o["name"] = json!(p.name); }
                if p.indexed {
                    let t = tv.next().unwrap();
                    // dynamic indexed values are stored as keccak256 of their encoding: report the hash only
                    if p.ty.is_dynamic() || matches!(p.ty, Ty::Tuple(_) | Ty::Array(..)) { o["value_hash"] = json!(hex(t)); }
                    else { o["value"] = abi::decode_word(&p.ty, t)?; }
                } else { o["value"] = dv.next().unwrap(); }
                args.push(o);
            }
            let mut o = sig_info(s);
            o["args"] = Value::Array(args);
            if let Some(t) = tr { o["trailing_hex"] = json!(t); }
            Ok(o)
        })();
        match res { Ok(o) => return Ok(o), Err(e) => last = e }
    }
    if last == "no_matching_event" { return Ok(json!({"status": "no_match", "topic": topics.first().map(|t| hex(t))})); }
    Err(last)
}

/// Decode raw data (returndata, constructor args) as a type list, no selector.
pub fn decode_types(types: &[Param], d: &[u8]) -> Result<Value, String> { decode_types_t(types, d, false) }

fn decode_types_t(types: &[Param], d: &[u8], allow_trailing: bool) -> Result<Value, String> {
    let (vals, tr) = dec_t(types, d, allow_trailing)?;
    let mut o = json!({"status": "ok", "types": format!("({})", types.iter().map(|p| p.ty.canon()).collect::<Vec<_>>().join(",")), "args": abi::labelled(types, vals)});
    if let Some(t) = tr { o["trailing_hex"] = json!(t); }
    Ok(o)
}

/// Decode output data of a function by its `returns (...)` list.
pub fn decode_output(s: &Sig, d: &[u8]) -> Result<Value, String> { decode_output_t(s, d, false) }

fn decode_output_t(s: &Sig, d: &[u8], allow_trailing: bool) -> Result<Value, String> {
    let mut o = decode_types_t(&s.outputs, d, allow_trailing)?;
    o["kind"] = json!("returns"); o["signature"] = json!(s.canonical()); o["selector"] = json!(hex(&s.selector()));
    Ok(o)
}

/// Facade: `{input, sig? | sigs?(text), types?, output?, allow_trailing?}` -> decoded JSON. Exactly the CLI's logic.
pub fn decode_json(req: &Value) -> Result<Value, String> {
    let input = match req.get("input") { Some(Value::String(s)) => s.clone(), Some(v @ Value::Object(_)) => v.to_string(), _ => return Err("missing_input".into()) };
    let mut sigs = vec![];
    if let Some(s) = req.get("sig").and_then(Value::as_str) { sigs.push(Sig::parse(s)?); }
    if let Some(s) = req.get("abi") { sigs.extend(load_sigs(&match s { Value::String(x) => x.clone(), v => v.to_string() })?); }
    let types = req.get("types").and_then(Value::as_str);
    let allow_trailing = match req.get("allow_trailing") { None | Some(Value::Bool(false)) => false, Some(Value::Bool(true)) => true, _ => return Err("allow_trailing_must_be_bool".into()) };
    decode_with(&input, &sigs, types, req.get("output").and_then(Value::as_bool).unwrap_or(false), allow_trailing)
}

/// Decode one input (hex or JSON) against parsed signatures; `types` = raw type list; `output` = first sig's returns.
/// `allow_trailing` (opt-in, default strict): bytes after the last head/tail are accepted and returned as
/// `trailing_hex` (always present when set, "0x" if none); every other strictness rule still applies.
pub fn decode_with(input: &str, sigs: &[Sig], types: Option<&str>, output: bool, allow_trailing: bool) -> Result<Value, String> {
    let inp = parse_input(input)?;
    if let Some(t) = types {
        let Input::Data(d) = inp else { return Err("types_need_data_not_a_log".into()) };
        return decode_types_t(&abi::parse_types(t)?, &d, allow_trailing);
    }
    if output {
        let Input::Data(d) = inp else { return Err("output_needs_data".into()) };
        let s = sigs.first().ok_or("output_needs_sig")?;
        return decode_output_t(s, &d, allow_trailing);
    }
    match inp {
        Input::Log(t, d) => decode_log_t(&t, &d, sigs, allow_trailing),
        Input::Data(d) => decode_selector_data_t(&d, sigs, allow_trailing),
    }
}

/// Facade: `{sig, args:[...]}` -> `{status, signature, selector, data}`. `sig` without a name (`(uint256,address)`) encodes bare args.
pub fn encode_json(req: &Value) -> Result<Value, String> {
    let args = req.get("args").and_then(Value::as_array).ok_or("missing_args")?;
    if req.get("abi").is_some_and(|a| !a.is_null()) { return encode_abi_fn(req, args) }
    let s = req.get("sig").and_then(Value::as_str).ok_or("missing_sig")?;
    encode_call(s, args)
}

/// Signatures a request names: `sigs` (array of signature strings) plus `abi` (Solidity JSON ABI as text, array or object).
pub fn sigs_from_req(req: &Value) -> Result<Vec<Sig>, String> {
    let mut out = vec![];
    match req.get("sigs") {
        None | Some(Value::Null) => {}
        Some(Value::Array(a)) => for x in a { out.push(Sig::parse(x.as_str().ok_or("bad_sigs")?)?) },
        Some(_) => return Err("bad_sigs".into()),
    }
    match req.get("abi") {
        None | Some(Value::Null) => {}
        Some(Value::String(t)) => out.extend(sig::parse_abi_json(t)?),
        Some(v) => out.extend(sig::parse_abi_json(&v.to_string())?),
    }
    Ok(out)
}

/// `{abi, name, args, signature?}`: encode a call to the function `name` of a JSON ABI. Overloads are told
/// apart by argument count, then by `signature` (e.g. "transfer(address,uint256)"); anything still
/// ambiguous is refused (`ambiguous_overload`, with `candidates` in the message), never guessed.
pub fn encode_abi_fn(req: &Value, args: &[Value]) -> Result<Value, String> {
    let name = req.get("name").and_then(Value::as_str).ok_or("missing_name")?;
    let all = sigs_from_req(&json!({"abi": req["abi"]}))?;
    let named: Vec<&Sig> = all.iter().filter(|s| s.kind == Kind::Function && s.name == name).collect();
    if named.is_empty() { return Err("no_such_function".into()) }
    let mut c: Vec<&Sig> = named.iter().copied().filter(|s| s.inputs.len() == args.len()).collect();
    if let Some(want) = req.get("signature").and_then(Value::as_str) {
        let w = Sig::parse(want)?.canonical();
        c.retain(|s| s.canonical() == w);
    }
    match c.len() {
        0 => Err("no_overload_matches".into()),
        1 => { let mut o = encode_call(&c[0].canonical(), args)?; o["name"] = json!(name); Ok(o) }
        _ => Err(format!("ambiguous_overload: {}", c.iter().map(|s| s.canonical()).collect::<Vec<_>>().join(" | "))),
    }
}

/// Facade for `approve_call`: `{to: "0x..20 bytes" | null, data: "0x..", sigs?: [..], abi?, createHash?: "0x..32 bytes"}`.
/// `to` null (or absent) = contract creation. Same check as `tx-verify --call/--abi/--create-hash`.
pub fn approve_json(req: &Value) -> Result<Value, String> {
    let to = match req.get("to") { None | Some(Value::Null) => None, Some(Value::String(t)) => Some(parse_address(t)?), _ => return Err("bad_to".into()) };
    let data = unhex(req.get("data").and_then(Value::as_str).ok_or("missing_data")?)?;
    let ch = create_hash_from_req(req)?;
    Ok(approve_call(to.as_ref().map(|x| &x[..]), &data, &sigs_from_req(req)?, ch.as_ref()))
}

/// `createHash` of a request: 32-byte keccak256 hex, or none.
pub fn create_hash_from_req(req: &Value) -> Result<Option<[u8; 32]>, String> {
    match req.get("createHash") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(h)) => Ok(Some(<[u8; 32]>::try_from(unhex(h)?.as_slice()).map_err(|_| "bad_createHash")?)),
        _ => Err("bad_createHash".into()),
    }
}

/// What an approved call lifts in a policy verdict (shared by tx-verify and the wasm verifyTx):
/// `unknown_contract_call`; `destination_not_expected` when the contract itself is in `expect_to`;
/// `has_warnings` when the only warnings are the ones a decoded call explains. Nothing else changes.
pub fn lift_approved(o: &Value, to: Option<&str>, expect_to: &[String], warnings: &[String], f: &mut Vec<String>) {
    if o["status"] != "ok" { return }
    f.retain(|x| x != "unknown_contract_call");
    if let Some(to) = to { if expect_to.iter().any(|e| e.eq_ignore_ascii_case(to)) { f.retain(|x| x != "destination_not_expected") } }
    if warnings.iter().all(|w| ["unsigned", "unknown_calldata", "contract_creation"].contains(&w.as_str())) { f.retain(|x| x != "has_warnings") }
}

/// Facade: `{types: "(int16,bytes1,...)", args:[..]}` -> Solidity `abi.encodePacked` bytes.
pub fn encode_packed_json(req: &Value) -> Result<Value, String> {
    let t = req.get("types").or_else(|| req.get("sig")).and_then(Value::as_str).ok_or("missing_types")?;
    let args = req.get("args").and_then(Value::as_array).ok_or("missing_args")?;
    let ps = abi::parse_types(t)?;
    let d = abi::encode_packed(&ps, args)?;
    Ok(json!({"status": "ok", "types": format!("({})", ps.iter().map(|p| p.ty.canon()).collect::<Vec<_>>().join(",")), "data": hex(&d), "keccak256": hex(&keccak(&d))}))
}

pub fn encode_call(s: &str, args: &[Value]) -> Result<Value, String> {
    if s.trim_start().starts_with('(') {
        let ps = abi::parse_types(s)?;
        return Ok(json!({"status": "ok", "types": format!("({})", ps.iter().map(|p| p.ty.canon()).collect::<Vec<_>>().join(",")), "data": hex(&abi::encode(&ps, args)?)}));
    }
    let sg = Sig::parse(s)?;
    let mut d = sg.selector().to_vec();
    d.extend(abi::encode(&sg.inputs, args)?);
    Ok(json!({"status": "ok", "signature": sg.canonical(), "selector": hex(&sg.selector()), "data": hex(&d)}))
}

/// Facade: `{deployer, nonce}` (CREATE) or `{deployer, salt, init_code_hash | init_code}` (CREATE2).
/// A JSON-RPC `{"result": tx}` envelope is unwrapped and a tx object's `from` stands for `deployer`.
pub fn create_json(req: &Value) -> Result<Value, String> {
    let req = req.get("result").filter(|r| r.is_object()).unwrap_or(req);
    let dep = parse_address(req.get("deployer").or_else(|| req.get("from")).and_then(Value::as_str).ok_or("missing_deployer")?)?;
    if let Some(salt) = req.get("salt") {
        let salt = unhex(salt.as_str().ok_or("bad_salt")?)?;
        let salt: [u8; 32] = salt.as_slice().try_into().map_err(|_| "salt_not_32_bytes")?;
        let h: [u8; 32] = match (req.get("init_code_hash").and_then(Value::as_str), req.get("init_code").and_then(Value::as_str)) {
            (Some(h), None) => unhex(h)?.as_slice().try_into().map_err(|_| "init_code_hash_not_32_bytes")?,
            (None, Some(c)) => keccak(&unhex(c)?),
            _ => return Err("create2_needs_exactly_one_of_init_code_hash_init_code".into()),
        };
        let a = crate::create::create2(&dep, &salt, &h);
        return Ok(json!({"status": "ok", "scheme": "create2", "deployer": checksum_address(&dep), "salt": hex(&salt), "init_code_hash": hex(&h), "address": checksum_address(&a)}));
    }
    let n = match req.get("nonce") {
        Some(Value::Number(n)) => n.as_u64().ok_or("bad_nonce")?,
        Some(Value::String(s)) => if let Some(h) = s.strip_prefix("0x") { u64::from_str_radix(h, 16).map_err(|_| "bad_nonce")? } else { s.parse().map_err(|_| "bad_nonce")? },
        _ => return Err("create_needs_nonce_or_salt".into()),
    };
    if n == u64::MAX { return Err("nonce_out_of_range_eip2681".into()); }
    let a = crate::create::create(&dep, n);
    Ok(json!({"status": "ok", "scheme": "create", "deployer": checksum_address(&dep), "nonce": n, "address": checksum_address(&a)}))
}

/// Log inputs a node hands back, flattened: one log object, an array of logs, an `eth_getLogs` envelope,
/// a receipt (its `logs`) or a receipt envelope. Order is preserved.
pub fn collect_logs(v: &Value) -> Result<Vec<Value>, String> {
    if let Some(e) = v.get("error") { return Err(format!("rpc_error:{e}")); }
    let r = v.get("result").unwrap_or(v);
    match r {
        Value::Array(xs) => { let mut o = vec![]; for x in xs { o.extend(collect_logs(x)?); } Ok(o) }
        Value::Object(m) if m.contains_key("topics") => Ok(vec![r.clone()]),
        Value::Object(m) if m.get("logs").is_some_and(Value::is_array) => collect_logs(&m["logs"]),
        Value::Null => Ok(vec![]),
        _ => Err("input_is_not_a_log_receipt_or_getlogs_result".into()),
    }
}

fn hex_qty(v: &Value) -> Value {
    match v.as_str().and_then(|s| s.strip_prefix("0x")).and_then(|h| u64::from_str_radix(h, 16).ok()) { Some(n) => json!(n), None => v.clone() }
}

/// Decode one log object (topics + data) against `sigs`, keeping where it came from:
/// `address`, `block_number`, `transaction_hash`, `log_index`, `removed` when the node gave them.
pub fn decode_log_object(log: &Value, sigs: &[Sig]) -> Result<Value, String> {
    let ts = log.get("topics").and_then(Value::as_array).ok_or("log_without_topics")?;
    if ts.len() > 4 { return Err("more_than_4_topics".into()); }
    let mut topics = vec![];
    for x in ts { let b = unhex(x.as_str().ok_or("bad_topic")?)?; topics.push(<[u8; 32]>::try_from(b.as_slice()).map_err(|_| "topic_not_32_bytes")?); }
    let data = unhex(log.get("data").and_then(Value::as_str).unwrap_or("0x"))?;
    let mut o = decode_log(&topics, &data, sigs)?;
    if o["status"] == "ok" { o["event"] = json!(o["signature"].as_str().unwrap_or("").split('(').next().unwrap_or("")); }
    if let Some(a) = log.get("address").and_then(Value::as_str) { o["address"] = json!(parse_address(a).map(|a| checksum_address(&a)).unwrap_or_else(|_| a.to_string())); }
    for (k, out) in [("blockNumber", "block_number"), ("logIndex", "log_index"), ("transactionIndex", "transaction_index")] {
        if let Some(x) = log.get(k) { o[out] = hex_qty(x); }
    }
    for (k, out) in [("transactionHash", "transaction_hash"), ("blockHash", "block_hash"), ("removed", "removed")] {
        if let Some(x) = log.get(k) { o[out] = x.clone(); }
    }
    Ok(o)
}

/// Signing-time check of an EVM tx's calldata. `to: None` = contract creation.
/// Calls: strict decode against `sigs` (function signatures only; the calldata must
/// re-encode byte-for-byte, so trailing or non-canonical bytes are refused).
/// Creation: approved only when keccak256(init code) equals `create_hash`.
/// Returns {"status": "ok"|"unknown_selector"|"bad_calldata"|"initcode_mismatch"|"not_approved", ...}.
pub fn approve_call(to: Option<&[u8]>, data: &[u8], sigs: &[Sig], create_hash: Option<&[u8; 32]>) -> Value {
    if to.is_none() {
        let h = keccak(data);
        let mut o = json!({"kind": "create", "initcode_len": data.len(), "initcode_keccak256": hex(&h)});
        o["status"] = json!(match create_hash { Some(x) if *x == h => "ok", Some(_) => "initcode_mismatch", None => "not_approved" });
        return o;
    }
    if data.len() < 4 { return json!({"kind": "call", "status": "bad_calldata", "data_len": data.len()}) }
    let sel = hex(&data[..4]);
    for s in sigs.iter().filter(|s| s.kind == Kind::Function && s.selector()[..] == data[..4]) {
        let Ok(vals) = abi::decode(&s.inputs, &data[4..]) else { continue };
        if abi::encode(&s.inputs, &vals).ok().as_deref() != Some(&data[4..]) { continue }
        let mut o = sig_info(s);
        o["kind"] = json!("call");
        o["args"] = abi::labelled(&s.inputs, vals);
        o["status"] = json!("ok");
        return o;
    }
    let known = sigs.iter().any(|s| s.selector()[..] == data[..4]);
    json!({"kind": "call", "selector": sel, "status": if known { "bad_calldata" } else { "unknown_selector" }})
}

/// Human lines for `approve_call` output (shown in the signing summary).
pub fn approve_text(o: &Value) -> String {
    let st = o["status"].as_str().unwrap_or("");
    if o["kind"] == "create" {
        return format!("Contract creation: init code {} bytes, keccak256 {} ({st})\n", o["initcode_len"], o["initcode_keccak256"].as_str().unwrap_or(""));
    }
    if st != "ok" { return format!("Contract call: selector {} ({st})\n", o["selector"].as_str().unwrap_or("?")) }
    let mut s = format!("Contract call: {}\n", o["signature"].as_str().or(o["name"].as_str()).unwrap_or("?"));
    for (i, a) in o["args"].as_array().into_iter().flatten().enumerate() {
        let n = a["name"].as_str().map(String::from).unwrap_or(format!("arg{i}"));
        let v = match &a["value"] { Value::String(x) => x.clone(), x => x.to_string() };
        s += &format!("  {n} ({}): {v}\n", a["type"].as_str().unwrap_or("?"));
    }
    s
}

#[cfg(test)]
mod approve_tests {
    use super::*;
    #[test]
    fn strict_call_and_create() {
        let s = vec![Sig::parse("setValue(uint256)").unwrap()];
        let mut d = unhex("0x55241077000000000000000000000000000000000000000000000000000000000000002a").unwrap();
        let to = [0xaa_u8; 20];
        let o = approve_call(Some(&to), &d, &s, None);
        assert_eq!(o["status"], "ok"); assert_eq!(o["args"][0]["value"], "42");
        assert!(approve_text(&o).contains("setValue(uint256)"));
        assert_eq!(approve_call(Some(&to), &d, &[], None)["status"], "unknown_selector");
        d.push(0);
        assert_eq!(approve_call(Some(&to), &d, &s, None)["status"], "bad_calldata");
        let h = keccak(&[0x60, 0x2a]);
        assert_eq!(approve_call(None, &[0x60, 0x2a], &[], Some(&h))["status"], "ok");
        assert_eq!(approve_call(None, &[0x60, 0x2b], &[], Some(&h))["status"], "initcode_mismatch");
        assert_eq!(approve_call(None, &[0x60, 0x2a], &[], None)["status"], "not_approved");
        let j = |v: Value| approve_json(&v).unwrap()["status"].clone();
        let data = "0x55241077000000000000000000000000000000000000000000000000000000000000002a";
        assert_eq!(j(json!({"to": format!("0x{}", "aa".repeat(20)), "data": data, "sigs": ["setValue(uint256)"]})), "ok");
        let abi = r#"[{"type":"function","name":"setValue","inputs":[{"name":"v","type":"uint256"}]}]"#;
        assert_eq!(j(json!({"to": format!("0x{}", "aa".repeat(20)), "data": data, "abi": abi})), "ok");
        assert_eq!(j(json!({"to": format!("0x{}", "aa".repeat(20)), "data": data})), "unknown_selector");
        assert_eq!(j(json!({"to": null, "data": "0x602a", "createHash": hex(&h)})), "ok");
        assert!(approve_json(&json!({"to": null, "data": "0x602a", "createHash": "0x12"})).is_err());
    }
    #[test]
    fn encode_from_abi_overloads() {
        let abi = json!([{"type":"function","name":"f","inputs":[{"type":"uint256"}]},{"type":"function","name":"f","inputs":[{"type":"address"}]},
            {"type":"function","name":"f","inputs":[{"type":"uint256"},{"type":"uint256"}]}]);
        let e = |v: Value| encode_json(&v);
        assert_eq!(e(json!({"abi": abi, "name": "f", "args": ["1", "2"]})).unwrap()["signature"], "f(uint256,uint256)");
        assert!(e(json!({"abi": abi, "name": "f", "args": ["1"]})).unwrap_err().starts_with("ambiguous_overload: f(uint256) | f(address)"));
        let o = e(json!({"abi": abi, "name": "f", "args": ["1"], "signature": "f(uint256)"})).unwrap();
        assert_eq!(o, { let mut x = encode_call("f(uint256)", &[json!("1")]).unwrap(); x["name"] = json!("f"); x });
        assert_eq!(e(json!({"abi": abi, "name": "g", "args": []})).unwrap_err(), "no_such_function");
        assert_eq!(e(json!({"abi": abi, "name": "f", "args": []})).unwrap_err(), "no_overload_matches");
    }
}
