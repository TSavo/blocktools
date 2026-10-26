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
pub fn decode_selector_data(d: &[u8], sigs: &[Sig]) -> Result<Value, String> {
    if d.len() < 4 { return Err("data_shorter_than_selector".into()); }
    let all: Vec<Sig> = sigs.iter().cloned().chain(builtin_errors()).filter(|s| s.kind != Kind::Event && s.kind != Kind::Constructor).collect();
    let cands: Vec<&Sig> = all.iter().filter(|s| s.selector()[..] == d[..4]).collect();
    if cands.is_empty() { return Ok(json!({"status": "no_match", "selector": hex(&d[..4])})); }
    let mut last = String::new();
    for s in cands {
        match abi::decode(&s.inputs, &d[4..]) {
            Ok(vals) => {
                let mut o = sig_info(s);
                let panic = (s.name == "Panic" && s.canonical() == "Panic(uint256)").then(|| vals[0].as_str().and_then(panic_reason)).flatten();
                o["args"] = abi::labelled(&s.inputs, vals);
                if let Some(r) = panic { o["panic_reason"] = json!(r); }
                return Ok(o);
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Decode a log: topic0 selects the event among `sigs` (anonymous events: tried by shape).
pub fn decode_log(topics: &[[u8; 32]], data: &[u8], sigs: &[Sig]) -> Result<Value, String> {
    let evs: Vec<&Sig> = sigs.iter().filter(|s| s.kind == Kind::Event).collect();
    let mut last = String::from("no_matching_event");
    for s in evs {
        let named = !s.anonymous;
        if named && topics.first() != Some(&s.hash()) { continue; }
        let idx: Vec<&Param> = s.inputs.iter().filter(|p| p.indexed).collect();
        if topics.len() != idx.len() + named as usize { last = "topic_count_mismatch".into(); continue; }
        let non: Vec<Param> = s.inputs.iter().filter(|p| !p.indexed).cloned().collect();
        let res = (|| -> Result<Value, String> {
            let mut dv = abi::decode(&non, data)?.into_iter();
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
            Ok(o)
        })();
        match res { Ok(o) => return Ok(o), Err(e) => last = e }
    }
    if last == "no_matching_event" { return Ok(json!({"status": "no_match", "topic": topics.first().map(|t| hex(t))})); }
    Err(last)
}

/// Decode raw data (returndata, constructor args) as a type list, no selector.
pub fn decode_types(types: &[Param], d: &[u8]) -> Result<Value, String> {
    let vals = abi::decode(types, d)?;
    Ok(json!({"status": "ok", "types": format!("({})", types.iter().map(|p| p.ty.canon()).collect::<Vec<_>>().join(",")), "args": abi::labelled(types, vals)}))
}

/// Decode output data of a function by its `returns (...)` list.
pub fn decode_output(s: &Sig, d: &[u8]) -> Result<Value, String> {
    let mut o = decode_types(&s.outputs, d)?;
    o["kind"] = json!("returns"); o["signature"] = json!(s.canonical()); o["selector"] = json!(hex(&s.selector()));
    Ok(o)
}

/// Facade: `{input, sig? | sigs?(text), types?, output?}` -> decoded JSON. Exactly the CLI's logic.
pub fn decode_json(req: &Value) -> Result<Value, String> {
    let input = match req.get("input") { Some(Value::String(s)) => s.clone(), Some(v @ Value::Object(_)) => v.to_string(), _ => return Err("missing_input".into()) };
    let mut sigs = vec![];
    if let Some(s) = req.get("sig").and_then(Value::as_str) { sigs.push(Sig::parse(s)?); }
    if let Some(s) = req.get("abi") { sigs.extend(load_sigs(&match s { Value::String(x) => x.clone(), v => v.to_string() })?); }
    let types = req.get("types").and_then(Value::as_str);
    decode_with(&input, &sigs, types, req.get("output").and_then(Value::as_bool).unwrap_or(false))
}

/// Decode one input (hex or JSON) against parsed signatures; `types` = raw type list; `output` = first sig's returns.
pub fn decode_with(input: &str, sigs: &[Sig], types: Option<&str>, output: bool) -> Result<Value, String> {
    let inp = parse_input(input)?;
    if let Some(t) = types {
        let Input::Data(d) = inp else { return Err("types_need_data_not_a_log".into()) };
        return decode_types(&abi::parse_types(t)?, &d);
    }
    if output {
        let Input::Data(d) = inp else { return Err("output_needs_data".into()) };
        let s = sigs.first().ok_or("output_needs_sig")?;
        return decode_output(s, &d);
    }
    match inp {
        Input::Log(t, d) => decode_log(&t, &d, sigs),
        Input::Data(d) => decode_selector_data(&d, sigs),
    }
}

/// Facade: `{sig, args:[...]}` -> `{status, signature, selector, data}`. `sig` without a name (`(uint256,address)`) encodes bare args.
pub fn encode_json(req: &Value) -> Result<Value, String> {
    let s = req.get("sig").and_then(Value::as_str).ok_or("missing_sig")?;
    let args = req.get("args").and_then(Value::as_array).ok_or("missing_args")?;
    encode_call(s, args)
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
