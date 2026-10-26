//! Signature grammar: `transfer(address,uint256)`, `function transfer(address to, uint256 amt) returns (bool)`,
//! `event Transfer(address indexed from, address indexed to, uint256 value)`, `error Foo(uint8)`,
//! tuples `f((uint256,address)[],bytes)` / `tuple(...)`, and Solidity-JSON ABI items. Canonical form
//! follows the Solidity ABI spec: names, data locations and `indexed` dropped, `uint`->`uint256`,
//! `int`->`int256`, tuples written `(a,b)`.
use crate::abi::{Param, Ty};
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind { Function, Event, Error, Constructor }

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self { Kind::Function => "function", Kind::Event => "event", Kind::Error => "error", Kind::Constructor => "constructor" }
    }
}

#[derive(Clone, Debug)]
pub struct Sig {
    pub kind: Kind,
    pub name: String,
    pub inputs: Vec<Param>,
    pub outputs: Vec<Param>,
    pub anonymous: bool,
}

const MAX_SIG: usize = 4096;

impl Sig {
    pub fn canonical(&self) -> String {
        format!("{}({})", self.name, self.inputs.iter().map(|p| p.ty.canon()).collect::<Vec<_>>().join(","))
    }
    /// keccak256 of the canonical signature.
    pub fn hash(&self) -> [u8; 32] { crate::keccak(self.canonical().as_bytes()) }
    pub fn selector(&self) -> [u8; 4] { let h = self.hash(); [h[0], h[1], h[2], h[3]] }

    /// Parse a human-readable signature. Without a keyword the kind is `default`.
    pub fn parse_as(s: &str, default: Kind) -> Result<Sig, String> {
        let s = s.trim().trim_end_matches(';').trim();
        if s.is_empty() { return Err("empty_signature".into()); }
        if s.len() > MAX_SIG { return Err("signature_too_long".into()); }
        let (kind, rest) = [("function ", Kind::Function), ("event ", Kind::Event), ("error ", Kind::Error), ("constructor", Kind::Constructor)]
            .iter()
            .find_map(|(k, kd)| s.strip_prefix(k).map(|r| (*kd, r.trim_start())))
            .unwrap_or((default, s));
        let open = rest.find('(').ok_or("signature_needs_parens")?;
        let name = rest[..open].trim().to_string();
        if kind != Kind::Constructor && !valid_ident(&name) { return Err("bad_signature_name".into()); }
        let close = matching(rest, open).ok_or("unbalanced_parens")?;
        let inputs = parse_params(&rest[open + 1..close], kind == Kind::Event)?;
        let mut tail = rest[close + 1..].trim();
        let mut outputs = vec![];
        let mut anonymous = false;
        // modifiers (view, pure, payable, external, public, anonymous) then optional returns (...)
        while !tail.is_empty() {
            if let Some(r) = tail.strip_prefix("returns") {
                let r = r.trim_start();
                if !r.starts_with('(') { return Err("returns_needs_parens".into()); }
                let c = matching(r, 0).ok_or("unbalanced_parens")?;
                outputs = parse_params(&r[1..c], false)?;
                tail = r[c + 1..].trim();
                continue;
            }
            let w: String = tail.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            match w.as_str() {
                "view" | "pure" | "payable" | "nonpayable" | "external" | "public" | "internal" | "virtual" | "override" => {}
                "anonymous" if kind == Kind::Event => anonymous = true,
                _ => return Err("bad_signature_suffix".into()),
            }
            tail = tail[w.len()..].trim_start();
        }
        Ok(Sig { kind, name, inputs, outputs, anonymous })
    }

    pub fn parse(s: &str) -> Result<Sig, String> { Sig::parse_as(s, Kind::Function) }

    /// One Solidity-JSON ABI item. Fallback/receive items yield Ok(None).
    pub fn from_abi_item(v: &Value) -> Result<Option<Sig>, String> {
        let kind = match v.get("type").and_then(Value::as_str).unwrap_or("function") {
            "function" => Kind::Function, "event" => Kind::Event, "error" => Kind::Error, "constructor" => Kind::Constructor,
            "fallback" | "receive" => return Ok(None),
            _ => return Err("bad_abi_item_type".into()),
        };
        let name = v.get("name").and_then(Value::as_str).unwrap_or("").to_string();
        if kind != Kind::Constructor && !valid_ident(&name) { return Err("bad_abi_item_name".into()); }
        let ps = |k: &str| -> Result<Vec<Param>, String> {
            match v.get(k) { None | Some(Value::Null) => Ok(vec![]), Some(Value::Array(a)) => a.iter().map(|p| param_from_json(p, 0)).collect(), _ => Err("bad_abi_params".into()) }
        };
        Ok(Some(Sig { kind, name, inputs: ps("inputs")?, outputs: ps("outputs")?, anonymous: v.get("anonymous").and_then(Value::as_bool).unwrap_or(false) }))
    }
}

/// Parse a Solidity-JSON ABI (array of items, or an object with an `abi` array, e.g. a Hardhat/Foundry artifact).
pub fn parse_abi_json(text: &str) -> Result<Vec<Sig>, String> {
    let v: Value = serde_json::from_str(text).map_err(|_| "bad_abi_json")?;
    let arr = match &v { Value::Array(a) => a, Value::Object(o) => o.get("abi").and_then(Value::as_array).ok_or("abi_json_needs_array")?, _ => return Err("abi_json_needs_array".into()) };
    let mut out = vec![];
    for it in arr { if let Some(s) = Sig::from_abi_item(it)? { out.push(s) } }
    Ok(out)
}

fn param_from_json(p: &Value, depth: usize) -> Result<Param, String> {
    if depth > 32 { return Err("abi_too_deep".into()); }
    let t = p.get("type").and_then(Value::as_str).ok_or("abi_param_needs_type")?;
    let name = p.get("name").and_then(Value::as_str).unwrap_or("").to_string();
    let indexed = p.get("indexed").and_then(Value::as_bool).unwrap_or(false);
    let ty = if let Some(suffix) = t.strip_prefix("tuple") {
        let comps = p.get("components").and_then(Value::as_array).ok_or("tuple_needs_components")?;
        let inner = comps.iter().map(|c| param_from_json(c, depth + 1)).collect::<Result<Vec<_>, _>>()?;
        Ty::with_suffix(Ty::Tuple(inner), suffix)?
    } else { Ty::parse(t)? };
    Ok(Param { name, ty, indexed })
}

pub(crate) fn valid_ident(n: &str) -> bool {
    let mut c = n.chars();
    matches!(c.next(), Some(x) if x.is_ascii_alphabetic() || x == '_' || x == '$') && c.all(|x| x.is_ascii_alphanumeric() || x == '_' || x == '$')
}

/// Index of the ')' matching the '(' at `open`.
pub(crate) fn matching(s: &str, open: usize) -> Option<usize> {
    let mut d = 0i32;
    for (i, c) in s.char_indices().skip_while(|(i, _)| *i < open) {
        match c { '(' => d += 1, ')' => { d -= 1; if d == 0 { return Some(i) } } _ => {} }
    }
    None
}

/// Split on top-level commas.
pub(crate) fn split_top(s: &str) -> Result<Vec<&str>, String> {
    let mut out = vec![]; let mut d = 0i32; let mut st = 0;
    for (i, c) in s.char_indices() {
        match c { '(' => d += 1, ')' => d -= 1, ',' if d == 0 => { out.push(&s[st..i]); st = i + 1 } _ => {} }
        if d < 0 { return Err("unbalanced_parens".into()); }
    }
    if d != 0 { return Err("unbalanced_parens".into()); }
    out.push(&s[st..]);
    Ok(out)
}

pub(crate) fn parse_params(s: &str, allow_indexed: bool) -> Result<Vec<Param>, String> {
    if s.trim().is_empty() { return Ok(vec![]); }
    split_top(s)?.into_iter().map(|p| parse_param(p.trim(), allow_indexed)).collect()
}

fn parse_param(p: &str, allow_indexed: bool) -> Result<Param, String> {
    if p.is_empty() { return Err("empty_param".into()); }
    // type is either a parenthesised tuple (+suffix) or the first whitespace-delimited word
    let (tystr, rest) = if p.starts_with('(') || p.starts_with("tuple(") {
        let o = p.find('(').unwrap();
        let c = matching(p, o).ok_or("unbalanced_parens")?;
        let end = c + 1 + p[c + 1..].find(|ch: char| ch.is_whitespace()).unwrap_or(p.len() - c - 1);
        (&p[..end], p[end..].trim())
    } else {
        let end = p.find(char::is_whitespace).unwrap_or(p.len());
        (&p[..end], p[end..].trim())
    };
    let ty = Ty::parse(tystr)?;
    let mut indexed = false; let mut name = String::new();
    for w in rest.split_whitespace() {
        match w {
            "indexed" if allow_indexed => indexed = true,
            "memory" | "calldata" | "storage" | "payable" => {}
            _ if name.is_empty() && valid_ident(w) => name = w.to_string(),
            _ => return Err("bad_param".into()),
        }
    }
    Ok(Param { name, ty, indexed })
}
