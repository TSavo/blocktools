//! Solidity ABI types, a strict decoder and an encoder (Solidity ABI spec, "Formal Specification
//! of the Encoding"). The decoder is bounds-checked and refuses non-canonical padding (dirty high
//! bits, bool not 0/1, nonzero tail padding), offsets outside the data, lengths that cannot fit,
//! nesting deeper than 32 and more than 100,000 decoded values (pointer aliasing blow-up).
use crate::u256::{self, Word};
use crate::{checksum_address, hex, parse_address, unhex};
use serde_json::{json, Value};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ty {
    Uint(usize),
    Int(usize),
    Address,
    Bool,
    FixedBytes(usize),
    Bytes,
    String,
    Array(Box<Ty>, Option<usize>),
    Tuple(Vec<Param>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Param { pub name: String, pub ty: Ty, pub indexed: bool }

impl Param { pub fn new(ty: Ty) -> Param { Param { name: String::new(), ty, indexed: false } } }

const MAX_DEPTH: usize = 32;
const MAX_VALUES: usize = 100_000;
const MAX_FIXED_ARRAY: usize = 1 << 16;

impl Ty {
    pub fn parse(s: &str) -> Result<Ty, String> {
        let s = s.trim();
        if s.starts_with('(') || s.starts_with("tuple(") {
            let o = s.find('(').unwrap();
            let c = crate::sig::matching(s, o).ok_or("unbalanced_parens")?;
            let inner = crate::sig::parse_params(&s[o + 1..c], false)?;
            return Ty::with_suffix(Ty::Tuple(inner), &s[c + 1..]);
        }
        let b = s.find('[').unwrap_or(s.len());
        let base = match &s[..b] {
            "address" => Ty::Address,
            "bool" => Ty::Bool,
            "string" => Ty::String,
            "bytes" => Ty::Bytes,
            "uint" => Ty::Uint(256),
            "int" => Ty::Int(256),
            "function" => Ty::FixedBytes(24),
            t => {
                let num = |r: &str| r.parse::<usize>().ok().filter(|_| !r.starts_with('0'));
                if let Some(m) = t.strip_prefix("uint").and_then(num) {
                    if m == 0 || m > 256 || m % 8 != 0 { return Err(format!("bad_type:{t}")); }
                    Ty::Uint(m)
                } else if let Some(m) = t.strip_prefix("int").and_then(num) {
                    if m == 0 || m > 256 || m % 8 != 0 { return Err(format!("bad_type:{t}")); }
                    Ty::Int(m)
                } else if let Some(m) = t.strip_prefix("bytes").and_then(num) {
                    if m == 0 || m > 32 { return Err(format!("bad_type:{t}")); }
                    Ty::FixedBytes(m)
                } else {
                    return Err(format!("bad_type:{t}"));
                }
            }
        };
        Ty::with_suffix(base, &s[b..])
    }

    pub(crate) fn with_suffix(mut t: Ty, mut suf: &str) -> Result<Ty, String> {
        suf = suf.trim();
        while !suf.is_empty() {
            if !suf.starts_with('[') { return Err("bad_array_suffix".into()); }
            let c = suf.find(']').ok_or("bad_array_suffix")?;
            let n = &suf[1..c];
            let len = if n.is_empty() { None } else {
                let k: usize = n.parse().map_err(|_| "bad_array_suffix")?;
                if k == 0 || k > MAX_FIXED_ARRAY { return Err("bad_array_length".into()); }
                Some(k)
            };
            t = Ty::Array(Box::new(t), len);
            suf = suf[c + 1..].trim_start();
        }
        Ok(t)
    }

    pub fn canon(&self) -> String {
        match self {
            Ty::Uint(m) => format!("uint{m}"),
            Ty::Int(m) => format!("int{m}"),
            Ty::Address => "address".into(),
            Ty::Bool => "bool".into(),
            Ty::FixedBytes(m) => format!("bytes{m}"),
            Ty::Bytes => "bytes".into(),
            Ty::String => "string".into(),
            Ty::Array(t, None) => format!("{}[]", t.canon()),
            Ty::Array(t, Some(k)) => format!("{}[{k}]", t.canon()),
            Ty::Tuple(ps) => format!("({})", ps.iter().map(|p| p.ty.canon()).collect::<Vec<_>>().join(",")),
        }
    }

    pub fn is_dynamic(&self) -> bool {
        match self {
            Ty::Bytes | Ty::String | Ty::Array(_, None) => true,
            Ty::Array(t, Some(_)) => t.is_dynamic(),
            Ty::Tuple(ps) => ps.iter().any(|p| p.ty.is_dynamic()),
            _ => false,
        }
    }

    /// Bytes this type occupies in a head (32 for dynamic types).
    pub fn head_size(&self) -> usize {
        if self.is_dynamic() { return 32; }
        match self {
            Ty::Array(t, Some(k)) => t.head_size().saturating_mul(*k),
            Ty::Tuple(ps) => ps.iter().map(|p| p.ty.head_size()).fold(0usize, |a, b| a.saturating_add(b)),
            _ => 32,
        }
    }
}

/// Parse a type list: `(uint256,address)`, `uint256,address` or `uint256`.
pub fn parse_types(s: &str) -> Result<Vec<Param>, String> {
    let s = s.trim();
    if s.starts_with('(') && crate::sig::matching(s, 0) == Some(s.len() - 1) {
        return crate::sig::parse_params(&s[1..s.len() - 1], false);
    }
    crate::sig::parse_params(s, false)
}

// ---------------------------------------------------------------- decode

struct Dec<'a> { d: &'a [u8], count: usize }

impl<'a> Dec<'a> {
    fn word(&self, at: usize) -> Result<&'a [u8], String> {
        self.d.get(at..at.checked_add(32).ok_or("offset_overflow")?).ok_or_else(|| "data_too_short".to_string()).map(|w| w)
    }
    fn usize_at(&self, at: usize) -> Result<usize, String> {
        let w = self.word(at)?;
        if w[..24].iter().any(|&b| b != 0) { return Err("offset_or_length_too_large".into()); }
        let v = u64::from_be_bytes(w[24..].try_into().unwrap());
        if v > self.d.len() as u64 { return Err("offset_or_length_out_of_bounds".into()); }
        Ok(v as usize)
    }
    fn tick(&mut self) -> Result<(), String> {
        self.count += 1;
        if self.count > MAX_VALUES { Err("too_many_values".into()) } else { Ok(()) }
    }

    fn tuple(&mut self, ts: &[&Ty], base: usize, depth: usize) -> Result<Vec<Value>, String> {
        if depth > MAX_DEPTH { return Err("too_deep".into()); }
        let mut head = base;
        let mut out = Vec::with_capacity(ts.len());
        for t in ts {
            if t.is_dynamic() {
                let off = self.usize_at(head)?;
                let at = base.checked_add(off).filter(|&a| a <= self.d.len()).ok_or("offset_out_of_bounds")?;
                out.push(self.value(t, at, depth + 1)?);
                head += 32;
            } else {
                out.push(self.value(t, head, depth + 1)?);
                head = head.checked_add(t.head_size()).ok_or("offset_overflow")?;
            }
        }
        Ok(out)
    }

    fn value(&mut self, t: &Ty, at: usize, depth: usize) -> Result<Value, String> {
        self.tick()?;
        Ok(match t {
            Ty::Uint(m) => {
                let w: Word = self.word(at)?.try_into().unwrap();
                if u256::bits(&w) > *m { return Err(format!("dirty_uint{m}")); }
                json!(u256::to_dec(&w))
            }
            Ty::Int(m) => {
                let w: Word = self.word(at)?.try_into().unwrap();
                let pad = 32 - m / 8;
                let sign = if w[pad] & 0x80 != 0 { 0xff } else { 0 };
                if w[..pad].iter().any(|&b| b != sign) { return Err(format!("dirty_int{m}")); }
                json!(u256::int_to_dec(&w))
            }
            Ty::Address => {
                let w = self.word(at)?;
                if w[..12].iter().any(|&b| b != 0) { return Err("dirty_address".into()); }
                json!(checksum_address(w[12..].try_into().unwrap()))
            }
            Ty::Bool => {
                let w = self.word(at)?;
                if w[..31].iter().any(|&b| b != 0) || w[31] > 1 { return Err("dirty_bool".into()); }
                json!(w[31] == 1)
            }
            Ty::FixedBytes(m) => {
                let w = self.word(at)?;
                if w[*m..].iter().any(|&b| b != 0) { return Err(format!("dirty_bytes{m}")); }
                json!(hex(&w[..*m]))
            }
            Ty::Bytes | Ty::String => {
                let n = self.usize_at(at)?;
                let st = at + 32;
                let body = self.d.get(st..st + n).ok_or("bytes_out_of_bounds")?;
                let padded = n.div_ceil(32) * 32;
                let pad = self.d.get(st + n..st + padded).ok_or("bytes_padding_missing")?;
                if pad.iter().any(|&b| b != 0) { return Err("dirty_bytes_padding".into()); }
                if *t == Ty::String {
                    json!(std::str::from_utf8(body).map_err(|_| "string_not_utf8")?)
                } else { json!(hex(body)) }
            }
            Ty::Array(e, None) => {
                let n = self.usize_at(at)?;
                // every element needs at least one word of head after the length word
                if n.saturating_mul(32) > self.d.len().saturating_sub(at + 32) && e.head_size() > 0 { return Err("array_length_out_of_bounds".into()); }
                let ts: Vec<&Ty> = std::iter::repeat_n(&**e, n).collect();
                Value::Array(self.tuple(&ts, at + 32, depth)?)
            }
            Ty::Array(e, Some(k)) => {
                let ts: Vec<&Ty> = std::iter::repeat_n(&**e, *k).collect();
                Value::Array(self.tuple(&ts, at, depth)?)
            }
            Ty::Tuple(ps) => {
                let ts: Vec<&Ty> = ps.iter().map(|p| &p.ty).collect();
                Value::Array(self.tuple(&ts, at, depth)?)
            }
        })
    }
}

/// Decode `data` as the ABI encoding of the tuple `params`. Returns (values, bytes consumed by the heads).
pub fn decode(params: &[Param], data: &[u8]) -> Result<Vec<Value>, String> {
    let ts: Vec<&Ty> = params.iter().map(|p| &p.ty).collect();
    Dec { d: data, count: 0 }.tuple(&ts, 0, 0)
}

/// Decode one 32-byte word (an indexed event topic) as a static type.
pub fn decode_word(t: &Ty, w: &[u8]) -> Result<Value, String> {
    Dec { d: w, count: 0 }.value(t, 0, 0)
}

/// Pair decoded values with their params: `[{name?, type, value}]`.
pub fn labelled(params: &[Param], vals: Vec<Value>) -> Value {
    Value::Array(params.iter().zip(vals).map(|(p, v)| {
        let mut o = json!({"type": p.ty.canon(), "value": v});
        if !p.name.is_empty() { o["name"] = json!(p.name); }
        if let Ty::Tuple(_) = p.ty { o["components"] = components(&p.ty); }
        o
    }).collect())
}

fn components(t: &Ty) -> Value {
    match t {
        Ty::Tuple(ps) => Value::Array(ps.iter().map(|p| json!({"name": p.name, "type": p.ty.canon()})).collect()),
        _ => Value::Null,
    }
}

// ---------------------------------------------------------------- encode

fn s_of(v: &Value) -> Result<String, String> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) if n.is_u64() || n.is_i64() => Ok(n.to_string()),
        Value::Number(_) => Err("number_not_integer_use_a_string".into()),
        Value::Bool(b) => Ok(b.to_string()),
        _ => Err("expected_scalar".into()),
    }
}

fn arr_of<'a>(v: &'a Value, owned: &'a mut Option<Value>) -> Result<&'a Vec<Value>, String> {
    if let Value::String(s) = v {
        *owned = Some(serde_json::from_str(s).map_err(|_| "expected_json_array")?);
        return owned.as_ref().unwrap().as_array().ok_or_else(|| "expected_json_array".to_string());
    }
    v.as_array().ok_or_else(|| "expected_json_array".to_string())
}

fn enc_tuple(ts: &[&Ty], vs: &[Value], depth: usize) -> Result<Vec<u8>, String> {
    if depth > MAX_DEPTH { return Err("too_deep".into()); }
    if ts.len() != vs.len() { return Err(format!("expected_{}_values_got_{}", ts.len(), vs.len())); }
    let head_len: usize = ts.iter().map(|t| t.head_size()).sum();
    let mut head = Vec::with_capacity(head_len);
    let mut tail = vec![];
    for (t, v) in ts.iter().zip(vs) {
        let e = enc_value(t, v, depth + 1)?;
        if t.is_dynamic() {
            let mut w = [0u8; 32];
            w[24..].copy_from_slice(&((head_len + tail.len()) as u64).to_be_bytes());
            head.extend_from_slice(&w);
            tail.extend(e);
        } else { head.extend(e); }
    }
    head.extend(tail);
    Ok(head)
}

fn len_word(n: usize) -> [u8; 32] { let mut w = [0u8; 32]; w[24..].copy_from_slice(&(n as u64).to_be_bytes()); w }

fn enc_value(t: &Ty, v: &Value, depth: usize) -> Result<Vec<u8>, String> {
    Ok(match t {
        Ty::Uint(m) => {
            let w = u256::parse_uint(&s_of(v)?)?;
            if u256::bits(&w) > *m { return Err(format!("value_too_large_for_uint{m}")); }
            w.to_vec()
        }
        Ty::Int(m) => u256::parse_int(&s_of(v)?, *m)?.to_vec(),
        Ty::Address => { let a = parse_address(&s_of(v)?)?; let mut w = vec![0u8; 12]; w.extend(a); w }
        Ty::Bool => {
            let b = match v { Value::Bool(b) => *b, _ => match s_of(v)?.as_str() { "true" | "1" => true, "false" | "0" => false, _ => return Err("bad_bool".into()) } };
            let mut w = vec![0u8; 32]; w[31] = b as u8; w
        }
        Ty::FixedBytes(m) => {
            let b = unhex(&s_of(v)?)?;
            if b.len() != *m { return Err(format!("bytes{m}_needs_{m}_bytes")); }
            let mut w = b; w.resize(32, 0); w
        }
        Ty::Bytes | Ty::String => {
            let s = s_of(v)?;
            let b = if *t == Ty::Bytes { unhex(&s)? } else { s.into_bytes() };
            let mut w = len_word(b.len()).to_vec();
            let n = b.len();
            w.extend(b); w.resize(32 + n.div_ceil(32) * 32, 0); w
        }
        Ty::Array(e, k) => {
            let mut o = None;
            let a = arr_of(v, &mut o)?;
            if let Some(k) = k { if a.len() != *k { return Err(format!("expected_{k}_elements")); } }
            let ts: Vec<&Ty> = std::iter::repeat_n(&**e, a.len()).collect();
            let body = enc_tuple(&ts, a, depth)?;
            if k.is_none() { let mut w = len_word(a.len()).to_vec(); w.extend(body); w } else { body }
        }
        Ty::Tuple(ps) => {
            let mut o = None;
            let a = arr_of(v, &mut o)?;
            let ts: Vec<&Ty> = ps.iter().map(|p| &p.ty).collect();
            enc_tuple(&ts, a, depth)?
        }
    })
}

/// ABI-encode `vals` as the tuple `params`. Arrays/tuples take JSON arrays (or a JSON string of one);
/// integers take decimal or 0x-hex strings (JSON numbers only up to 64 bits).
pub fn encode(params: &[Param], vals: &[Value]) -> Result<Vec<u8>, String> {
    let ts: Vec<&Ty> = params.iter().map(|p| &p.ty).collect();
    enc_tuple(&ts, vals, 0)
}

/// Solidity `abi.encodePacked` (non-standard packed mode, Solidity docs "Non-standard Packed Mode"):
/// types shorter than 32 bytes are concatenated at their own width, `bytes`/`string` are raw with no
/// length, array elements are padded to 32 bytes with no length prefix. Tuples, nested arrays and
/// arrays of dynamic types are refused (Solidity does not support them in packed mode).
pub fn encode_packed(params: &[Param], vals: &[Value]) -> Result<Vec<u8>, String> {
    if params.len() != vals.len() { return Err(format!("expected_{}_values_got_{}", params.len(), vals.len())); }
    let mut out = vec![];
    for (p, v) in params.iter().zip(vals) {
        match &p.ty {
            Ty::Tuple(_) => return Err("packed_tuple_unsupported".into()),
            Ty::Array(e, k) => {
                if matches!(**e, Ty::Array(..) | Ty::Tuple(_)) || e.is_dynamic() { return Err("packed_array_element_must_be_static_elementary".into()); }
                let mut o = None;
                let a = arr_of(v, &mut o)?;
                if let Some(k) = k { if a.len() != *k { return Err(format!("expected_{k}_elements")); } }
                for x in a { out.extend(enc_value(e, x, 1)?); }
            }
            Ty::Bytes | Ty::String => {
                let s = s_of(v)?;
                out.extend(if p.ty == Ty::Bytes { unhex(&s)? } else { s.into_bytes() });
            }
            t => {
                let w = enc_value(t, v, 1)?;
                let n = match t { Ty::Uint(m) | Ty::Int(m) => m / 8, Ty::Address => 20, Ty::Bool => 1, Ty::FixedBytes(m) => *m, _ => 32 };
                out.extend(if matches!(t, Ty::FixedBytes(_)) { &w[..n] } else { &w[32 - n..] });
            }
        }
    }
    Ok(out)
}
