//! EIP-4361 (Sign-In with Ethereum) messages: build one from fields and parse one strictly.
//! The ABNF is EIP-4361's (domain = RFC 3986 authority with an optional `scheme://`, URI/resources =
//! RFC 3986 URI, address = EIP-55, nonce = 8+ alphanumerics, times = RFC 3339 date-time). Parsing is
//! canonical: the text must equal what `render` prints for the parsed fields, byte for byte (no CR,
//! no trailing newline, no extra spaces), so one set of fields has exactly one accepted text.
//! No keys, no signatures: pair it with msg-verify (EIP-191 personal_sign) to check who signed.
use serde_json::{json, Map, Value};

pub const HEADER: &str = " wants you to sign in with your Ethereum account:";

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Siwe {
    pub scheme: Option<String>,
    pub domain: String,
    pub address: String,
    pub statement: Option<String>,
    pub uri: String,
    pub version: String,
    pub chain_id: u64,
    pub nonce: String,
    pub issued_at: String,
    pub expiration_time: Option<String>,
    pub not_before: Option<String>,
    pub request_id: Option<String>,
    pub resources: Option<Vec<String>>,
}

fn unres(c: u8) -> bool { c.is_ascii_alphanumeric() || b"-._~".contains(&c) }
fn subd(c: u8) -> bool { b"!$&'()*+,;=".contains(&c) }
/// Every byte is unreserved, a sub-delim, one of `extra`, or part of a %HH escape.
fn chars_ok(s: &str, extra: &[u8]) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'%' {
            if i + 2 >= b.len() { return false }
            if !(b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit()) { return false }
            i += 3; continue
        }
        if !(unres(c) || subd(c) || extra.contains(&c)) { return false }
        i += 1
    }
    true
}
pub fn scheme_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b[0].is_ascii_alphabetic() && b.iter().all(|c| c.is_ascii_alphanumeric() || b"+-.".contains(c))
}
fn ipv4_ok(s: &str, leading_zeros: bool) -> bool {
    let p: Vec<&str> = s.split('.').collect();
    p.len() == 4 && p.iter().all(|o| !o.is_empty() && o.len() <= 3 && o.bytes().all(|c| c.is_ascii_digit())
        && o.parse::<u16>().map(|v| v <= 255).unwrap_or(false) && (leading_zeros || o.len() == 1 || !o.starts_with('0')))
}
fn h16(s: &str) -> bool { !s.is_empty() && s.len() <= 4 && s.bytes().all(|c| c.is_ascii_hexdigit()) }
/// RFC 3986 IPv6address (with an embedded IPv4 as the last 32 bits).
pub fn ipv6_ok(s: &str) -> bool {
    let units = |part: &str, last: bool| -> Option<usize> {
        if part.is_empty() { return Some(0) }
        let g: Vec<&str> = part.split(':').collect();
        let mut n = 0;
        for (i, x) in g.iter().enumerate() {
            if last && i == g.len() - 1 && x.contains('.') { if !ipv4_ok(x, true) { return None } n += 2 }
            else if h16(x) { n += 1 } else { return None }
        }
        Some(n)
    };
    match s.matches("::").count() {
        0 => units(s, true) == Some(8),
        1 => {
            let (a, b) = s.split_once("::").unwrap();
            if a.contains('.') { return false }
            match (units(a, false), units(b, true)) { (Some(x), Some(y)) => x + y <= 7, _ => false }
        }
        _ => false,
    }
}
fn host_ok(h: &str) -> bool {
    if let Some(inner) = h.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        if let Some(f) = inner.strip_prefix('v').or_else(|| inner.strip_prefix('V')) {
            let Some((hx, rest)) = f.split_once('.') else { return false };
            return h16(hx) || (!hx.is_empty() && hx.bytes().all(|c| c.is_ascii_hexdigit()))
                && !rest.is_empty() && rest.bytes().all(|c| unres(c) || subd(c) || c == b':');
        }
        return ipv6_ok(inner)
    }
    chars_ok(h, b"")
}
/// RFC 3986 authority = [ userinfo "@" ] host [ ":" port ]. `need_host`: the host must be non-empty.
pub fn authority_ok(a: &str, need_host: bool) -> bool {
    let (ui, hp) = match a.split_once('@') { Some((u, r)) => (Some(u), r), None => (None, a) };
    if ui.is_some_and(|u| !chars_ok(u, b":")) { return false }
    let (host, port) = if hp.starts_with('[') {
        let Some(e) = hp.find(']') else { return false };
        let rest = &hp[e + 1..];
        match rest { "" => (hp, None), r if r.starts_with(':') => (&hp[..=e], Some(&r[1..])), _ => return false }
    } else {
        match hp.split_once(':') { Some((h, p)) => (h, Some(p)), None => (hp, None) }
    };
    if port.is_some_and(|p| !p.bytes().all(|c| c.is_ascii_digit())) { return false }
    host_ok(host) && !(need_host && host.is_empty())
}
/// RFC 3986 URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ].
pub fn uri_ok(u: &str) -> bool {
    let Some((sch, rest)) = u.split_once(':') else { return false };
    if !scheme_ok(sch) { return false }
    let (rest, frag) = match rest.split_once('#') { Some((r, f)) => (r, Some(f)), None => (rest, None) };
    let (hier, q) = match rest.split_once('?') { Some((r, q)) => (r, Some(q)), None => (rest, None) };
    if frag.is_some_and(|f| !chars_ok(f, b":@/?")) || q.is_some_and(|q| !chars_ok(q, b":@/?")) { return false }
    if let Some(h) = hier.strip_prefix("//") {
        let (auth, path) = match h.find('/') { Some(i) => (&h[..i], &h[i..]), None => (h, "") };
        authority_ok(auth, false) && chars_ok(path, b":@/")
    } else {
        chars_ok(hier, b":@/")
    }
}
fn days_in(y: i64, m: i64) -> i64 {
    match m { 1 | 3 | 5 | 7 | 8 | 10 | 12 => 31, 4 | 6 | 9 | 11 => 30, _ => if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 { 29 } else { 28 } }
}
/// RFC 3339 date-time (uppercase T and Z, seconds 00-59, fraction optional) -> unix milliseconds.
pub fn rfc3339_ms(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = s.get(r)?; if t.bytes().all(|c| c.is_ascii_digit()) { t.parse().ok() } else { None }
    };
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' { return None }
    let (y, mo, d, h, mi, se) = (num(0..4)?, num(5..7)?, num(8..10)?, num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || d < 1 || d > days_in(y, mo) || h > 23 || mi > 59 || se > 59 { return None }
    let mut i = 19;
    let mut ms = 0i64;
    if b[i] == b'.' {
        let st = i + 1; i = st;
        while i < b.len() && b[i].is_ascii_digit() { i += 1 }
        if i == st { return None }
        let f = &s[st..i];
        ms = format!("{:0<3}", &f[..f.len().min(3)]).parse().ok()?;
    }
    let off = match &s[i..] {
        "Z" => 0,
        o if o.len() == 6 && (o.starts_with('+') || o.starts_with('-')) && o.as_bytes()[3] == b':' => {
            let (oh, om) = (num(i + 1..i + 3)?, num(i + 4..i + 6)?);
            if oh > 23 || om > 59 { return None }
            let v = oh * 60 + om; if o.starts_with('-') { -v } else { v }
        }
        _ => return None,
    };
    // days from civil (Howard Hinnant)
    let (yy, mm) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * mm + 2) / 5 + d - 1;
    let days = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
    Some(((days * 24 + h) * 60 + mi - off) * 60_000 + se * 1000 + ms)
}
fn eip55_ok(a: &str) -> bool {
    a.len() == 42 && a.starts_with("0x") && blocktools_core::hex_dec(&a[2..]).is_some_and(|b| blocktools_core::validate::checksum_eth(&b) == a)
}
fn statement_ok(s: &str) -> bool { s.bytes().all(|c| unres(c) || subd(c) || b":/?#[]@ ".contains(&c)) }
fn nonce_ok(n: &str) -> bool { n.len() >= 8 && n.bytes().all(|c| c.is_ascii_alphanumeric()) }

impl Siwe {
    /// Field checks shared by build and parse. Err = a stable reason code.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.scheme.as_deref().is_some_and(|s| !scheme_ok(s)) { return Err("bad_scheme") }
        if !authority_ok(&self.domain, true) { return Err("bad_domain") }
        if !eip55_ok(&self.address) { return Err("address_not_eip55") }
        if self.statement.as_deref().is_some_and(|s| !statement_ok(s)) { return Err("bad_statement") }
        if !uri_ok(&self.uri) { return Err("bad_uri") }
        if self.version != "1" { return Err("bad_version") }
        if !nonce_ok(&self.nonce) { return Err("bad_nonce") }
        if rfc3339_ms(&self.issued_at).is_none() { return Err("bad_issued_at") }
        if self.expiration_time.as_deref().is_some_and(|t| rfc3339_ms(t).is_none()) { return Err("bad_expiration_time") }
        if self.not_before.as_deref().is_some_and(|t| rfc3339_ms(t).is_none()) { return Err("bad_not_before") }
        if self.request_id.as_deref().is_some_and(|r| !chars_ok(r, b":@")) { return Err("bad_request_id") }
        if self.resources.as_ref().is_some_and(|r| r.iter().any(|u| !uri_ok(u))) { return Err("bad_resource") }
        Ok(())
    }
    /// The EIP-4361 text (no trailing newline).
    pub fn render(&self) -> String {
        let mut s = String::new();
        if let Some(sc) = &self.scheme { s += sc; s += "://" }
        s += &self.domain; s += HEADER; s += "\n"; s += &self.address; s += "\n\n";
        if let Some(st) = &self.statement { s += st; s += "\n" }
        s += &format!("\nURI: {}\nVersion: {}\nChain ID: {}\nNonce: {}\nIssued At: {}", self.uri, self.version, self.chain_id, self.nonce, self.issued_at);
        if let Some(t) = &self.expiration_time { s += "\nExpiration Time: "; s += t }
        if let Some(t) = &self.not_before { s += "\nNot Before: "; s += t }
        if let Some(t) = &self.request_id { s += "\nRequest ID: "; s += t }
        if let Some(r) = &self.resources { s += "\nResources:"; for u in r { s += "\n- "; s += u } }
        s
    }
    /// Strict parse: fields must be valid and the text must equal `render()` exactly.
    pub fn parse(text: &str) -> Result<Siwe, &'static str> {
        if text.contains('\r') || text.ends_with('\n') || text.starts_with(char::is_whitespace) { return Err("non_canonical") }
        let l: Vec<&str> = text.split('\n').collect();
        let head = l[0].strip_suffix(HEADER).ok_or("bad_header")?;
        let (scheme, domain) = match head.split_once("://") { Some((s, d)) => (Some(s.to_string()), d), None => (None, head) };
        let mut m = Siwe { scheme, domain: domain.to_string(), ..Default::default() };
        m.address = l.get(1).ok_or("missing_address")?.to_string();
        if l.get(2) != Some(&"") { return Err("non_canonical") }
        let mut i = if l.get(3) == Some(&"") && l.get(4).is_some_and(|x| x.starts_with("URI: ")) { 4 } else {
            m.statement = Some(l.get(3).ok_or("missing_uri")?.to_string());
            if l.get(4) != Some(&"") { return Err("bad_statement") }
            5
        };
        let mut take = |tag: &str, need: bool| -> Result<Option<String>, &'static str> {
            match l.get(i).and_then(|x| x.strip_prefix(tag)) {
                Some(v) => { i += 1; Ok(Some(v.to_string())) }
                None if need => Err(match tag { "URI: " => "missing_uri", "Version: " => "missing_version", "Chain ID: " => "missing_chain_id", "Nonce: " => "missing_nonce", _ => "missing_issued_at" }),
                None => Ok(None),
            }
        };
        m.uri = take("URI: ", true)?.unwrap();
        m.version = take("Version: ", true)?.unwrap();
        let cid = take("Chain ID: ", true)?.unwrap();
        m.nonce = take("Nonce: ", true)?.unwrap();
        m.issued_at = take("Issued At: ", true)?.unwrap();
        m.expiration_time = take("Expiration Time: ", false)?;
        m.not_before = take("Not Before: ", false)?;
        m.request_id = take("Request ID: ", false)?;
        if l.get(i) == Some(&"Resources:") {
            i += 1;
            let mut r = vec![];
            while let Some(x) = l.get(i).and_then(|x| x.strip_prefix("- ")) { r.push(x.to_string()); i += 1 }
            m.resources = Some(r);
        }
        if i != l.len() { return Err("unexpected_line") }
        if cid.is_empty() || !cid.bytes().all(|c| c.is_ascii_digit()) { return Err("bad_chain_id") }
        m.chain_id = cid.parse().map_err(|_| "bad_chain_id")?;
        m.validate()?;
        if m.render() != text { return Err("non_canonical") }
        Ok(m)
    }
    /// JSON fields with siwe's (spruceid) camelCase names; absent optionals are omitted.
    pub fn to_json(&self) -> Value {
        let mut o = Map::new();
        let mut put = |k: &str, v: Value| { o.insert(k.into(), v); };
        if let Some(s) = &self.scheme { put("scheme", json!(s)) }
        put("domain", json!(self.domain)); put("address", json!(self.address));
        if let Some(s) = &self.statement { put("statement", json!(s)) }
        put("uri", json!(self.uri)); put("version", json!(self.version)); put("chainId", json!(self.chain_id));
        put("nonce", json!(self.nonce)); put("issuedAt", json!(self.issued_at));
        if let Some(s) = &self.expiration_time { put("expirationTime", json!(s)) }
        if let Some(s) = &self.not_before { put("notBefore", json!(s)) }
        if let Some(s) = &self.request_id { put("requestId", json!(s)) }
        if let Some(r) = &self.resources { put("resources", json!(r)) }
        Value::Object(o)
    }
    /// From the same JSON names. Unknown keys and wrong types are errors; null = absent.
    pub fn from_json(v: &Value) -> Result<Siwe, String> {
        let o = v.as_object().ok_or("fields must be a JSON object")?;
        const KEYS: [&str; 13] = ["scheme", "domain", "address", "statement", "uri", "version", "chainId", "nonce", "issuedAt", "expirationTime", "notBefore", "requestId", "resources"];
        if let Some(k) = o.keys().find(|k| !KEYS.contains(&k.as_str())) { return Err(format!("unknown field {k}")) }
        let s = |k: &str| -> Result<Option<String>, String> {
            match o.get(k) { None | Some(Value::Null) => Ok(None), Some(Value::String(x)) => Ok(Some(x.clone())), _ => Err(format!("{k} must be a string")) }
        };
        let req = |k: &str| -> Result<String, String> { s(k)?.ok_or(format!("missing {k}")) };
        let chain_id = match o.get("chainId") { Some(Value::Number(n)) => n.as_u64().ok_or("chainId must be a non-negative integer")?, None | Some(Value::Null) => return Err("missing chainId".into()), _ => return Err("chainId must be a JSON integer".into()) };
        let resources = match o.get("resources") {
            None | Some(Value::Null) => None,
            Some(Value::Array(a)) => Some(a.iter().map(|x| x.as_str().map(String::from).ok_or("resources must be strings".to_string())).collect::<Result<_, _>>()?),
            _ => return Err("resources must be an array".into()),
        };
        Ok(Siwe { scheme: s("scheme")?, domain: req("domain")?, address: req("address")?, statement: s("statement")?, uri: req("uri")?,
            version: req("version")?, chain_id, nonce: req("nonce")?, issued_at: req("issuedAt")?,
            expiration_time: s("expirationTime")?, not_before: s("notBefore")?, request_id: s("requestId")?, resources })
    }
}
