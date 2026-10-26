//! Custom chain spec: a JSON file that registers ONE extra UTXO chain for this process only
//! (`--chain-spec FILE` or `BLOCKTOOLS_CHAIN_SPEC=FILE`; nothing is persisted). docs/CHAIN-SPEC.md.
//!
//! The spec is unverified by construction. It cannot weaken anything: the default UTXO fee cap
//! and every verifier rule apply, only `sign: "standard"` with 8 decimals is ever built or signed,
//! and a name that is already in the table is always refused. A spec whose address bytes (or
//! hrp) overlap a built-in chain is refused unless the file itself says `"allow_collision": true`.
//! Any field the human did not supply is "unknown"; tools refuse only the steps that need it,
//! with a stable code naming it (`spec_missing_wif`, `spec_missing_p2sh`, ...). The file never
//! holds a secret: a value that decodes as a WIF/private key is refused (`spec_contains_secret`).
use crate::chains::{Chain, Enc, Sign, CHAINS};
use std::sync::OnceLock;

pub const FORMAT: &str = "blocktools-chain-spec/1";
pub const ENV: &str = "BLOCKTOOLS_CHAIN_SPEC";
/// Fields a spec may carry. Anything else is `spec_unknown_field` (typos must not pass silently).
pub const FIELDS: &[&str] = &["format", "name", "ticker", "title", "p2pkh", "p2sh", "wif", "hrp", "slip44", "checksum", "sign", "decimals", "allow_collision", "evidence"];

/// A field's state: Known(v), None = "known to be absent" (JSON null; only hrp/slip44), Unknown.
#[derive(Clone, Debug, PartialEq)]
pub enum F<T> { Known(T), Absent, Unknown }
impl<T: Clone> F<T> { pub fn get(&self) -> Option<T> { if let F::Known(v) = self { Some(v.clone()) } else { None } } pub fn unknown(&self) -> bool { matches!(self, F::Unknown) } }

#[derive(Clone, Debug)]
pub struct Spec {
    pub name: String, pub ticker: F<String>, pub title: String,
    pub p2pkh: F<u8>, pub p2sh: F<u8>, pub wif: F<u8>, pub hrp: F<String>, pub slip44: F<u32>,
    pub checksum: String, pub sign: String, pub decimals: F<u32>, pub allow_collision: bool,
    /// Built-in chains whose bytes this spec shares (only non-empty when allow_collision).
    pub collisions: Vec<&'static str>,
    /// sha256 of the file bytes, shown next to "unverified chain spec".
    pub sha256: String,
}

// ---------- strict, minimal JSON (one object; values: string, integer, true/false/null, one nested object of strings) ----------
#[derive(Clone, Debug, PartialEq)]
pub enum V { S(String), N(u64), B(bool), Null, Obj(Vec<(String, V)>) }
struct P<'a> { b: &'a [u8], i: usize }
impl P<'_> {
    fn ws(&mut self) { while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') { self.i += 1 } }
    fn eat(&mut self, c: u8) -> Result<(), &'static str> { self.ws(); if self.b.get(self.i) == Some(&c) { self.i += 1; Ok(()) } else { Err("spec_malformed") } }
    fn s(&mut self) -> Result<String, &'static str> {
        self.eat(b'"')?; let st = self.i;
        while self.i < self.b.len() && self.b[self.i] != b'"' { if self.b[self.i] == b'\\' || self.b[self.i] < 0x20 { return Err("spec_malformed") } self.i += 1 }
        let v = std::str::from_utf8(&self.b[st..self.i]).map_err(|_| "spec_malformed")?.to_string(); self.eat(b'"')?; Ok(v)
    }
    fn v(&mut self, depth: u8) -> Result<V, &'static str> {
        self.ws();
        match self.b.get(self.i) {
            Some(b'"') => self.s().map(V::S),
            Some(b'{') if depth == 0 => self.obj(1).map(V::Obj),
            Some(c) if c.is_ascii_digit() => { let st = self.i; while self.i < self.b.len() && self.b[self.i].is_ascii_digit() { self.i += 1 }
                if self.i - st > 10 { return Err("spec_bad_value") } std::str::from_utf8(&self.b[st..self.i]).unwrap().parse().map(V::N).map_err(|_| "spec_bad_value") }
            _ => {
                for (w, v) in [("true", V::B(true)), ("false", V::B(false)), ("null", V::Null)] {
                    if self.b[self.i..].starts_with(w.as_bytes()) { self.i += w.len(); return Ok(v) }
                }
                Err("spec_malformed")
            }
        }
    }
    fn obj(&mut self, depth: u8) -> Result<Vec<(String, V)>, &'static str> {
        self.eat(b'{')?; let mut o: Vec<(String, V)> = vec![]; self.ws();
        if self.b.get(self.i) == Some(&b'}') { self.i += 1; return Ok(o) }
        loop {
            let k = self.s()?; self.eat(b':')?; let v = self.v(depth)?;
            if o.iter().any(|(x, _)| *x == k) { return Err("spec_duplicate_field") }
            if o.len() >= 64 { return Err("spec_malformed") }
            o.push((k, v)); self.ws();
            match self.b.get(self.i) { Some(b',') => self.i += 1, Some(b'}') => { self.i += 1; return Ok(o) } _ => return Err("spec_malformed") }
        }
    }
}
pub fn parse_json(s: &str) -> Result<Vec<(String, V)>, &'static str> {
    let mut p = P { b: s.as_bytes(), i: 0 };
    let o = p.obj(0)?; p.ws(); if p.i != p.b.len() { return Err("spec_malformed") } Ok(o)
}

fn looks_secret(s: &str) -> bool {
    // WIF (33/34-byte base58check payload) or 64-hex private key: a spec never needs one.
    let t = s.trim();
    (t.len() >= 50 && t.len() <= 53 && bitcoin::base58::decode_check(t).map_or(false, |b| b.len() == 33 || b.len() == 34))
        || (t.len() == 64 && t.bytes().all(|c| c.is_ascii_hexdigit()))
}
fn byte(v: Option<&V>) -> Result<F<u8>, &'static str> {
    match v { None => Ok(F::Unknown), Some(V::S(s)) if s == "unknown" => Ok(F::Unknown), Some(V::N(n)) if *n <= 255 => Ok(F::Known(*n as u8)), _ => Err("spec_bad_value") }
}

/// Parse and check a spec file's text. Never registers anything.
pub fn parse(text: &str) -> Result<Spec, &'static str> {
    if text.len() > 64 << 10 { return Err("spec_too_large") }
    let o = parse_json(text)?;
    let g = |k: &str| o.iter().find(|(x, _)| x == k).map(|(_, v)| v);
    for (k, v) in &o {
        if !FIELDS.contains(&k.as_str()) { return Err("spec_unknown_field") }
        let strs: Vec<&String> = match v { V::S(s) => vec![s], V::Obj(m) => m.iter().flat_map(|(a, b)| { let mut x = vec![a]; if let V::S(s) = b { x.push(s) } x }).collect(), _ => vec![] };
        if strs.iter().any(|s| looks_secret(s)) { return Err("spec_contains_secret") }
        if let V::Obj(m) = v { if k != "evidence" || m.iter().any(|(_, x)| !matches!(x, V::S(_))) { return Err("spec_bad_value") } }
    }
    if g("format") != Some(&V::S(FORMAT.into())) { return Err("spec_bad_format") }
    let name = match g("name") { Some(V::S(s)) => s.clone(), None => return Err("spec_missing_name"), _ => return Err("spec_bad_name") };
    if !(2..=12).contains(&name.len()) || !name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) || !name.as_bytes()[0].is_ascii_lowercase() { return Err("spec_bad_name") }
    if CHAINS.iter().any(|c| c.name == name) || name == "zec" || name == "all" { return Err("spec_name_collision") }
    let ticker = match g("ticker") { None => F::Unknown, Some(V::S(s)) if s == "unknown" => F::Unknown,
        Some(V::S(s)) if (1..=10).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) => F::Known(s.clone()), _ => return Err("spec_bad_value") };
    let title = match g("title") { None => name.clone(), Some(V::S(s)) if s.len() <= 64 && s.bytes().all(|c| c.is_ascii_graphic() || c == b' ') => s.clone(), _ => return Err("spec_bad_value") };
    let (p2pkh, p2sh, wif) = (byte(g("p2pkh"))?, byte(g("p2sh"))?, byte(g("wif"))?);
    let hrp = match g("hrp") { None => F::Unknown, Some(V::Null) => F::Absent, Some(V::S(s)) if s == "unknown" => F::Unknown,
        Some(V::S(s)) if (1..=16).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) && bitcoin::bech32::Hrp::parse(s).is_ok() => F::Known(s.clone()), _ => return Err("spec_bad_value") };
    let slip44 = match g("slip44") { None => F::Unknown, Some(V::Null) => F::Absent, Some(V::S(s)) if s == "unknown" => F::Unknown, Some(V::N(n)) if *n < 1 << 31 => F::Known(*n as u32), _ => return Err("spec_bad_value") };
    let checksum = match g("checksum") { Some(V::S(s)) if s == "sha256d" => s.clone(), None => return Err("spec_missing_checksum"), Some(V::S(s)) if s == "unknown" => return Err("spec_missing_checksum"), _ => return Err("spec_unsupported_checksum") };
    let sign = match g("sign") { None => "unknown".to_string(), Some(V::S(s)) if s.len() <= 24 && s.bytes().all(|c| c.is_ascii_lowercase() || c == b'-') => s.clone(), _ => return Err("spec_bad_value") };
    let decimals = match g("decimals") { None => F::Unknown, Some(V::S(s)) if s == "unknown" => F::Unknown, Some(V::N(n)) if *n <= 18 => F::Known(*n as u32), _ => return Err("spec_bad_value") };
    let allow_collision = match g("allow_collision") { None => false, Some(V::B(b)) => *b, _ => return Err("spec_bad_value") };
    if let (F::Known(a), F::Known(b)) = (&p2pkh, &p2sh) { if a == b { return Err("spec_bad_value") } }
    // Address-space overlap with the built-in table: same version byte (either kind) or same hrp.
    let mut collisions = vec![];
    for c in CHAINS {
        let Enc::Utxo { p2pkh: a, p2sh: b, hrp: h, .. } = c.enc else { continue };
        let mine = [p2pkh.get(), p2sh.get()];
        if mine.iter().flatten().any(|x| *x == a || *x == b) || (hrp.get().is_some() && hrp.get().as_deref() == h) { collisions.push(c.name) }
    }
    if !collisions.is_empty() && !allow_collision { return Err("spec_byte_collision") }
    let sha256 = { use bitcoin::hashes::{sha256, Hash}; sha256::Hash::hash(text.as_bytes()).to_string() };
    Ok(Spec { name, ticker, title, p2pkh, p2sh, wif, hrp, slip44, checksum, sign, decimals, allow_collision, collisions, sha256 })
}

/// Colliding built-in names for a rejected-on-collision spec (for error detail).
pub fn collisions_of(text: &str) -> Vec<&'static str> {
    // Re-parse with the flag forced on, only to name the colliding chains in the error.
    match parse_json(text) {
        Ok(mut o) => { o.retain(|(k, _)| k != "allow_collision"); o.push(("allow_collision".into(), V::B(true)));
            let s = to_json(&o); parse(&s).map(|x| x.collisions).unwrap_or_default() }
        Err(_) => vec![],
    }
}
fn to_json(o: &[(String, V)]) -> String {
    fn v(x: &V) -> String { match x { V::S(s) => format!("\"{s}\""), V::N(n) => n.to_string(), V::B(b) => b.to_string(), V::Null => "null".into(), V::Obj(m) => format!("{{{}}}", m.iter().map(|(k, x)| format!("\"{k}\":{}", v(x))).collect::<Vec<_>>().join(",")) } }
    format!("{{{}}}", o.iter().map(|(k, x)| format!("\"{k}\":{}", v(x))).collect::<Vec<_>>().join(","))
}

static REG: OnceLock<(&'static Spec, &'static Chain)> = OnceLock::new();

impl Spec {
    /// The table row this spec stands for (verified = false, always). Unknown bytes are
    /// filled with values no lookup trusts: callers check `missing()` first.
    pub fn row(&self) -> Chain {
        let leak = |s: &str| -> &'static str { Box::leak(s.to_string().into_boxed_str()) };
        let pkh = self.p2pkh.get().unwrap_or(0);
        let sign = match self.sign.as_str() { "standard" => Sign::Standard, "pos-ntime" => Sign::PosTime, _ => Sign::Unknown };
        Chain { name: leak(&self.name), ticker: leak(&self.ticker.get().unwrap_or_else(|| self.name.to_ascii_uppercase())), title: leak(&self.title),
            coin: self.slip44.get().unwrap_or(0),
            enc: Enc::Utxo { p2pkh: pkh, p2sh: self.p2sh.get().unwrap_or(pkh), hrp: self.hrp.get().map(|h| leak(&h)), wif: self.wif.get().unwrap_or(0), taproot: false },
            default_count: 10, sign, verified: false, source: leak(&format!("unverified chain spec sha256:{}", self.sha256)), sources: &[] }
    }
}

/// Register a parsed spec for this process. A second call is refused.
pub fn register(s: Spec) -> Result<&'static Chain, &'static str> {
    let spec: &'static Spec = Box::leak(Box::new(s));
    let c: &'static Chain = Box::leak(Box::new(spec.row()));
    REG.set((spec, c)).map_err(|_| "spec_already_loaded")?;
    Ok(c)
}
pub fn get() -> Option<&'static Spec> { REG.get().map(|x| x.0) }
pub fn chain() -> Option<&'static Chain> { REG.get().map(|x| x.1) }
pub fn is_spec(name: &str) -> bool { get().map_or(false, |s| s.name == name) }
/// Stable refusal code when `name` is the spec chain and `field` was not supplied.
pub fn missing(name: &str, field: &str) -> Option<&'static str> {
    let s = get().filter(|s| s.name == name)?;
    let unk = match field { "p2pkh" => s.p2pkh.unknown(), "p2sh" => s.p2sh.unknown(), "wif" => s.wif.unknown(), "hrp" => s.hrp.unknown(),
        "slip44" => s.slip44.unknown(), "decimals" => s.decimals.unknown(), "ticker" => s.ticker.unknown(), _ => false };
    if !unk { return None }
    Some(match field { "p2pkh" => "spec_missing_p2pkh", "p2sh" => "spec_missing_p2sh", "wif" => "spec_missing_wif", "hrp" => "spec_missing_hrp",
        "slip44" => "spec_missing_slip44", "decimals" => "spec_missing_decimals", _ => "spec_missing_ticker" })
}
/// Refuse (bad_input JSON line, exit 2) when `name` is the spec chain and `field` was not supplied.
pub fn require_or_exit(tool: &str, name: &str, field: &str) {
    if let Some(e) = missing(name, field) {
        println!(r#"{{"tool":"{tool}","status":"bad_input","error":"{e}","chain":"{name}"}}"#);
        std::process::exit(2)
    }
}
/// Checks before building or signing a transaction on the spec chain (no-op for other chains).
pub fn tx_ready(name: &str, signing: bool) -> Result<(), &'static str> {
    let Some(s) = get().filter(|s| s.name == name) else { return Ok(()) };
    if let Some(e) = missing(name, "p2pkh") { return Err(e) }
    if s.sign != "standard" { return Err("spec_unsupported_sign") }
    match s.decimals { F::Known(8) => {}, F::Known(_) => return Err("spec_unsupported_decimals"), _ => return Err("spec_missing_decimals") }
    if signing { if let Some(e) = missing(name, "wif") { return Err(e) } }
    Ok(())
}
/// The banner every plain summary and tx-sign confirmation carries for a spec chain.
pub fn banner(name: &str) -> Option<String> {
    get().filter(|s| s.name == name).map(|s| format!("!! unverified chain spec: {} (sha256 {}); parameters come from a file, not this program's table", s.name, &s.sha256[..16]))
}
/// The spec as canonical JSON (what chain-learn emits and chain-table prints).
pub fn emit(s: &Spec, evidence: &[(String, String)]) -> String {
    fn f8(x: &F<u8>) -> String { match x { F::Known(v) => v.to_string(), F::Absent => "null".into(), F::Unknown => "\"unknown\"".into() } }
    let fs = |x: &F<String>| match x { F::Known(v) => format!("\"{v}\""), F::Absent => "null".into(), F::Unknown => "\"unknown\"".into() };
    let fn32 = |x: &F<u32>| match x { F::Known(v) => v.to_string(), F::Absent => "null".into(), F::Unknown => "\"unknown\"".into() };
    let mut o = format!("{{\"format\":\"{FORMAT}\",\"name\":\"{}\",\"ticker\":{},\"title\":\"{}\",\"p2pkh\":{},\"p2sh\":{},\"wif\":{},\"hrp\":{},\"slip44\":{},\"checksum\":\"{}\",\"sign\":\"{}\",\"decimals\":{}",
        s.name, fs(&s.ticker), s.title, f8(&s.p2pkh), f8(&s.p2sh), f8(&s.wif), fs(&s.hrp), fn32(&s.slip44), s.checksum, s.sign, fn32(&s.decimals));
    if s.allow_collision { o.push_str(",\"allow_collision\":true") }
    if !evidence.is_empty() { o.push_str(&format!(",\"evidence\":{{{}}}", evidence.iter().map(|(k, v)| format!("\"{k}\":\"{}\"", v.replace(['"', '\\'], "'"))).collect::<Vec<_>>().join(","))) }
    o.push('}'); o
}

/// For binaries: strip `--chain-spec FILE` from argv, load it (or `$BLOCKTOOLS_CHAIN_SPEC`),
/// register it, and return the remaining argv. On any spec error prints one bad_input JSON
/// line naming the code and exits 2. Library code never calls this.
pub fn args_or_exit(tool: &str) -> Vec<String> {
    let mut a: Vec<String> = std::env::args().collect();
    let mut path = std::env::var(ENV).ok().filter(|s| !s.is_empty());
    let die = |e: &str, extra: &str| -> ! { println!("{{\"tool\":\"{tool}\",\"status\":\"bad_input\",\"error\":\"{e}\"{extra}}}"); std::process::exit(2) };
    while let Some(i) = a.iter().position(|x| x == "--chain-spec") {
        if i + 1 >= a.len() { die("spec_unreadable", "") }
        let p = a.remove(i + 1); a.remove(i);
        if path.as_ref().map_or(false, |q| *q != p) { die("spec_conflict", "") } // two different files (flags or flag + env)
        path = Some(p);
    }
    if let Some(p) = path {
        let mut t = String::new();
        use std::io::Read;
        std::fs::File::open(&p).and_then(|f| f.take((64 << 10) + 1).read_to_string(&mut t)).unwrap_or_else(|_| die("spec_unreadable", ""));
        match parse(&t) {
            Ok(s) => { register(s).unwrap_or_else(|e| die(e, "")); }
            Err("spec_byte_collision") => die("spec_byte_collision", &format!(",\"collides_with\":[{}]", collisions_of(&t).iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(","))),
            Err(e) => die(e, ""),
        }
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    const FTX: &str = r#"{"format":"blocktools-chain-spec/1","name":"ftx","ticker":"FTX","p2pkh":14,"p2sh":5,"wif":142,"hrp":"fc","slip44":8,"checksum":"sha256d","sign":"standard","decimals":8,"allow_collision":true}"#;
    #[test] fn parses_and_flags_collision() {
        let s = parse(FTX).unwrap(); assert_eq!(s.p2pkh, F::Known(14)); assert!(s.collisions.contains(&"ftc"));
        assert_eq!(parse(&FTX.replace(",\"allow_collision\":true", "")).unwrap_err(), "spec_byte_collision");
        assert!(collisions_of(&FTX.replace(",\"allow_collision\":true", "")).contains(&"ftc"));
    }
    #[test] fn negatives() {
        for (t, e) in [("{", "spec_malformed"), ("[]", "spec_malformed"), (r#"{"format":"x","name":"ab","checksum":"sha256d"}"#, "spec_bad_format"),
            (&FTX.replace("\"ftx\"", "\"ftc\"") as &str, "spec_name_collision"), (&FTX.replace("sha256d", "groestl"), "spec_unsupported_checksum"),
            (&FTX.replace("\"decimals\"", "\"decimal\""), "spec_unknown_field"), (&FTX.replace("\"p2pkh\":14", "\"p2pkh\":300"), "spec_bad_value"),
            (&FTX.replace("\"title\"", "\"t\"").replace("\"ticker\":\"FTX\"", "\"ticker\":\"FTX\",\"title\":\"5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ\""), "spec_contains_secret"),
            (&FTX.replace("\"name\":\"ftx\",", ""), "spec_missing_name"), (&FTX.replace(",\"checksum\":\"sha256d\"", ""), "spec_missing_checksum")] {
            assert_eq!(parse(t).unwrap_err(), e, "{t}");
        }
    }
    #[test] fn emit_roundtrips() {
        let s = parse(FTX).unwrap(); let t = emit(&s, &[("p2pkh".into(), "3/3 name records".into())]);
        let s2 = parse(&t).unwrap(); assert_eq!(emit(&s2, &[("p2pkh".into(), "3/3 name records".into())]), t);
        let u = parse(r#"{"format":"blocktools-chain-spec/1","name":"zz","p2pkh":77,"checksum":"sha256d"}"#).unwrap();
        assert!(u.wif.unknown() && u.p2sh.unknown() && u.decimals.unknown() && u.sign == "unknown");
    }
}
