//! SwapChan recovery verifier: Rust twin of SwapChan's `verifyRecovery` (apps/api/src/recover.ts, with safe.ts,
//! lpv4.ts, exitguard.ts) and `verifySweepTx` (apps/api/src/sweepverify.ts).
//!
//! Fail closed: anything that does not decode to a call that can only pay the owner is rejected. The ABI decoder
//! follows viem 2.x decoding rules (offsets, cursor bounds, recursive read limit, lenient address words, strict
//! bools) so verdicts match the TypeScript; `tests/data/verifier-corpus.json` is generated from the TS sources and
//! checked case by case. Known, deliberate differences (all fail closed): `data` that is not `0x`-prefixed
//! even-length hex is rejected up front ("data is not hex"); multicall nesting deeper than 32 is rejected;
//! a non-integer `value` gives a verdict instead of a thrown exception.
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::sync::OnceLock;

/// Pendle Router V4 (approve(PendleRouter) is accepted as an approval step only).
pub const PENDLE_ROUTER: &str = "0x888888888889758f76e7103c6cbf23abbf58f946";
/// exitguard.ts EXIT_DEADLINE_MAX_S: exit deadlines further out than now + this are rejected.
pub const EXIT_DEADLINE_MAX_S: u64 = 60 * 60;
/// safe.ts MULTISEND_CALL_ONLY (the only delegatecall targets a Safe sweep may use).
pub const MULTISEND_CALL_ONLY: [&str; 2] = ["0x40a2accbd92bca938b02010e17a5b8929b49130d", "0x9641d764fc13c8b624c04430c7356c1c7c8102e2"];
const MAX_MULTICALL_DEPTH: u32 = 32;

/// recover.ts STANDARD_RECOVERY: signature, argument indexes that must equal the owner
/// (-1 = args[0].recipient, -2 = args[0].withdrawer). Order matters: the first entry whose selector decodes wins.
pub const STANDARD_RECOVERY: &[(&str, &[i32])] = &[
    ("withdraw()", &[]),
    ("exit()", &[]),
    ("getReward()", &[]),
    ("getReward(address)", &[0]),
    ("claim()", &[]),
    ("claimFees()", &[]),
    ("vest()", &[]),
    ("claimRewards()", &[]),
    ("withdraw(uint256)", &[]),
    ("withdrawAndUnwrap(uint256,bool)", &[]),
    ("withdrawAndHarvest(uint256,uint256,address)", &[2]),
    ("withdraw(uint256,uint256)", &[]),
    ("withdraw(address,uint256,address)", &[2]),
    ("completeQueuedWithdrawal((address staker,address delegatedTo,address withdrawer,uint256 nonce,uint32 startBlock,address[] strategies,uint256[] scaledShares),address[],bool)", &[-2]),
    ("queueWithdrawals((address[] strategies,uint256[] depositShares,address withdrawer)[])", &[]),
    ("redeem(uint256,address,address)", &[1, 2]),
    ("withdrawToken(address,uint256)", &[]),
    ("claimComp(address)", &[0]),
    ("claimVenus(address)", &[0]),
    ("claimWithdrawal(uint256)", &[]),
    ("claimWithdraw(uint256)", &[]),
    ("burnRedemptionTicketNft(uint256,address)", &[1]),
    ("finalizeWithdrawal(uint256)", &[]),
    ("claim(uint256)", &[]),
    ("withdrawMax(uint256,address)", &[1]),
    ("redeemPlans(uint256[])", &[]),
    ("withdrawTokens(uint256)", &[]),
    ("withdraw(address,uint256,uint256,uint256)", &[]),
    ("downgrade(uint256)", &[]),
    ("downgradeToETH(uint256)", &[]),
    ("claimFundingFees(address[],address[],address)", &[2]),
    ("claimCollateral()", &[]),
    ("releaseDeed(bytes32)", &[]),
    ("claim(uint256,address,uint256,bytes32[])", &[1]),
    ("removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)", &[5]),
    ("exitPostExpToToken(address,address,uint256,uint256,(address,uint256,address,address,(uint8,address,bytes,bool)))", &[0]),
    ("redeem(address,uint256,address,uint256,bool)", &[0]),
    ("decreaseLiquidity((uint256 tokenId,uint128 liquidity,uint256 amount0Min,uint256 amount1Min,uint256 deadline))", &[]),
    ("collect((uint256 tokenId,address recipient,uint128 amount0Max,uint128 amount1Max))", &[-1]),
];

/// Contract-pinned special cases in verifyRecovery: (label, contract `to` or "" for any, rule).
pub const PINNED: &[(&str, &str, &str)] = &[
    ("approve(Pendle Router) — approval step only", "", "data starts 0x095ea7b3, spender == 0x888888888889758f76e7103c6cbf23abbf58f946"),
    ("Safe execTransaction (every leg pays the owner)", "", "data starts 0x6a761202"),
    ("modifyLiquidities(DECREASE_LIQUIDITY,TAKE_PAIR→owner)", "", "data starts 0xdd46508f"),
    ("approve(WithdrawDAO) — TheDAO refund step 1", "0xbb9bc244d798123fde783fcc1c72d3bb8c189413", "data starts 0x095ea7b3, spender == 0xbf4ed7b27f1d666546e30d74d50d173d20bca754"),
    ("WithdrawDAO.withdraw() (pays the caller)", "0xbf4ed7b27f1d666546e30d74d50d173d20bca754", "data == 0x3ccfd60b"),
    ("Arbitrum Outbox.executeTransaction (executes a proven L2→L1 message)", "0x0b9857ae2d4a3dbe74ffe1d7df045bb7f96e4840", "data starts 0x08635a95"),
    ("OptimismPortal prove/finalize (executes a committed L2→L1 withdrawal)", "0xbeb5fc579115071764c7423a4f75ededa441ec71", "data starts 0x4870496f or 0x43ca1c50"),
    ("IronHands payout() (zero value; pays the queue head)", "0xe58b65d1c0c8e8b2a0e3a3acec633271531084ed", "data == 0x63bd1d4a"),
];

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict { Verified(String), Rejected(String) }
impl Verdict {
    pub fn verified(&self) -> bool { matches!(self, Verdict::Verified(_)) }
    pub fn to_json(&self) -> Value {
        match self { Verdict::Verified(c) => json!({"verified": true, "call": c}), Verdict::Rejected(r) => json!({"verified": false, "reason": r}) }
    }
}
use Verdict::{Rejected as No, Verified as Yes};

// ---------------- ABI (viem 2.x decoding semantics) ----------------
#[derive(Debug, Clone)]
enum Ty { Addr, Num(bool, u16), Bool, Bytes, Str, Fb(usize), Arr(Box<Ty>), Tup(Vec<Ty>) }
#[derive(Debug, Clone)]
enum Val { Addr([u8; 20]), Word([u8; 32]), Bool, Bytes(Vec<u8>), List(Vec<Val>) }
type R<T> = Result<T, ()>;

fn ws(s: &[u8], i: &mut usize) { while *i < s.len() && s[*i] == b' ' { *i += 1 } }
fn ident(s: &[u8], i: &mut usize) -> String {
    let st = *i; while *i < s.len() && (s[*i].is_ascii_alphanumeric() || s[*i] == b'_') { *i += 1 }
    String::from_utf8_lossy(&s[st..*i]).into()
}
fn parse_list(s: &[u8], i: &mut usize) -> R<Vec<Ty>> {
    if s.get(*i) != Some(&b'(') { return Err(()) }
    *i += 1; let mut v = vec![]; ws(s, i);
    if s.get(*i) == Some(&b')') { *i += 1; return Ok(v) }
    loop {
        v.push(parse_param(s, i)?); ws(s, i);
        match s.get(*i) { Some(b',') => { *i += 1; ws(s, i) } Some(b')') => { *i += 1; return Ok(v) } _ => return Err(()) }
    }
}
fn parse_param(s: &[u8], i: &mut usize) -> R<Ty> {
    let mut t = if s.get(*i) == Some(&b'(') { Ty::Tup(parse_list(s, i)?) } else {
        let id = ident(s, i);
        match id.as_str() {
            "address" => Ty::Addr, "bool" => Ty::Bool, "bytes" => Ty::Bytes, "string" => Ty::Str,
            x if x.starts_with("uint") => Ty::Num(false, x[4..].parse().unwrap_or(256)),
            x if x.starts_with("int") => Ty::Num(true, x[3..].parse().unwrap_or(256)),
            x if x.starts_with("bytes") => Ty::Fb(x[5..].parse().map_err(|_| ())?),
            _ => return Err(()),
        }
    };
    while s[*i..].starts_with(b"[]") { t = Ty::Arr(Box::new(t)); *i += 2 }
    ws(s, i); ident(s, i); // optional parameter name
    Ok(t)
}
fn canon(t: &Ty) -> String {
    match t {
        Ty::Addr => "address".into(), Ty::Bool => "bool".into(), Ty::Bytes => "bytes".into(), Ty::Str => "string".into(),
        Ty::Num(sg, b) => format!("{}int{b}", if *sg { "" } else { "u" }), Ty::Fb(n) => format!("bytes{n}"),
        Ty::Arr(x) => format!("{}[]", canon(x)),
        Ty::Tup(c) => format!("({})", c.iter().map(canon).collect::<Vec<_>>().join(",")),
    }
}
struct Func { sig: &'static str, name: String, inputs: Vec<Ty>, sel: String }
fn func(sig: &'static str) -> Func {
    let b = sig.as_bytes(); let mut i = 0; let name = ident(b, &mut i);
    let inputs = parse_list(b, &mut i).expect("static signature parses");
    let full = format!("{name}({})", inputs.iter().map(canon).collect::<Vec<_>>().join(","));
    let sel = format!("0x{}", hex(&Keccak256::digest(full.as_bytes())[..4]));
    Func { sig, name, inputs, sel }
}
/// Selector (`0x` + 8 hex) of a signature, names and spaces ignored.
pub fn selector(sig: &'static str) -> String { func(sig).sel }

struct Cur<'a> { b: &'a [u8], pos: usize, reads: HashMap<usize, u32>, rec: u32 }
const LIMIT: u32 = 8192;
impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Self { Cur { b, pos: 0, reads: HashMap::new(), rec: 0 } }
    fn set(&mut self, p: u128) -> R<()> { if p >= self.b.len() as u128 { return Err(()) } self.pos = p as usize; Ok(()) }
    fn read(&mut self, n: u128, adv: Option<usize>) -> R<&'a [u8]> {
        if self.rec >= LIMIT { return Err(()) }
        let c = self.reads.entry(self.pos).or_insert(0); if *c > 0 { self.rec += 1 } *c += 1;
        if n == 0 || self.pos as u128 + n > self.b.len() as u128 { return Err(()) }
        let n = n as usize; let v = &self.b[self.pos..self.pos + n];
        self.pos += adv.unwrap_or(n); Ok(v)
    }
    fn word(&mut self) -> R<&'a [u8]> { self.read(32, None) }
}
fn num(w: &[u8]) -> u128 {
    if w[..16].iter().any(|&x| x != 0) { return u128::MAX / 4 }
    w[16..].iter().fold(0u128, |a, &x| a << 8 | x as u128)
}
fn has_dyn(t: &Ty) -> bool { match t { Ty::Bytes | Ty::Str | Ty::Arr(_) => true, Ty::Tup(c) => c.iter().any(has_dyn), _ => false } }
fn dec_one(c: &mut Cur, t: &Ty, sp: u128) -> R<(Val, u128)> {
    match t {
        Ty::Arr(inner) => {
            let off = num(c.word()?); let start = sp.saturating_add(off); let sod = start.saturating_add(32);
            c.set(start)?; let len = num(c.word()?); let dy = has_dyn(inner);
            let (mut cons, mut v, mut i) = (0u128, vec![], 0u128);
            while i < len {
                c.set(sod.saturating_add(if dy { i.saturating_mul(32) } else { cons }))?;
                let (x, k) = dec_one(c, inner, sod)?; cons = cons.saturating_add(k); v.push(x); i += 1;
            }
            c.set(sp.saturating_add(32))?; Ok((Val::List(v), 32))
        }
        Ty::Tup(cs) => {
            let mut v = vec![]; let mut cons = 0u128;
            if has_dyn(t) {
                let off = num(c.word()?); let start = sp.saturating_add(off);
                for x in cs { c.set(start.saturating_add(cons))?; let (y, k) = dec_one(c, x, start)?; cons = cons.saturating_add(k); v.push(y) }
                c.set(sp.saturating_add(32))?; Ok((Val::List(v), 32))
            } else {
                for x in cs { let (y, k) = dec_one(c, x, sp)?; cons += k; v.push(y) }
                Ok((Val::List(v), cons))
            }
        }
        Ty::Bytes | Ty::Str => {
            let off = num(c.word()?); c.set(sp.saturating_add(off))?; let len = num(c.word()?);
            if len == 0 { c.set(sp.saturating_add(32))?; return Ok((Val::Bytes(vec![]), 32)) }
            let adv = if matches!(t, Ty::Str) { Some(32) } else { None };
            let d = c.read(len, adv)?.to_vec(); c.set(sp.saturating_add(32))?; Ok((Val::Bytes(d), 32))
        }
        Ty::Fb(n) => Ok((Val::Bytes(c.read(*n as u128, Some(32))?.to_vec()), 32)),
        Ty::Addr => { let w = c.word()?; let mut a = [0u8; 20]; a.copy_from_slice(&w[12..]); Ok((Val::Addr(a), 32)) }
        Ty::Bool => { let w = c.word()?; if w[..31].iter().any(|&x| x != 0) || w[31] > 1 { return Err(()) } Ok((Val::Bool, 32)) }
        Ty::Num(..) => { let mut a = [0u8; 32]; a.copy_from_slice(c.word()?); Ok((Val::Word(a), 32)) }
    }
}
fn dec_params(ts: &[Ty], d: &[u8]) -> R<Vec<Val>> {
    if !ts.is_empty() && d.len() < 32 { return Err(()) }
    let mut c = Cur::new(d); let mut cons = 0u128; let mut out = vec![];
    for t in ts { if cons < d.len() as u128 { c.set(cons)? } let (v, k) = dec_one(&mut c, t, 0)?; cons = cons.saturating_add(k); out.push(v) }
    Ok(out)
}
/// viem decodeFunctionData over `abi`: selector compared on the hex *string* (case-sensitive), then arguments.
/// Outer Err = selector not found; inner Err = decode failure.
fn dec_fn<'f>(abi: &'f [Func], s: &str, b: &[u8]) -> Result<(&'f Func, R<Vec<Val>>), String> {
    let body = s.strip_prefix("0x").unwrap_or(s);
    let sig = format!("0x{}", body.chars().take(8).collect::<String>());
    let f = abi.iter().find(|f| f.sel == sig).ok_or(sig)?;
    if f.inputs.is_empty() { return Ok((f, Ok(vec![]))) }
    if b.len() <= 4 { return Ok((f, Err(()))) }
    Ok((f, dec_params(&f.inputs, &b[4..])))
}
fn dec_ok<'f>(abi: &'f [Func], s: &str, b: &[u8]) -> Option<(&'f Func, Vec<Val>)> {
    match dec_fn(abi, s, b) { Ok((f, Ok(a))) => Some((f, a)), _ => None }
}

// ---------------- helpers ----------------
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn hex0x(b: &[u8]) -> String { format!("0x{}", hex(b)) }
fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let h = s.strip_prefix("0x")?;
    if h.len() % 2 != 0 { return None }
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(h.get(i..i + 2)?, 16).ok()).collect()
}
fn zero(w: &[u8]) -> bool { w.iter().all(|&x| x == 0) }
fn word_le_u64(w: &[u8; 32], n: u64) -> bool { zero(&w[..24]) && u64::from_be_bytes(w[24..].try_into().unwrap()) <= n }
fn checksum(a: &[u8; 20]) -> String { blocktools_core::validate::checksum_eth(a) }
/// viem isAddress (strict): 0x + 40 hex; mixed case must be a valid EIP-55 checksum.
pub fn is_address(s: &str) -> bool {
    let Some(h) = s.strip_prefix("0x") else { return false };
    if h.len() != 40 || !h.bytes().all(|c| c.is_ascii_hexdigit()) { return false }
    if s.to_lowercase() == s { return true }
    get20(h).map_or(false, |a| checksum(&a) == s)
}
fn get20(h: &str) -> Option<[u8; 20]> { parse_hex(&format!("0x{h}"))?.try_into().ok() }
/// viem getAddress: Err when not an address.
fn get_address(s: &str) -> R<[u8; 20]> { if !is_address(s) { return Err(()) } get20(&s[2..]).ok_or(()) }
fn deadline_ok(w: &[u8; 32], now_s: u64) -> bool { word_le_u64(w, now_s.saturating_add(EXIT_DEADLINE_MAX_S)) }
fn word(v: &Val) -> R<&[u8; 32]> { if let Val::Word(w) = v { Ok(w) } else { Err(()) } }
fn list(v: &Val) -> R<&Vec<Val>> { if let Val::List(l) = v { Ok(l) } else { Err(()) } }
fn bytes(v: &Val) -> R<&Vec<u8>> { if let Val::Bytes(b) = v { Ok(b) } else { Err(()) } }
fn addr(v: &Val) -> R<&[u8; 20]> { if let Val::Addr(a) = v { Ok(a) } else { Err(()) } }

/// JS `BigInt(s)` for a string: Ok((negative, nonzero)), Err(message) like V8's SyntaxError.
fn js_bigint(s: &str) -> Result<(bool, bool), String> {
    let bad = || format!("Cannot convert {s} to a BigInt");
    let t = s.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    if t.is_empty() { return Ok((false, false)) }
    let pre = t.get(..2).map(|p| p.to_ascii_lowercase());
    let radix = match pre.as_deref() { Some("0x") => 16, Some("0o") => 8, Some("0b") => 2, _ => 10 };
    if radix != 10 {
        let d = &t[2..];
        if d.is_empty() || !d.chars().all(|c| c.is_digit(radix)) { return Err(bad()) }
        return Ok((false, d.chars().any(|c| c != '0')));
    }
    let (neg, d) = match t.as_bytes()[0] { b'-' => (true, &t[1..]), b'+' => (false, &t[1..]), _ => (false, t) };
    if d.is_empty() || !d.bytes().all(|c| c.is_ascii_digit()) { return Err(bad()) }
    let nz = d.bytes().any(|c| c != b'0');
    Ok((neg && nz, nz))
}
/// JS `String(v)` for JSON values.
fn js_string(v: &Value) -> String {
    match v {
        Value::Null => "null".into(), Value::Bool(b) => b.to_string(), Value::String(s) => s.clone(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() { return i.to_string() }
            if let Some(u) = n.as_u64() { return u.to_string() }
            let f = n.as_f64().unwrap_or(f64::NAN);
            if f.fract() == 0.0 && f.abs() < 1e21 { format!("{f:.0}") } else { format!("{f}") }
        }
        Value::Array(a) => a.iter().map(|x| if x.is_null() { String::new() } else { js_string(x) }).collect::<Vec<_>>().join(","),
        Value::Object(_) => "[object Object]".into(),
    }
}
fn slice80(s: &str) -> String { s.chars().take(80).collect() }

fn abis() -> &'static (Vec<Func>, Vec<Func>, Vec<Func>, Vec<Func>, Vec<Func>, Vec<Func>) {
    static A: OnceLock<(Vec<Func>, Vec<Func>, Vec<Func>, Vec<Func>, Vec<Func>, Vec<Func>)> = OnceLock::new();
    A.get_or_init(|| (
        STANDARD_RECOVERY.iter().map(|(s, _)| func(s)).collect(),
        vec![func("multicall(bytes[])")],
        vec![func("execTransaction(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,bytes signatures)")],
        vec![func("multiSend(bytes transactions)")],
        vec![func("transfer(address to,uint256 amount)")],
        // viem erc20Abi functions, in viem's order
        ["allowance(address,address)", "approve(address,uint256)", "balanceOf(address)", "decimals()", "name()", "symbol()",
         "totalSupply()", "transfer(address,uint256)", "transferFrom(address,address,uint256)"].into_iter().map(func).collect(),
    ))
}

// ---------------- Safe (safe.ts verifySafe) ----------------
fn leg_ok(to: &str, value_nz: bool, data: &[u8], owner: &str) -> R<bool> {
    let own = get_address(owner)?;
    if get_address(to)? == own { return Ok(data.is_empty()) }
    if value_nz { return Ok(false) }
    let Some((_, a)) = dec_ok(&abis().4, &hex0x(data), data) else { return Ok(false) };
    Ok(*addr(&a[0])? == own)
}
fn verify_safe(s: &str, b: &[u8], owner: &str) -> Option<bool> {
    if !s.starts_with("0x6a761202") { return None }
    Some((|| -> R<bool> {
        let (_, a) = dec_ok(&abis().2, s, b).ok_or(())?;
        if !zero(word(&a[6])?) || *addr(&a[7])? != [0; 20] || *addr(&a[8])? != [0; 20] { return Ok(false) }
        let (to, op) = (addr(&a[0])?, word(&a[3])?);
        if zero(op) { return leg_ok(&hex0x(to), !zero(word(&a[1])?), bytes(&a[2])?, owner) }
        let one = { let mut o = [0u8; 32]; o[31] = 1; o };
        if *op != one || !MULTISEND_CALL_ONLY.contains(&hex0x(to).as_str()) { return Ok(false) }
        let inner = bytes(&a[2])?;
        let (_, m) = dec_ok(&abis().3, &hex0x(inner), inner).ok_or(())?;
        let blob = hex(bytes(&m[0])?);
        let sl = |a: usize, z: usize| -> &str { let n = blob.len(); &blob[a.min(n)..z.min(n).max(a.min(n))] };
        let big = |h: &str| -> R<(bool, u128)> {
            if h.is_empty() { return Err(()) }
            let nz = h.bytes().any(|c| c != b'0');
            let t = h.trim_start_matches('0');
            Ok((nz, if t.len() > 30 { u128::MAX / 4 } else if t.is_empty() { 0 } else { u128::from_str_radix(t, 16).map_err(|_| ())? }))
        };
        let (mut i, mut n) = (0usize, 0u32);
        while i < blob.len() {
            if sl(i, i + 2) != "00" { return Ok(false) }
            let t = format!("0x{}", sl(i + 2, i + 42));
            let (vnz, _) = big(sl(i + 42, i + 106))?;
            let (_, len) = big(sl(i + 106, i + 170))?;
            let end = (i as u128 + 170).saturating_add(len.saturating_mul(2)).min(blob.len() as u128) as usize;
            let d = parse_hex(&format!("0x{}", sl(i + 170, end))).ok_or(())?;
            if !leg_ok(&t, vnz, &d, owner)? { return Ok(false) }
            let step = 170u128.saturating_add(len.saturating_mul(2));
            i = (i as u128).saturating_add(step).min(usize::MAX as u128) as usize; n += 1;
        }
        Ok(n > 0)
    })().unwrap_or(false))
}

// ---------------- Uniswap v4 (lpv4.ts verifyV4) ----------------
fn verify_v4(s: &str, b: &[u8], owner: &str, now_s: u64) -> Option<bool> {
    if !s.starts_with("0xdd46508f") { return None }
    Some((|| -> R<bool> {
        let top = dec_params(&[Ty::Bytes, Ty::Num(false, 256)], &b[4..])?;
        if !deadline_ok(word(&top[1])?, now_s) { return Ok(false) }
        let u = dec_params(&[Ty::Bytes, Ty::Arr(Box::new(Ty::Bytes))], bytes(&top[0])?)?;
        let (acts, ps) = (bytes(&u[0])?, list(&u[1])?);
        if acts.len() != ps.len() || acts.is_empty() { return Ok(false) }
        let mut took = false;
        for (a, p) in acts.iter().zip(ps) {
            let p = bytes(p)?;
            match a {
                0x01 => {
                    let n = Ty::Num(false, 256);
                    let d = dec_params(&[n.clone(), n.clone(), Ty::Num(false, 128), Ty::Num(false, 128), Ty::Bytes], p)?;
                    if !zero(word(&d[1])?) && zero(word(&d[2])?) && zero(word(&d[3])?) { return Ok(false) }
                }
                0x11 => {
                    let d = dec_params(&[Ty::Addr, Ty::Addr, Ty::Addr], p)?;
                    if *addr(&d[2])? != get_address(owner)? { return Ok(false) }
                    took = true;
                }
                _ => return Ok(false),
            }
        }
        Ok(took)
    })().unwrap_or(false))
}

fn exit_guard(sig: &str, a: &[Val], now_s: u64) -> R<Option<&'static str>> {
    let name = &sig[..sig.find('(').unwrap_or(sig.len())];
    const ZM: &str = "zero minimum outputs (sandwichable)"; const DL: &str = "deadline too far out"; const ZT: &str = "zero minTokenOut (sandwichable)";
    if name == "removeLiquidity" {
        if zero(word(&a[3])?) && zero(word(&a[4])?) { return Ok(Some(ZM)) }
        if !deadline_ok(word(&a[6])?, now_s) { return Ok(Some(DL)) }
    }
    if name == "decreaseLiquidity" {
        let p = list(&a[0])?;
        if !zero(word(&p[1])?) && zero(word(&p[2])?) && zero(word(&p[3])?) { return Ok(Some(ZM)) }
        if !deadline_ok(word(&p[4])?, now_s) { return Ok(Some(DL)) }
    }
    if name == "exitPostExpToToken" && zero(word(&list(&a[4])?[1])?) { return Ok(Some(ZT)) }
    if sig == "redeem(address,uint256,address,uint256,bool)" && zero(word(&a[3])?) { return Ok(Some(ZT)) }
    Ok(None)
}

/// recover.ts verifyRecovery: decode a recovery tx and prove it can only pay the owner. `now_s` drives the
/// exit-deadline guard (TS uses Date.now()).
pub fn verify_recovery(to: &str, data: &str, value: &str, owner: &str, now_s: u64) -> Verdict { rec(to, data, value, owner, now_s, 0) }
fn rec(to: &str, data: &str, value: &str, owner: &str, now_s: u64, depth: u32) -> Verdict {
    match js_bigint(if value.is_empty() { "0" } else { value }) {
        Ok((_, true)) => return No("non-zero value".into()),
        Ok(_) => {}
        Err(e) => return No(format!("unverifiable: {}", slice80(&e))),
    }
    let Some(b) = parse_hex(data) else { return No("data is not hex".into()) };
    let sl = |a: usize, z: usize| data.get(a.min(data.len())..z.min(data.len())).unwrap_or("").to_lowercase();
    let z24 = "0".repeat(24);
    if data.starts_with("0x095ea7b3") && sl(10, 74) == format!("{z24}{}", &PENDLE_ROUTER[2..]) { return Yes(PINNED[0].0.into()) }
    match verify_safe(data, &b, owner) { Some(true) => return Yes(PINNED[1].0.into()), Some(false) => return No("Safe tx with a leg that does not pay the owner".into()), None => {} }
    match verify_v4(data, &b, owner, now_s) { Some(true) => return Yes(PINNED[2].0.into()), Some(false) => return No("v4 actions other than decrease + take-to-owner".into()), None => {} }
    let (tl, dl) = (to.to_lowercase(), data.to_lowercase());
    if tl == PINNED[3].1 && data.starts_with("0x095ea7b3") && sl(10, 74) == format!("{z24}bf4ed7b27f1d666546e30d74d50d173d20bca754") { return Yes(PINNED[3].0.into()) }
    if tl == PINNED[4].1 && dl == "0x3ccfd60b" { return Yes(PINNED[4].0.into()) }
    if tl == PINNED[5].1 && dl.starts_with("0x08635a95") { return Yes(PINNED[5].0.into()) }
    if tl == PINNED[6].1 && (dl.starts_with("0x4870496f") || dl.starts_with("0x43ca1c50")) { return Yes(PINNED[6].0.into()) }
    if dl == "0x63bd1d4a" && tl == PINNED[7].1 { return Yes(PINNED[7].0.into()) }
    if let Some((_, a)) = dec_ok(&abis().1, data, &b) {
        let Ok(inner) = list(&a[0]) else { return No("not a standard recovery call".into()) };
        if inner.is_empty() { return No("empty multicall".into()) }
        if depth >= MAX_MULTICALL_DEPTH { return No("multicall: nested too deep".into()) }
        for d in inner {
            let Ok(d) = bytes(d) else { return No("not a standard recovery call".into()) };
            if let No(r) = rec(to, &hex0x(d), "0", owner, now_s, depth + 1) { return No(format!("multicall: {r}")) }
        }
        return Yes("multicall(bytes[])".into());
    }
    let ol = owner.to_lowercase();
    for (f, (_, owners)) in abis().0.iter().zip(STANDARD_RECOVERY) {
        let Ok((_, Ok(a))) = dec_fn(std::slice::from_ref(f), data, &b) else { continue };
        let ok = owners.iter().all(|&i| {
            let v = match i { -1 => a.first().and_then(|t| list(t).ok()?.get(1)), -2 => a.first().and_then(|t| list(t).ok()?.get(2)), i => a.get(i as usize) };
            matches!(v, Some(Val::Addr(x)) if checksum(x).to_lowercase() == ol)
        });
        if ok {
            match exit_guard(f.sig, &a, now_s) { Ok(Some(g)) => return No(format!("{}: {g}", f.sig)), Ok(None) => {}, Err(_) => continue }
            return Yes(f.sig.into());
        }
        return No(format!("{}: recipient is not the owner", f.sig));
    }
    No("not a standard recovery call".into())
}

/// sweepverify.ts verifySweepTx over a JSON tx `{from,to,value,data,chainId}` (fields typed exactly as the TS sees them).
pub fn verify_sweep(tx: &Value, owner: &str, chain_id: u64, token: Option<&str>) -> Verdict {
    if !is_address(owner) { return No("owner is not an address".into()) }
    let own = get_address(owner).unwrap();
    let g = |k: &str| tx.get(k).filter(|v| !v.is_null());
    if g("chainId").and_then(|v| v.as_f64()) != Some(chain_id as f64) { return No("chainId missing or wrong (EIP-155 replay protection)".into()) }
    let from = g("from").and_then(|v| v.as_str());
    if !from.map_or(false, |f| get_address(f) == Ok(own)) { return No("from is not the owner".into()) }
    let Some(to) = g("to").and_then(|v| v.as_str()).filter(|t| is_address(t)) else { return No("bad to".into()) };
    let to20 = get_address(to).unwrap();
    let data = g("data").and_then(|v| v.as_str()).unwrap_or("0x");
    let vs = g("value").map_or("0".to_string(), js_string);
    let (neg, nz) = match js_bigint(&vs) { Ok(x) => x, Err(e) => return No(format!("unverifiable: {}", slice80(&e))) };
    let Some(token) = token.filter(|t| !t.is_empty()) else {
        if data != "0x" { return No("native sweep must carry no calldata".into()) }
        if to20 != own { return No("native sweep does not pay the owner".into()) }
        if neg || !nz { return No("nothing to send".into()) }
        return Yes(format!("native transfer to owner (chainId {chain_id})"));
    };
    if !is_address(token) || get_address(token).unwrap() != to20 { return No("token sweep to the wrong contract".into()) }
    if nz { return No("token sweep must send no native value".into()) }
    let b = parse_hex(data);
    let (f, args) = match dec_fn(&abis().5, data, b.as_deref().unwrap_or(&[])) {
        Err(sig) => return No(format!("unverifiable: {}", slice80(&format!("Encoded function signature \"{sig}\" not found on ABI.\nMake sure you are using the correct ABI and that the function exists on it.")))),
        Ok(x) => x,
    };
    let args = match (b, args) { (Some(_), Ok(a)) => a, (None, _) => return No("unverifiable: data is not hex".into()), (_, Err(_)) => return No("unverifiable: calldata does not decode".into()) };
    if f.name != "transfer" { return No("not an ERC-20 transfer".into()) }
    let (Ok(rcpt), Ok(amt)) = (addr(&args[0]), word(&args[1])) else { return No("unverifiable: calldata does not decode".into()) };
    if *rcpt != own { return No("token transfer does not pay the owner".into()) }
    if zero(amt) { return No("nothing to send".into()) }
    Yes(format!("transfer(owner, {}) on {} (chainId {chain_id})", blocktools_tx::evm::dec(amt), checksum(&to20)))
}

/// Raw signed or unsigned EVM tx (legacy EIP-155 or type 2) -> (fields, sender if signed).
fn raw_fields(raw: &[u8], chain_id: u64) -> Result<(blocktools_tx::evm::Tx, Value), Verdict> {
    let tx = blocktools_tx::evm::Tx::parse(raw).map_err(|e| No(format!("unverifiable: {e}")))?;
    let from = tx.from().map(|a| checksum(&a));
    let meta = json!({
        "kind": if tx.kind == blocktools_tx::evm::Kind::Eip1559 { "eip1559" } else { "legacy" },
        "chainId": tx.chain_id, "signed": tx.sig.is_some(), "from": from,
        "to": tx.to.map(|a| checksum(&a)), "value": tx.value.to_string(), "data": hex0x(&tx.data),
        "txid": tx.txhash().map(|h| hex0x(&h)),
    });
    if tx.chain_id != Some(chain_id) { return Err(No("chainId missing or wrong (EIP-155 replay protection)".into())) }
    if tx.sig.is_some() && from.is_none() { return Err(No("unverifiable: bad signature".into())) }
    Ok((tx, meta))
}
fn merge(v: Verdict, meta: Value) -> Value { let mut o = v.to_json(); o["tx"] = meta; o }
/// Raw-hex entry point for verify_recovery: also requires EIP-155 chain id == `chain_id`, a `to`, and, when
/// signed, the recovered sender == owner.
pub fn verify_recovery_raw(raw: &[u8], owner: &str, chain_id: u64, now_s: u64) -> Value {
    let (tx, meta) = match raw_fields(raw, chain_id) { Ok(x) => x, Err(v) => return v.to_json() };
    let Some(to) = tx.to else { return merge(No("contract creation".into()), meta) };
    if let Some(f) = meta["from"].as_str() { if get_address(owner).ok() != get_address(f).ok() { return merge(No("from is not the owner".into()), meta) } }
    merge(verify_recovery(&hex0x(&to), &hex0x(&tx.data), &tx.value.to_string(), owner, now_s), meta)
}
/// Raw-hex entry point for verify_sweep. The sender comes from the signature, so an unsigned tx fails closed
/// ("from is not the owner"): sign first, or use the JSON form with `from`.
pub fn verify_sweep_raw(raw: &[u8], owner: &str, chain_id: u64, token: Option<&str>) -> Value {
    let (_, meta) = match raw_fields(raw, chain_id) { Ok(x) => x, Err(v) => return v.to_json() };
    let j = json!({"from": meta["from"], "to": meta["to"], "value": meta["value"], "data": meta["data"], "chainId": chain_id});
    merge(verify_sweep(&j, owner, chain_id, token), meta)
}
/// JSON entry for verify_recovery: `{to, data, value}` as SwapChan's RecoveryTx.
pub fn verify_recovery_json(tx: &Value, owner: &str, now_s: u64) -> Verdict {
    let (Some(to), Some(data)) = (tx.get("to").and_then(|v| v.as_str()), tx.get("data").and_then(|v| v.as_str())) else {
        return No("bad tx: to and data must be strings".into());
    };
    let v = match tx.get("value") { None | Some(Value::Null) | Some(Value::Bool(false)) => "0".into(), Some(Value::Number(n)) if n.as_f64() == Some(0.0) => "0".into(), Some(x) => js_string(x) };
    verify_recovery(to, data, &v, owner, now_s)
}
/// The tables, for docs and cross-checks.
pub fn tables() -> Value {
    json!({
        "standard_recovery": abis().0.iter().zip(STANDARD_RECOVERY).map(|(f, (s, o))| json!({"sig": s, "owners": o, "selector": f.sel})).collect::<Vec<_>>(),
        "pinned": PINNED.iter().map(|(l, t, r)| json!({"call": l, "to": t, "rule": r})).collect::<Vec<_>>(),
        "multisend_call_only": MULTISEND_CALL_ONLY, "pendle_router": PENDLE_ROUTER, "exit_deadline_max_s": EXIT_DEADLINE_MAX_S,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn selectors() {
        assert_eq!(selector("withdraw()"), "0x3ccfd60b");
        assert_eq!(selector("multicall(bytes[])"), "0xac9650d8");
        assert_eq!(abis().2[0].sel, "0x6a761202");
        assert_eq!(selector("modifyLiquidities(bytes unlockData, uint256 deadline)"), "0xdd46508f");
        assert_eq!(selector("transfer(address to, uint256 amount)"), "0xa9059cbb");
        assert_eq!(abis().3[0].sel, "0x8d80ff0a");
    }
    #[test] fn bigint() {
        assert_eq!(js_bigint(" 0x10 "), Ok((false, true)));
        assert_eq!(js_bigint(""), Ok((false, false)));
        assert_eq!(js_bigint("-0"), Ok((false, false)));
        assert!(js_bigint("-0x1").is_err() && js_bigint("1.5").is_err() && js_bigint("0x").is_err());
    }
}
