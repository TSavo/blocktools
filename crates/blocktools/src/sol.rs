//! Solana public-data helpers: base58, ed25519 on-curve, PDA / ATA derivation, Anchor discriminator,
//! transaction (legacy + v0) decode, signature verify, and transfer checks. No private keys.
use bitcoin::hashes::{sha256, Hash};
use curve25519_dalek::edwards::CompressedEdwardsY;
use serde_json::{json, Value};

pub const SYSTEM: &str = "11111111111111111111111111111111";
pub const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
pub const ATA: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
pub const COMPUTE_BUDGET: &str = "ComputeBudget111111111111111111111111111111";
pub const MEMO: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

pub fn b58enc(b: &[u8]) -> String { bitcoin::base58::encode(b) }
pub fn b58dec(s: &str) -> Result<Vec<u8>, &'static str> { bitcoin::base58::decode(s).map_err(|_| "bad_base58") }
/// 32-byte public key from base58.
pub fn pubkey(s: &str) -> Result<[u8; 32], &'static str> { b58dec(s)?.try_into().map_err(|_| "bad_length") }
/// True if the 32 bytes decompress to an ed25519 point (a wallet key can sign; a PDA must not be on curve).
/// Same call Solana's runtime uses (`curve25519_dalek` `CompressedEdwardsY::decompress`), so edge encodings
/// follow dalek, not strict RFC 8032: a non-canonical y (y >= p, reduced mod p) and x = 0 with the sign bit
/// set both count as on curve.
pub fn is_on_curve(k: &[u8; 32]) -> bool { CompressedEdwardsY(*k).decompress().is_some() }

/// `create_program_address`: sha256(seeds ‖ program ‖ "ProgramDerivedAddress"); errors if on curve.
pub fn create_program_address(seeds: &[&[u8]], program: &[u8; 32]) -> Result<[u8; 32], &'static str> {
    if seeds.len() > 16 || seeds.iter().any(|s| s.len() > 32) { return Err("bad_seeds") }
    let mut e = sha256::HashEngine::default();
    use bitcoin::hashes::HashEngine;
    for s in seeds { e.input(s) } e.input(program); e.input(b"ProgramDerivedAddress");
    let h = sha256::Hash::from_engine(e).to_byte_array();
    if is_on_curve(&h) { Err("on_curve") } else { Ok(h) }
}
/// `find_program_address`: bump from 255 down to the first off-curve address.
pub fn find_program_address(seeds: &[&[u8]], program: &[u8; 32]) -> Result<([u8; 32], u8), &'static str> {
    if seeds.len() > 15 { return Err("bad_seeds") }
    for bump in (0..=255u8).rev() {
        let b = [bump]; let mut s = seeds.to_vec(); s.push(&b);
        match create_program_address(&s, program) { Ok(a) => return Ok((a, bump)), Err("on_curve") => continue, Err(e) => return Err(e) }
    }
    Err("no_bump")
}
/// Associated token account for (owner, mint) under `token_program` (classic or Token-2022).
pub fn associated_token_address(owner: &[u8; 32], mint: &[u8; 32], token_program: &[u8; 32]) -> Result<([u8; 32], u8), &'static str> {
    find_program_address(&[owner, token_program, mint], &pubkey(ATA)?)
}
/// Anchor instruction discriminator: sha256("global:" + name)[..8].
pub fn anchor_discriminator(name: &str) -> [u8; 8] {
    let h = sha256::Hash::hash(format!("global:{name}").as_bytes()).to_byte_array(); h[..8].try_into().unwrap()
}

struct Rd<'a> { b: &'a [u8], i: usize }
impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], &'static str> { let e = self.i.checked_add(n).ok_or("truncated")?; let s = self.b.get(self.i..e).ok_or("truncated")?; self.i = e; Ok(s) }
    fn u8(&mut self) -> Result<u8, &'static str> { Ok(self.take(1)?[0]) }
    fn sv(&mut self) -> Result<usize, &'static str> {
        let mut v = 0usize; for k in 0..3 { let b = self.u8()?; v |= ((b & 0x7f) as usize) << (7 * k); if b & 0x80 == 0 { return Ok(v) } } Err("bad_shortvec")
    }
}

#[derive(Clone, Debug)]
pub struct Ix { pub program: usize, pub accounts: Vec<usize>, pub data: Vec<u8> }
#[derive(Clone, Debug)]
pub struct Lookup { pub table: [u8; 32], pub writable: Vec<u8>, pub readonly: Vec<u8> }
#[derive(Clone, Debug)]
pub struct SolTx {
    pub signatures: Vec<[u8; 64]>, pub version: Option<u8>, pub header: [u8; 3], pub keys: Vec<[u8; 32]>,
    pub blockhash: [u8; 32], pub ixs: Vec<Ix>, pub lookups: Vec<Lookup>, pub message: Vec<u8>,
    /// v1 (SIMD-0385) transaction config: (mask, priority_fee_lamports, compute_unit_limit, loaded_accounts_data_size_limit, heap_size).
    pub config: Option<V1Config>,
}
#[derive(Clone, Debug, Default)]
pub struct V1Config { pub mask: u32, pub priority_fee: Option<u64>, pub cu_limit: Option<u32>, pub loaded_data_limit: Option<u32>, pub heap_size: Option<u32> }

/// v1 wire format (SIMD-0385, prefix 0x81): header, u32 config mask, blockhash, u8 counts, inline addresses,
/// config values, fixed instruction headers then payloads, signatures at the tail. Applies the SIMD's
/// sanitization rules (size <= 4096, <= 12 signatures, <= 64 addresses / instructions, no duplicate
/// addresses, both priority-fee bits or neither, heap 32..256 KiB in 1 KiB steps, no unknown mask bits).
fn parse_v1(raw: &[u8]) -> Result<SolTx, &'static str> {
    if raw.len() > 4096 { return Err("v1_too_large") }
    let mut r = Rd { b: raw, i: 1 };
    let header: [u8; 3] = r.take(3)?.try_into().unwrap();
    let mask = u32::from_le_bytes(r.take(4)?.try_into().unwrap());
    let blockhash = r.take(32)?.try_into().unwrap();
    let ni = r.u8()? as usize; let na = r.u8()? as usize;
    if ni > 64 || na > 64 { return Err("v1_limits") }
    let mut keys: Vec<[u8; 32]> = Vec::new(); for _ in 0..na { keys.push(r.take(32)?.try_into().unwrap()) }
    if mask & !0x1f != 0 { return Err("v1_unknown_config_bits") }
    if (mask & 1) != ((mask >> 1) & 1) { return Err("v1_priority_fee_bits") }
    let mut c = V1Config { mask, ..Default::default() };
    let w = |r: &mut Rd| -> Result<u32, &'static str> { Ok(u32::from_le_bytes(r.take(4)?.try_into().unwrap())) };
    if mask & 3 == 3 { c.priority_fee = Some(u64::from_le_bytes(r.take(8)?.try_into().unwrap())) }
    if mask & 4 != 0 { c.cu_limit = Some(w(&mut r)?) }
    if mask & 8 != 0 { c.loaded_data_limit = Some(w(&mut r)?) }
    if mask & 16 != 0 { let h = w(&mut r)?; if h % 1024 != 0 || !(32 * 1024..=256 * 1024).contains(&h) { return Err("v1_heap_size") } c.heap_size = Some(h) }
    let mut hdrs = Vec::new(); for _ in 0..ni { let b = r.take(4)?; hdrs.push((b[0] as usize, b[1] as usize, u16::from_le_bytes([b[2], b[3]]) as usize)) }
    let mut ixs = Vec::new();
    for (program, nacc, nd) in hdrs { let accounts = r.take(nacc)?.iter().map(|&x| x as usize).collect(); ixs.push(Ix { program, accounts, data: r.take(nd)?.to_vec() }) }
    let ms = r.i; let ns = header[0] as usize;
    if ns > 12 { return Err("too_many_signatures") }
    let mut signatures = Vec::new(); for _ in 0..ns { signatures.push(r.take(64)?.try_into().unwrap()) }
    if r.i != raw.len() { return Err("trailing_bytes") }
    if ns == 0 || header[1] as usize >= ns || ns + header[2] as usize > na { return Err("bad_header") }
    let mut sorted = keys.clone(); sorted.sort(); sorted.dedup(); if sorted.len() != na { return Err("v1_duplicate_address") }
    for ix in &ixs { if ix.program >= na || ix.accounts.iter().any(|&a| a >= na) { return Err("bad_account_index") } }
    Ok(SolTx { signatures, version: Some(1), header, keys, blockhash, ixs, lookups: vec![], message: raw[..ms].to_vec(), config: Some(c) })
}
/// Parse a wire transaction (signatures + legacy or v0 message). Rejects trailing bytes and bad indices.
pub fn parse_tx(raw: &[u8]) -> Result<SolTx, &'static str> {
    match raw.first() { Some(0x81) => return parse_v1(raw), Some(&b) if b > 0x81 && b & 0x80 != 0 => return Err("unsupported_version"), _ => {} }
    let mut r = Rd { b: raw, i: 0 };
    let ns = r.sv()?; if ns > 64 { return Err("too_many_signatures") }
    let mut signatures = Vec::new(); for _ in 0..ns { signatures.push(r.take(64)?.try_into().unwrap()) }
    let ms = r.i; let mut v = None;
    let mut first = r.u8()?;
    if first & 0x80 != 0 { let ver = first & 0x7f; if ver != 0 { return Err("unsupported_version") } v = Some(0); first = r.u8()? }
    let header = [first, r.u8()?, r.u8()?];
    let nk = r.sv()?; let mut keys = Vec::new(); for _ in 0..nk { keys.push(r.take(32)?.try_into().unwrap()) }
    let blockhash = r.take(32)?.try_into().unwrap();
    let ni = r.sv()?; let mut ixs = Vec::new();
    for _ in 0..ni {
        let program = r.u8()? as usize; let na = r.sv()?; let accounts = r.take(na)?.iter().map(|&x| x as usize).collect();
        let nd = r.sv()?; ixs.push(Ix { program, accounts, data: r.take(nd)?.to_vec() });
    }
    let mut lookups = Vec::new();
    if v.is_some() { let nl = r.sv()?; for _ in 0..nl {
        let table = r.take(32)?.try_into().unwrap(); let w = r.sv()?; let writable = r.take(w)?.to_vec(); let ro = r.sv()?; lookups.push(Lookup { table, writable, readonly: r.take(ro)?.to_vec() });
    } }
    if r.i != raw.len() { return Err("trailing_bytes") }
    if (header[0] as usize) != ns { return Err("signature_count_mismatch") }
    if (header[0] as usize) > nk || (header[1] as usize) > header[0] as usize || (header[2] as usize) > nk - header[0] as usize { return Err("bad_header") }
    let total = nk + lookups.iter().map(|l| l.writable.len() + l.readonly.len()).sum::<usize>();
    for ix in &ixs { if ix.program >= nk || ix.accounts.iter().any(|&a| a >= total) { return Err("bad_account_index") } }
    Ok(SolTx { signatures, version: v, header, message: raw[ms..].to_vec(), keys, blockhash, ixs, lookups, config: None })
}
impl SolTx {
    fn key(&self, i: usize) -> String { self.keys.get(i).map(|k| b58enc(k)).unwrap_or_else(|| format!("lookup#{}", i - self.keys.len())) }
    pub fn is_writable(&self, i: usize) -> bool {
        let (s, rs, ru) = (self.header[0] as usize, self.header[1] as usize, self.header[2] as usize); let n = self.keys.len();
        if i < s { i < s - rs } else if i < n { i < n - ru } else { i - n < self.lookups.iter().map(|l| l.writable.len()).sum::<usize>() }
    }
    /// Transaction id = first signature (base58).
    pub fn txid(&self) -> Option<String> { self.signatures.first().map(|s| b58enc(s)) }
    /// ed25519-verify each signature against its signer key over the message bytes. All-zero = unsigned.
    pub fn verify_signatures(&self) -> Vec<Value> {
        self.signatures.iter().enumerate().map(|(i, s)| {
            let st = if s.iter().all(|&b| b == 0) { "unsigned" } else {
                if ed25519_verify(&self.keys[i], &self.message, s) { "valid" } else { "invalid" } };
            json!({"signer": self.key(i), "status": st})
        }).collect()
    }
}
/// Verify-only ed25519 (RFC 8032, cofactorless, strict: canonical S, non-small-order A and R),
/// built on curve25519-dalek so the wasm build carries no signing code.
pub fn ed25519_verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
    use bitcoin::hashes::{sha512, HashEngine};
    let Some(a) = CompressedEdwardsY(*pk).decompress() else { return false };
    let r_bytes: [u8; 32] = sig[..32].try_into().unwrap();
    let Some(r) = CompressedEdwardsY(r_bytes).decompress() else { return false };
    if a.is_small_order() || r.is_small_order() { return false }
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(sig[32..].try_into().unwrap())) else { return false };
    let mut e = sha512::HashEngine::default(); e.input(&r_bytes); e.input(pk); e.input(msg);
    let k = Scalar::from_bytes_mod_order_wide(&sha512::Hash::from_engine(e).to_byte_array());
    EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &-a, &s).compress().to_bytes() == r_bytes
}
fn u64le(d: &[u8], o: usize) -> Option<u64> { d.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap())) }
/// Decode one instruction to {program, kind, ...}. Known: System, SPL Token / Token-2022, ATA, ComputeBudget, Memo.
fn decode_ix(t: &SolTx, ix: &Ix) -> Value {
    let p = t.key(ix.program); let a = |k: usize| ix.accounts.get(k).map(|&i| t.key(i)).unwrap_or_default(); let d = &ix.data;
    let tag32 = d.get(..4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    let mut v = match p.as_str() {
        SYSTEM => match tag32 {
            Some(2) if d.len() == 12 => json!({"kind": "system_transfer", "from": a(0), "to": a(1), "lamports": u64le(d, 4).unwrap().to_string()}),
            Some(0) => json!({"kind": "system_create_account", "from": a(0), "new": a(1), "lamports": u64le(d, 4).map(|x| x.to_string())}),
            Some(1) => json!({"kind": "system_assign", "account": a(0)}),
            Some(4) => json!({"kind": "system_advance_nonce", "nonce": a(0), "authority": a(2)}),
            Some(7) => json!({"kind": "system_authorize_nonce", "nonce": a(0)}),
            _ => json!({"kind": "system_other"}),
        },
        TOKEN | TOKEN_2022 => match d.first() {
            Some(3) if d.len() == 9 => json!({"kind": "token_transfer", "source": a(0), "destination": a(1), "authority": a(2), "amount": u64le(d, 1).unwrap().to_string()}),
            Some(12) if d.len() == 10 => json!({"kind": "token_transfer_checked", "source": a(0), "mint": a(1), "destination": a(2), "authority": a(3), "amount": u64le(d, 1).unwrap().to_string(), "decimals": d[9]}),
            Some(4) => json!({"kind": "token_approve", "source": a(0), "delegate": a(1), "amount": u64le(d, 1).map(|x| x.to_string())}),
            Some(13) => json!({"kind": "token_approve_checked", "source": a(0), "delegate": a(2)}),
            Some(6) => json!({"kind": "token_set_authority", "account": a(0), "authority_type": d.get(1), "new_authority": if d.get(2) == Some(&1) { d.get(3..35).map(b58enc) } else { None }}),
            Some(9) => json!({"kind": "token_close_account", "account": a(0), "destination": a(1)}),
            Some(7) | Some(14) => json!({"kind": "token_mint_to", "mint": a(0)}),
            Some(8) | Some(15) => json!({"kind": "token_burn", "account": a(0)}),
            _ => json!({"kind": "token_other"}),
        },
        ATA => json!({"kind": "ata_create", "payer": a(0), "ata": a(1), "owner": a(2), "mint": a(3), "idempotent": d.first() == Some(&1)}),
        COMPUTE_BUDGET => match d.first() {
            Some(2) => json!({"kind": "compute_unit_limit", "units": d.get(1..5).map(|b| u32::from_le_bytes(b.try_into().unwrap()))}),
            Some(3) => json!({"kind": "compute_unit_price", "micro_lamports": u64le(d, 1).map(|x| x.to_string())}),
            _ => json!({"kind": "compute_budget_other"}),
        },
        MEMO => json!({"kind": "memo", "text": String::from_utf8_lossy(d)}),
        _ => json!({"kind": "unknown", "accounts": ix.accounts.iter().map(|&i| t.key(i)).collect::<Vec<_>>(), "data": crate::hex_enc(d)}),
    };
    v["program"] = json!(p); v["program_index"] = json!(ix.program); v["account_indexes"] = json!(ix.accounts); v["data_hex"] = json!(crate::hex_enc(d)); v
}
/// JSON decode of a wire transaction.
pub fn decode_tx(raw: &[u8]) -> Result<Value, &'static str> {
    let t = parse_tx(raw)?;
    Ok(json!({
        "version": t.version.map(|v| json!(v)).unwrap_or(json!("legacy")),
        "txid": t.txid(), "fee_payer": t.key(0), "recent_blockhash": b58enc(&t.blockhash),
        "num_required_signatures": t.header[0], "accounts": (0..t.keys.len()).map(|i| json!({"pubkey": t.key(i), "signer": i < t.header[0] as usize, "writable": t.is_writable(i)})).collect::<Vec<_>>(),
        "address_table_lookups": t.lookups.iter().map(|l| json!({"table": b58enc(&l.table), "writable": l.writable, "readonly": l.readonly})).collect::<Vec<_>>(),
        "instructions": t.ixs.iter().map(|ix| decode_ix(&t, ix)).collect::<Vec<_>>(),
        "signatures": t.verify_signatures(),
        "message_hex": crate::hex_enc(&t.message),
        "config": t.config.as_ref().map(|c| json!({"mask": c.mask, "priority_fee_lamports": c.priority_fee.map(|x| x.to_string()), "compute_unit_limit": c.cu_limit, "loaded_accounts_data_size_limit": c.loaded_data_limit, "heap_size": c.heap_size})),
    }))
}
/// Verify a transaction against expectations. `expect`: {owner?, to?, lamports? (decimal), mint?, amount?, allow_programs?: [..]}.
/// Fails closed: ok only if every check passes and no risky instruction is present.
pub fn verify_tx(raw: &[u8], expect: &Value) -> Result<Value, &'static str> {
    let d = decode_tx(raw)?; let t = parse_tx(raw)?;
    let mut fail: Vec<String> = Vec::new(); let mut warn: Vec<String> = Vec::new();
    let s = |k: &str| expect.get(k).and_then(|v| v.as_str()).map(str::to_string);
    if let Some(o) = s("owner") { if d["fee_payer"] != o.as_str() { fail.push("fee_payer_not_owner".into()) } }
    for sg in d["signatures"].as_array().unwrap() { if sg["status"] == "invalid" { fail.push("bad_signature".into()) } }
    if !t.lookups.is_empty() { warn.push("address_lookup_tables_unresolved".into()) }
    let allow: Vec<String> = expect.get("allow_programs").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    let (mut lam, mut tok) = (0u128, 0u128); let mut seen_to = false;
    for ix in d["instructions"].as_array().unwrap() {
        let k = ix["kind"].as_str().unwrap();
        match k {
            "system_transfer" => { lam += ix["lamports"].as_str().unwrap().parse::<u128>().unwrap();
                if let Some(to) = s("to") { if ix["to"] == to.as_str() { seen_to = true } else { fail.push(format!("unexpected_recipient:{}", ix["to"].as_str().unwrap())) } } }
            "token_transfer" | "token_transfer_checked" => { tok += ix["amount"].as_str().unwrap().parse::<u128>().unwrap();
                if let Some(m) = s("mint") { if k == "token_transfer_checked" && ix["mint"] != m.as_str() { fail.push("wrong_mint".into()) } if k == "token_transfer" { warn.push("token_transfer_unchecked_mint".into()) } }
                if let Some(to) = s("to") { if ix["destination"] == to.as_str() { seen_to = true } else { fail.push(format!("unexpected_token_destination:{}", ix["destination"].as_str().unwrap())) } } }
            "compute_unit_limit" | "compute_unit_price" | "memo" | "ata_create" | "system_advance_nonce" => {}
            "token_approve" | "token_approve_checked" => fail.push("token_approve".into()),
            "token_set_authority" => fail.push("token_set_authority".into()),
            "token_close_account" => { if let Some(o) = s("owner") { if ix["destination"] != o.as_str() { fail.push("close_account_to_other".into()) } } else { warn.push("close_account".into()) } }
            "system_assign" | "system_authorize_nonce" => fail.push(k.to_string()),
            _ => { let p = ix["program"].as_str().unwrap(); if !allow.iter().any(|a| a == p) { fail.push(format!("unknown_program:{p}")) } }
        }
    }
    if s("to").is_some() && !seen_to { fail.push("recipient_not_paid".into()) }
    if let Some(l) = s("lamports") { if l.parse::<u128>().ok() != Some(lam) { fail.push("lamports_mismatch".into()) } }
    if let Some(a) = s("amount") { if a.parse::<u128>().ok() != Some(tok) { fail.push("amount_mismatch".into()) } }
    // Only signatures that ed25519-verify count as signed; invalid ones fail the whole check.
    let st = |w: &str| d["signatures"].as_array().unwrap().iter().filter(|x| x["status"] == w).count();
    let (nv, ni, nu) = (st("valid"), st("invalid"), st("unsigned"));
    if nu > 0 { warn.push("unsigned".into()) }
    fail.sort(); fail.dedup();
    Ok(json!({"ok": fail.is_empty(), "failures": fail, "warnings": warn, "txid": d["txid"],
        "signatures_valid": nv, "signatures_invalid": ni, "signatures_unsigned": nu, "fully_signed": ni == 0 && nu == 0 && nv > 0, "lamports": lam.to_string(), "token_amount": tok.to_string()}))
}

#[cfg(test)]
mod t {
    use super::*;
    // Vectors: solders 0.2x (find_program_address, is_on_curve, Transaction / VersionedTransaction bytes).
    const OWNER: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xyybapC8G4wEGGkZwyTDt1v";
    pub const LEGACY: &str = "010e63fc82a30c1b2e0587e81cce44e17d6b9e756e1494fc5b34efce519239d2b78128fa5e9aa95018fdc59649bea55c03c07a8a001f9060a356f1cdd50234f00f010001038a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c7e8c088760bfde1dddcf32c17f209b8242ee52aaf131facd88d0ea2c6d0b06f20000000000000000000000000000000000000000000000000000000000000000c49ae77603782054f17a9decea43b444eba0edb12c6f1d31c6e0e4a84bf052eb01020200010c0200000087d6120000000000";
    pub const V0: &str = "010283e65523da6db1e3383b8d3ff3d769dcee9de3c5993f33d3d18998cb8fc285d2cf6800f8f8e8b21312ea3d489a4f4495dc8baedd690b3d7ddf903b8dc5010f80010001038a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c7e8c088760bfde1dddcf32c17f209b8242ee52aaf131facd88d0ea2c6d0b06f20000000000000000000000000000000000000000000000000000000000000000c49ae77603782054f17a9decea43b444eba0edb12c6f1d31c6e0e4a84bf052eb01020200010c0200000087d612000000000000";
    fn h(s: &str) -> Vec<u8> { crate::hex_dec(s).unwrap() }
    #[test] fn rfc8032_vector1() {
        let pk: [u8; 32] = h("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").try_into().unwrap();
        let mut sig: [u8; 64] = h("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b").try_into().unwrap();
        assert!(ed25519_verify(&pk, b"", &sig)); assert!(!ed25519_verify(&pk, b"x", &sig));
        sig[63] |= 0xf0; assert!(!ed25519_verify(&pk, b"", &sig)); // non-canonical S
    }
    #[test] fn pda_ata() {
        let (o, m, tk) = (pubkey(OWNER).unwrap(), pubkey(USDC).unwrap(), pubkey(TOKEN).unwrap());
        let (a, b) = associated_token_address(&o, &m, &tk).unwrap();
        assert_eq!((b58enc(&a).as_str(), b), ("4W6igchc7ZieLsp9grU642c2mBcVSeC9bo5jfn2iBSpe", 255));
        let (p, b) = find_program_address(&[b"vault", &o], &tk).unwrap();
        assert_eq!((b58enc(&p).as_str(), b), ("Duvp5BivpbCj7kPqjzGFUMRuwmv1BBNMp4FvSsLkjZAZ", 254));
        assert!(is_on_curve(&o)); assert!(!is_on_curve(&a));
        assert_eq!(crate::hex_enc(anchor_discriminator("initialize")), "afaf6d1f0d989bed");
    }
    #[test] fn decode_verify() {
        for (raw, ver) in [(LEGACY, json!("legacy")), (V0, json!(0))] {
            let d = decode_tx(&h(raw)).unwrap();
            assert_eq!(d["version"], ver); assert_eq!(d["fee_payer"], "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9");
            assert_eq!(d["instructions"][0]["kind"], "system_transfer"); assert_eq!(d["instructions"][0]["lamports"], "1234567");
            assert_eq!(d["signatures"][0]["status"], "valid");
            let v = verify_tx(&h(raw), &json!({"owner": "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9", "to": OWNER, "lamports": "1234567"})).unwrap();
            assert_eq!(v["ok"], true, "{v}");
            let v = verify_tx(&h(raw), &json!({"to": USDC})).unwrap(); assert_eq!(v["ok"], false);
        }
        assert_eq!(decode_tx(&h(LEGACY)).unwrap()["txid"], "HgsP3r893euWYPRfiZv5b8P6SrWhx3z2whQWMfpkhFwgEgnxQMXmufFmXa4c9c9WaFRkWnd6AdNmzHjJJqvLDLA");
        let mut bad = h(LEGACY); let n = bad.len(); bad[n - 1] ^= 1;
        assert_eq!(decode_tx(&bad).unwrap()["signatures"][0]["status"], "invalid");
        assert_eq!(verify_tx(&bad, &json!({})).unwrap()["ok"], false);
        assert!(parse_tx(&h(&LEGACY[..LEGACY.len() - 2])).is_err());
        let mut tr = h(LEGACY); tr.push(0); assert_eq!(parse_tx(&tr).unwrap_err(), "trailing_bytes");
        let d = decode_tx(&h(LEGACY)).unwrap()["instructions"][0].clone();
        assert_eq!(d["program_index"], 2); assert_eq!(d["account_indexes"], json!([0, 1])); assert_eq!(d["data_hex"], "0200000087d6120000000000");
    }
    #[test] fn invalid_signature_fails_closed() {
        let mut bad = h(LEGACY); bad[1] ^= 1; // corrupt R of the only signature
        let v = verify_tx(&bad, &json!({"owner": "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9", "to": OWNER, "lamports": "1234567"})).unwrap();
        assert_eq!(v["ok"], false); assert!(v["failures"].as_array().unwrap().contains(&json!("bad_signature")));
        assert_eq!(v["signatures_valid"], 0); assert_eq!(v["signatures_invalid"], 1); assert_eq!(v["fully_signed"], false);
        let v = verify_tx(&h(LEGACY), &json!({})).unwrap(); assert_eq!(v["fully_signed"], true); assert_eq!(v["signatures_valid"], 1);
    }
    #[test] fn on_curve_edges_match_dalek() {
        // Expected values from solders Pubkey.is_on_curve (Solana's curve25519-dalek decompress).
        let mut x0 = [0u8; 32]; x0[0] = 1; x0[31] = 0x80; assert!(is_on_curve(&x0)); // x = 0 with sign bit
        let mut p1 = [0xffu8; 32]; p1[0] = 0xee; p1[31] = 0x7f; assert!(is_on_curve(&p1)); // y = p+1 (non-canonical 1)
        let mut p0 = p1; p0[0] = 0xed; assert!(is_on_curve(&p0)); // y = p (non-canonical 0)
        p1[31] = 0xff; assert!(is_on_curve(&p1)); // y = p+1, sign bit set
        let mut p2 = p0; p2[0] = 0xef; assert!(!is_on_curve(&p2)); // y = p+2 (2 is not a valid y)
    }
}
