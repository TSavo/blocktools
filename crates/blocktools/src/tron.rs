//! Tron transaction id and raw_data decode (protobuf), public data only.
//! txID = sha256(raw_data bytes). Contracts decoded: Transfer, TransferAsset, TriggerSmartContract
//! (TRC-20 transfer / approve recognised), others reported by type with their owner address.
use bitcoin::hashes::{sha256, Hash};
use serde_json::{json, Value};

pub fn address(b: &[u8]) -> Option<String> { (b.len() == 21 && b[0] == 0x41).then(|| bitcoin::base58::encode_check(b)) }
pub fn txid(raw_data: &[u8]) -> String { crate::hex_enc(sha256::Hash::hash(raw_data).to_byte_array()) }

enum F<'a> { V(u64), B(&'a [u8]) }
fn varint(b: &[u8], i: &mut usize) -> Result<u64, &'static str> {
    let mut v = 0u64; for k in 0..10 { let x = *b.get(*i).ok_or("truncated")?; *i += 1; v |= ((x & 0x7f) as u64) << (7 * k); if x & 0x80 == 0 { return Ok(v) } } Err("bad_varint")
}
fn fields(b: &[u8]) -> Result<Vec<(u64, F<'_>)>, &'static str> {
    let (mut i, mut o) = (0, vec![]);
    while i < b.len() {
        let k = varint(b, &mut i)?; let (n, w) = (k >> 3, k & 7);
        match w { 0 => o.push((n, F::V(varint(b, &mut i)?))),
            2 => { let l = varint(b, &mut i)? as usize; let e = i.checked_add(l).ok_or("truncated")?; o.push((n, F::B(b.get(i..e).ok_or("truncated")?))); i = e }
            1 => { i += 8; if i > b.len() { return Err("truncated") } } 5 => { i += 4; if i > b.len() { return Err("truncated") } }
            _ => return Err("bad_wire_type") }
    }
    Ok(o)
}
fn get_b<'a>(f: &'a [(u64, F<'a>)], n: u64) -> Option<&'a [u8]> { f.iter().find_map(|(k, v)| match v { F::B(b) if *k == n => Some(*b), _ => None }) }
fn get_v(f: &[(u64, F<'_>)], n: u64) -> Option<u64> { f.iter().find_map(|(k, v)| match v { F::V(x) if *k == n => Some(*x), _ => None }) }
fn addr_at(f: &[(u64, F<'_>)], n: u64) -> Value { get_b(f, n).map(|b| address(b).map(Value::from).unwrap_or_else(|| crate::hex_enc(b).into())).unwrap_or(Value::Null) }

fn contract(c: &[u8]) -> Result<Value, &'static str> {
    let f = fields(c)?; let ty = get_v(&f, 1).unwrap_or(0);
    let any = fields(get_b(&f, 2).ok_or("no_parameter")?)?;
    let url = String::from_utf8_lossy(get_b(&any, 1).unwrap_or_default()).to_string();
    let p = fields(get_b(&any, 2).unwrap_or_default())?;
    let name = url.rsplit('.').next().unwrap_or("").to_string();
    let mut v = json!({"type": name, "type_id": ty, "owner": addr_at(&p, 1)});
    match name.as_str() {
        "TransferContract" => { v["to"] = addr_at(&p, 2); v["amount_sun"] = get_v(&p, 3).unwrap_or(0).to_string().into() }
        "TransferAssetContract" => { v["asset"] = String::from_utf8_lossy(get_b(&p, 1).unwrap_or_default()).into(); v["owner"] = addr_at(&p, 2); v["to"] = addr_at(&p, 3); v["amount"] = get_v(&p, 4).unwrap_or(0).to_string().into() }
        "TriggerSmartContract" => {
            v["contract"] = addr_at(&p, 2); v["call_value_sun"] = get_v(&p, 3).unwrap_or(0).to_string().into();
            let d = get_b(&p, 4).unwrap_or_default(); v["data"] = crate::hex_enc(d).into();
            if d.len() == 68 && (d[..4] == [0xa9, 0x05, 0x9c, 0xbb] || d[..4] == [0x09, 0x5e, 0xa7, 0xb3]) {
                let mut a = vec![0x41]; a.extend_from_slice(&d[16..36]);
                let amt = &d[36..68]; let dec = u256_dec(amt);
                v[if d[0] == 0xa9 { "trc20_transfer" } else { "trc20_approve" }] = json!({ if d[0] == 0xa9 { "to" } else { "spender" }: address(&a), "amount": dec });
            }
        }
        _ => {}
    }
    Ok(v)
}
fn u256_dec(b: &[u8]) -> String {
    let mut n = b.to_vec(); let mut s = vec![];
    while n.iter().any(|&x| x != 0) { let mut r = 0u32; for x in n.iter_mut() { let c = (r << 8) | *x as u32; *x = (c / 10) as u8; r = c % 10 } s.push(b'0' + r as u8) }
    if s.is_empty() { "0".into() } else { s.reverse(); String::from_utf8(s).unwrap() }
}
/// Decode `raw_data` bytes (tronweb `raw_data_hex`) or a full signed Transaction (raw_data = field 1, signatures = field 2).
pub fn decode(bytes: &[u8]) -> Result<Value, &'static str> {
    let top = fields(bytes)?;
    // A full Transaction has field 1 = raw_data (bytes) and optional field 2 signatures; raw_data itself starts with field 1 ref_block_bytes (2 bytes).
    let (raw, sigs): (&[u8], usize) = match get_b(&top, 1) { Some(r) if r.len() > 2 && fields(r).map(|f| get_b(&f, 11).is_some()).unwrap_or(false) => (r, top.iter().filter(|(k, _)| *k == 2).count()), _ => (bytes, 0) };
    let f = fields(raw)?;
    let cs: Vec<Value> = f.iter().filter_map(|(k, v)| match v { F::B(b) if *k == 11 => Some(contract(b)), _ => None }).collect::<Result<_, _>>()?;
    if cs.is_empty() { return Err("no_contract") }
    Ok(json!({
        "txid": txid(raw), "ref_block_bytes": get_b(&f, 1).map(crate::hex_enc), "ref_block_hash": get_b(&f, 4).map(crate::hex_enc),
        "expiration": get_v(&f, 8), "timestamp": get_v(&f, 14), "fee_limit_sun": get_v(&f, 18).map(|x| x.to_string()),
        "memo": get_b(&f, 10).map(|b| String::from_utf8_lossy(b).to_string()), "contracts": cs, "signatures": sigs, "raw_data_hex": crate::hex_enc(raw),
    }))
}

// ---- Unsigned builder (TransferContract / TRC-20 transfer), field order as java-tron serializes. ----
fn pv(o: &mut Vec<u8>, mut v: u64) { loop { let b = (v & 0x7f) as u8; v >>= 7; if v == 0 { o.push(b); return } o.push(b | 0x80) } }
fn pb(o: &mut Vec<u8>, n: u64, b: &[u8]) { pv(o, n << 3 | 2); pv(o, b.len() as u64); o.extend_from_slice(b) }
fn pn(o: &mut Vec<u8>, n: u64, v: u64) { pv(o, n << 3); pv(o, v) }

/// What a Tron transfer moves. `Sweep` sends `balance - reserve_sun`; Tron fees (bandwidth burn) are
/// not knowable offline, so the caller chooses the reserve (0 when free bandwidth covers it).
pub enum TronAmount { Send(u64), Sweep { balance: u64, reserve_sun: u64 }, Trc20 { contract: [u8; 21], amount: u128, fee_limit_sun: u64 } }
/// Reference block: `ref_block_bytes` = block number bytes 6..8, `ref_block_hash` = block id bytes 8..16.
pub struct TronPlan { pub from: [u8; 21], pub to: [u8; 21], pub ref_block_bytes: [u8; 2], pub ref_block_hash: [u8; 8],
    pub expiration_ms: u64, pub timestamp_ms: u64, pub memo: Option<Vec<u8>>, pub amount: TronAmount }

/// Parse a base58check T-address into its 21 bytes (0x41 prefix).
pub fn parse_address(s: &str) -> Result<[u8; 21], &'static str> {
    let b = bitcoin::base58::decode_check(s).map_err(|_| "bad_address")?;
    if b.len() != 21 || b[0] != 0x41 { return Err("bad_address") }
    Ok(b.try_into().unwrap())
}

/// Unsigned `raw_data` bytes; txid = sha256 of these; sign the txid elsewhere.
pub fn build_transfer(p: &TronPlan) -> Result<Vec<u8>, &'static str> {
    if p.from == p.to { return Err("from_equals_to") }
    if p.expiration_ms <= p.timestamp_ms { return Err("expiration_not_after_timestamp") }
    let mut par = vec![]; let (url, ty, fee_limit);
    match p.amount {
        TronAmount::Send(_) | TronAmount::Sweep { .. } => {
            let v = match p.amount { TronAmount::Send(v) => v, TronAmount::Sweep { balance, reserve_sun } => balance.checked_sub(reserve_sun).ok_or("balance does not cover reserve")?, _ => unreachable!() };
            if v == 0 { return Err("zero_amount") }
            pb(&mut par, 1, &p.from); pb(&mut par, 2, &p.to); pn(&mut par, 3, v);
            url = "type.googleapis.com/protocol.TransferContract"; ty = 1; fee_limit = None;
        }
        TronAmount::Trc20 { contract, amount, fee_limit_sun } => {
            if amount == 0 { return Err("zero_amount") }
            if fee_limit_sun == 0 { return Err("zero_fee_limit") }
            let mut d = vec![0xa9, 0x05, 0x9c, 0xbb]; d.extend([0u8; 12]); d.extend(&p.to[1..]); d.extend([0u8; 16]); d.extend(amount.to_be_bytes());
            pb(&mut par, 1, &p.from); pb(&mut par, 2, &contract); pb(&mut par, 4, &d);
            url = "type.googleapis.com/protocol.TriggerSmartContract"; ty = 31; fee_limit = Some(fee_limit_sun);
        }
    }
    let mut any = vec![]; pb(&mut any, 1, url.as_bytes()); pb(&mut any, 2, &par);
    let mut c = vec![]; pn(&mut c, 1, ty); pb(&mut c, 2, &any);
    let mut o = vec![];
    pb(&mut o, 1, &p.ref_block_bytes); pb(&mut o, 4, &p.ref_block_hash); pn(&mut o, 8, p.expiration_ms);
    if let Some(m) = &p.memo { pb(&mut o, 10, m) }
    pb(&mut o, 11, &c); pn(&mut o, 14, p.timestamp_ms);
    if let Some(f) = fee_limit { pn(&mut o, 18, f) }
    Ok(o)
}

#[cfg(test)]
mod t {
    use super::*;
    // Mainnet block 60,000,000 (TronGrid getblockbynum): txID and contract fields from the node's JSON.
    pub const TRC20: &str = "0a0286ec220805d9f8c360a410c44093b39ce2e4315aae01081f12a9010a31747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a1541595c4a379ab80c202f0372bbf9bbf3fad6ca8768121541a614f803b6fd780986a42c78ec9c7f77e6ded13c2244a9059cbb000000000000000000000041641b18d083a10dee3cfe1d6b8871a55e2eb3ac42000000000000000000000000000000000000000000000000000000005395db9062077363726970747370939187d1e4319001a8a5d810";
    pub const TRX: &str = "0a0286ec220805d9f8c360a410c440d0d78ad1e4315a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a15418380d3e5288ecab17c89827a4dd17652d13e7264121541ee0a85ee960f6da8c50292d3dd07ea291c133ed1180170859087d1e431";
    pub const ASSET: &str = "0a0286ec220805d9f8c360a410c440d0d78ad1e4315a77080212730a32747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e736665724173736574436f6e7472616374123d0a073130303530323712154158585057d3010bfd27d100157f93b7df4ea6dc1c1a154122100cdc332b393c9d69a4b637c4fdd9c05cfe69208097c68e2170a39887d1e431";
    fn h(s: &str) -> Vec<u8> { crate::hex_dec(s).unwrap() }
    #[test] fn mainnet() {
        let d = decode(&h(TRC20)).unwrap();
        assert_eq!(d["txid"], "9cfd805857f9a972388bb72bc86386787c93966fc4b526f7322e33d3074c7572");
        let c = &d["contracts"][0]; assert_eq!(c["type"], "TriggerSmartContract");
        assert_eq!(c["owner"], address(&h("41595c4a379ab80c202f0372bbf9bbf3fad6ca8768")).unwrap());
        assert_eq!(c["trc20_transfer"]["to"], address(&h("41641b18d083a10dee3cfe1d6b8871a55e2eb3ac42")).unwrap());
        assert_eq!(c["trc20_transfer"]["amount"], "1402330000"); assert_eq!(d["fee_limit_sun"], "35001000"); assert_eq!(d["expiration"], 1710676711827u64); assert_eq!(d["timestamp"], 1710640711827u64);
        let d = decode(&h(TRX)).unwrap();
        assert_eq!(d["txid"], "07755381b660a83a2767b8de974e88257797d2865c6dde14eccfe69c23717d00");
        assert_eq!(d["contracts"][0]["amount_sun"], "1"); assert_eq!(d["contracts"][0]["to"], address(&h("41ee0a85ee960f6da8c50292d3dd07ea291c133ed1")).unwrap());
        let d = decode(&h(ASSET)).unwrap();
        assert_eq!(d["txid"], "6188c5c1720f34502015b4d23f87582fca10950c6829cebb8f507899252c24d5");
        assert_eq!(d["contracts"][0]["asset"], "1005027"); assert_eq!(d["contracts"][0]["amount"], "8888880000");
        assert!(decode(&h(&TRX[..TRX.len() - 4])).is_err());
        // Full Transaction wrapper (raw_data = 1, one 65-byte signature = 2) gives the same txid.
        let raw = h(TRX); let mut w = vec![0x0a]; w.push(raw.len() as u8 | 0x80); w.push((raw.len() >> 7) as u8); w.extend(&raw); w.extend([0x12, 65]); w.extend([7u8; 65]);
        let d = decode(&w).unwrap(); assert_eq!(d["txid"], "07755381b660a83a2767b8de974e88257797d2865c6dde14eccfe69c23717d00"); assert_eq!(d["signatures"], 1);
    }
    /// Builder reproduces the mainnet raw_data bytes (block 60,000,000) from their decoded fields.
    #[test] fn builder_matches_mainnet() {
        let a = |x: &str| -> [u8; 21] { h(x).try_into().unwrap() };
        let rb = |d: &Value, k: &str| h(d[k].as_str().unwrap());
        for (hexs, amt) in [(TRX, None), (TRC20, Some(1402330000u128))] {
            let d = decode(&h(hexs)).unwrap(); let c = &d["contracts"][0];
            let from = parse_address(c["owner"].as_str().unwrap()).unwrap();
            let (to, amount) = match amt {
                None => (parse_address(c["to"].as_str().unwrap()).unwrap(), TronAmount::Send(1)),
                Some(v) => (parse_address(c["trc20_transfer"]["to"].as_str().unwrap()).unwrap(),
                    TronAmount::Trc20 { contract: parse_address(c["contract"].as_str().unwrap()).unwrap(), amount: v, fee_limit_sun: 35001000 }),
            };
            let p = TronPlan { from, to, ref_block_bytes: rb(&d, "ref_block_bytes").try_into().unwrap(), ref_block_hash: rb(&d, "ref_block_hash").try_into().unwrap(),
                expiration_ms: d["expiration"].as_u64().unwrap(), timestamp_ms: d["timestamp"].as_u64().unwrap(), memo: d["memo"].as_str().map(|m| m.as_bytes().to_vec()), amount };
            // The TRC-20 vector also carries raw_data.scripts (field 12, "scripts"), which the builder never emits.
            // That sender's wallet also left the 0x41 prefix inside the ABI address word; the builder emits the
            // standard 12 zero bytes + 20-byte address (what tronweb / Solidity abi.encode produce).
            assert_eq!(crate::hex_enc(build_transfer(&p).unwrap()), hexs.replace("620773637269707473", "").replace("000000000041641b18", "000000000000641b18"));
        }
        let p = |amount| TronPlan { from: a("41595c4a379ab80c202f0372bbf9bbf3fad6ca8768"), to: a("41641b18d083a10dee3cfe1d6b8871a55e2eb3ac42"), ref_block_bytes: [0; 2], ref_block_hash: [0; 8], expiration_ms: 2, timestamp_ms: 1, memo: None, amount };
        let d = decode(&build_transfer(&p(TronAmount::Sweep { balance: 1000, reserve_sun: 268 })).unwrap()).unwrap();
        assert_eq!(d["contracts"][0]["amount_sun"], "732");
        assert_eq!(build_transfer(&p(TronAmount::Sweep { balance: 1, reserve_sun: 2 })).unwrap_err(), "balance does not cover reserve");
        assert_eq!(build_transfer(&p(TronAmount::Send(0))).unwrap_err(), "zero_amount");
        // TRC-20 calldata: the ABI address word is 12 zero bytes + 20-byte address, never 0x41-prefixed
        // (Solidity >= 0.8 rejects dirty high bits). Check bytes, not just the decoder's view.
        let raw = build_transfer(&p(TronAmount::Trc20 { contract: a("41a614f803b6fd780986a42c78ec9c7f77e6ded13c"), amount: 5, fee_limit_sun: 1 })).unwrap();
        let d = decode(&raw).unwrap(); let data = h(d["contracts"][0]["data"].as_str().unwrap());
        assert_eq!(data.len(), 68); assert_eq!(&data[..4], &[0xa9, 0x05, 0x9c, 0xbb]);
        assert_eq!(&data[4..16], &[0u8; 12]); assert_eq!(&data[16..36], &h("41641b18d083a10dee3cfe1d6b8871a55e2eb3ac42")[1..]);
        assert_eq!(&data[36..67], &[0u8; 31]); assert_eq!(data[67], 5);
    }
}

/// Parse a transfer plan (the `tronBuildTransfer` JSON) into a [`TronPlan`]. Shared by wasm and the
/// `sol-tron-tx` CLI.
pub fn plan_from_json(v: &Value) -> Result<TronPlan, &'static str> {
    let a = |x: &Value| parse_address(x.as_str().unwrap_or(""));
    let n = |x: &Value| x.as_str().and_then(|s| s.parse::<u64>().ok()).or(x.as_u64()).ok_or("bad_number");
    let hx = |x: &Value, l: usize| crate::hex_dec(x.as_str().unwrap_or("")).filter(|b| b.len() == l).ok_or("bad_ref_block");
    let amount = if !v["amount_sun"].is_null() { TronAmount::Send(n(&v["amount_sun"])?) }
        else if v["sweep"].is_object() { TronAmount::Sweep { balance: n(&v["sweep"]["balance_sun"])?, reserve_sun: n(&v["sweep"]["reserve_sun"])? } }
        else if v["trc20"].is_object() { let t = &v["trc20"]; TronAmount::Trc20 { contract: a(&t["contract"])?,
            amount: t["amount"].as_str().and_then(|s| s.parse().ok()).ok_or("bad_number")?, fee_limit_sun: n(&t["fee_limit_sun"])? } }
        else { return Err("missing_amount") };
    Ok(TronPlan { from: a(&v["from"])?, to: a(&v["to"])?, ref_block_bytes: hx(&v["ref_block_bytes"], 2)?.try_into().unwrap(),
        ref_block_hash: hx(&v["ref_block_hash"], 8)?.try_into().unwrap(), expiration_ms: n(&v["expiration_ms"])?, timestamp_ms: n(&v["timestamp_ms"])?,
        memo: v["memo"].as_str().map(|m| m.as_bytes().to_vec()), amount })
}
