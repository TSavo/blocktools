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
}
