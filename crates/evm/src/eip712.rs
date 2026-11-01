//! EIP-712 typed structured data: encodeType, hashStruct, domain separator, signing digest, and
//! signer recovery (secp256k1 ecrecover). Offline; nothing is signed here.
use crate::abi::{Param, Ty};
use crate::{checksum_address, hex, keccak, unhex};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

fn types_of(td: &Value) -> Result<&Map<String, Value>, String> { td.get("types").and_then(Value::as_object).ok_or_else(|| "missing_types".into()) }

fn fields<'a>(types: &'a Map<String, Value>, t: &str) -> Result<Vec<(&'a str, &'a str)>, String> {
    types.get(t).and_then(Value::as_array).ok_or_else(|| format!("unknown_type:{t}"))?.iter().map(|f| {
        Ok((f.get("name").and_then(Value::as_str).ok_or("field_needs_name")?, f.get("type").and_then(Value::as_str).ok_or("field_needs_type")?))
    }).collect()
}

fn base(t: &str) -> &str { t.split('[').next().unwrap_or(t) }

fn deps(types: &Map<String, Value>, t: &str, out: &mut BTreeSet<String>, depth: usize) -> Result<(), String> {
    if depth > 32 { return Err("types_too_deep".into()); }
    for (_, ft) in fields(types, t)? { let b = base(ft); if types.contains_key(b) && out.insert(b.to_string()) { deps(types, b, out, depth + 1)?; } }
    Ok(())
}

/// encodeType: primary type then its dependencies sorted by name.
pub fn encode_type(types: &Map<String, Value>, primary: &str) -> Result<String, String> {
    let mut d = BTreeSet::new(); deps(types, primary, &mut d, 0)?; d.remove(primary);
    let one = |t: &str| -> Result<String, String> { Ok(format!("{t}({})", fields(types, t)?.iter().map(|(n, ty)| format!("{ty} {n}")).collect::<Vec<_>>().join(","))) };
    let mut s = one(primary)?; for t in d { s += &one(&t)?; } Ok(s)
}

pub fn type_hash(types: &Map<String, Value>, t: &str) -> Result<[u8; 32], String> { Ok(keccak(encode_type(types, t)?.as_bytes())) }

fn enc_value(types: &Map<String, Value>, t: &str, v: &Value, depth: usize) -> Result<[u8; 32], String> {
    if depth > 32 { return Err("types_too_deep".into()); }
    if let Some(inner) = t.strip_suffix(']') {
        let et = &inner[..inner.rfind('[').ok_or("bad_type")?];
        let a = v.as_array().ok_or("expected_json_array")?;
        let mut buf = vec![]; for x in a { buf.extend(enc_value(types, et, x, depth + 1)?); }
        return Ok(keccak(&buf));
    }
    if types.contains_key(t) { return hash_struct_d(types, t, v, depth + 1); }
    match t {
        "string" => Ok(keccak(v.as_str().ok_or("expected_string")?.as_bytes())),
        "bytes" => Ok(keccak(&unhex(v.as_str().ok_or("expected_hex_string")?)?)),
        _ => {
            let ty = Ty::parse(t)?;
            if matches!(ty, Ty::Tuple(_) | Ty::Array(..) | Ty::Bytes | Ty::String) { return Err(format!("unknown_type:{t}")); }
            let e = crate::abi::encode(&[Param::new(ty)], std::slice::from_ref(v))?;
            let mut w = [0u8; 32]; w.copy_from_slice(&e[..32]); Ok(w)
        }
    }
}

fn hash_struct_d(types: &Map<String, Value>, t: &str, v: &Value, depth: usize) -> Result<[u8; 32], String> {
    let o = v.as_object().ok_or("expected_json_object")?;
    let mut buf = type_hash(types, t)?.to_vec();
    for (n, ft) in fields(types, t)? {
        let x = o.get(n).ok_or_else(|| format!("missing_field:{n}"))?;
        buf.extend(enc_value(types, ft, x, depth)?);
    }
    Ok(keccak(&buf))
}

pub fn hash_struct(types: &Map<String, Value>, t: &str, v: &Value) -> Result<[u8; 32], String> { hash_struct_d(types, t, v, 0) }

/// Digest = keccak256(0x19 0x01 || domainSeparator || hashStruct(message)).
pub fn digest(td: &Value) -> Result<([u8; 32], [u8; 32], [u8; 32]), String> {
    let types = types_of(td)?;
    let primary = td.get("primaryType").and_then(Value::as_str).ok_or("missing_primary_type")?;
    if !types.contains_key("EIP712Domain") { return Err("missing_eip712domain_type".into()); }
    let ds = hash_struct(types, "EIP712Domain", td.get("domain").ok_or("missing_domain")?)?;
    let mh = if primary == "EIP712Domain" { None } else { Some(hash_struct(types, primary, td.get("message").ok_or("missing_message")?)?) };
    let mut b = vec![0x19, 0x01]; b.extend(ds); if let Some(m) = mh { b.extend(m); }
    Ok((ds, mh.unwrap_or([0; 32]), keccak(&b)))
}

/// secp256k1 group order / 2 (EIP-2 low-s bound).
const HALF_N: [u8; 32] = [0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x5d,0x57,0x6e,0x73,0x57,0xa4,0x50,0x1d,0xdf,0xe9,0x2f,0x46,0x68,0x1b,0x20,0xa0];

/// Recover the signer of a 32-byte digest from a 65-byte r||s||v (v 27/28 or 0/1) or 64-byte EIP-2098 signature.
pub fn recover(d: &[u8; 32], sig: &[u8]) -> Result<([u8; 20], bool), String> {
    use secp256k1::{ecdsa::{RecoverableSignature, RecoveryId}, Message, Secp256k1};
    let (mut rs, v) = match sig.len() {
        65 => { let v = match sig[64] { 0 | 27 => 0, 1 | 28 => 1, _ => return Err("bad_v".into()) }; (sig[..64].to_vec(), v) }
        64 => { let mut x = sig.to_vec(); let v = (x[32] >> 7) as i32; x[32] &= 0x7f; (x, v) }
        _ => return Err("signature_not_64_or_65_bytes".into()),
    };
    let low_s = rs[32..64] <= HALF_N[..];
    rs.truncate(64);
    let s = RecoverableSignature::from_compact(&rs, RecoveryId::from_i32(v).map_err(|_| "bad_v")?).map_err(|_| "bad_signature")?;
    let pk = Secp256k1::verification_only().recover_ecdsa(&Message::from_digest(*d), &s).map_err(|_| "recover_failed")?;
    let h = keccak(&pk.serialize_uncompressed()[1..]);
    let mut a = [0u8; 20]; a.copy_from_slice(&h[12..]); Ok((a, low_s))
}

/// {typed_data, signature, signer?} -> digests, recovered signer, and verdict when `signer` is given.
pub fn verify(td: &Value, sig_hex: Option<&str>, signer: Option<&str>) -> Result<Value, String> {
    let (ds, mh, d) = digest(td)?;
    let primary = td["primaryType"].as_str().unwrap_or("");
    let mut o = json!({"status": "ok", "primary_type": primary, "encode_type": encode_type(types_of(td)?, primary)?,
        "domain_separator": hex(&ds), "message_hash": hex(&mh), "digest": hex(&d)});
    if primary == "EIP712Domain" { o.as_object_mut().unwrap().remove("message_hash"); }
    if let Some(cid) = td.get("domain").and_then(|x| x.get("chainId")) { o["chain_id"] = cid.clone(); }
    if let Some(vc) = td.get("domain").and_then(|x| x.get("verifyingContract")) { o["verifying_contract"] = vc.clone(); }
    if let Some(s) = sig_hex {
        let (a, low_s) = recover(&d, &unhex(s)?)?;
        o["recovered"] = json!(checksum_address(&a)); o["low_s"] = json!(low_s);
        if let Some(want) = signer {
            let w = crate::parse_address(want)?;
            let ok = w == a;
            o["status"] = json!(if ok { "valid" } else { "signer_mismatch" });
            o["expected"] = json!(checksum_address(&w));
        }
    }
    Ok(o)
}
