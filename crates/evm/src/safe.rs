//! Gnosis Safe (>= 1.3.0) m-of-n `execTransaction`: the EIP-712 Safe transaction hash, owner-signature
//! ordering, the `execTransaction` calldata, and a verifier. NO key handling and NO new crypto here:
//! each owner signs the Safe tx hash in their own wallet (ordinary ECDSA), this orders what they return
//! and recovers owners with the same ecrecover (`eip712::recover`) the rest of the EVM code uses.
//!
//! Safe tx hash = keccak(0x19 0x01 || domainSeparator || safeTxStructHash), with
//!   domainSeparator  = keccak(DOMAIN_TYPEHASH, chainId, verifyingContract)   (Safe >= 1.3.0)
//!   safeTxStructHash = keccak(SAFE_TX_TYPEHASH, to, value, keccak(data), operation,
//!                             safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, nonce)
//! Owner signatures the contract accepts for an EOA owner (v in {27,28}) are ECDSA over that hash, and
//! the `signatures` blob is each owner's 65-byte r||s||v concatenated in ASCENDING owner-address order.
use crate::abi;
use crate::sig::Sig;
use crate::{api, checksum_address, eip712, keccak, parse_address, u256};
use serde_json::{json, Value};

/// The canonical Safe >= 1.3.0 type strings. The hashes are asserted against the on-chain constants in tests.
const DOMAIN_TYPE: &str = "EIP712Domain(uint256 chainId,address verifyingContract)";
const SAFE_TX_TYPE: &str = "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)";
/// `execTransaction(...)` — the solidity signature whose selector + ABI encoding is the calldata.
pub const EXEC_SIG: &str = "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)";

/// A Safe transaction's fields, as the strings a caller supplies (addresses 0x-hex, integers decimal or
/// 0x-hex, `data` 0x-hex). Kept as strings so the same values hash and ABI-encode without a lossy round-trip.
#[derive(Clone, Debug)]
pub struct SafeTx {
    pub to: String,
    pub value: String,
    pub data: String,
    pub operation: String,
    pub safe_tx_gas: String,
    pub base_gas: String,
    pub gas_price: String,
    pub gas_token: String,
    pub refund_receiver: String,
    pub nonce: String,
}

impl SafeTx {
    /// A plain ETH/token call with everything else zeroed (operation CALL, no gas refund).
    pub fn call(to: &str, value: &str, data: &str, nonce: &str) -> SafeTx {
        SafeTx {
            to: to.into(), value: value.into(), data: data.into(), operation: "0".into(),
            safe_tx_gas: "0".into(), base_gas: "0".into(), gas_price: "0".into(),
            gas_token: ZERO_ADDR.into(), refund_receiver: ZERO_ADDR.into(), nonce: nonce.into(),
        }
    }
    fn args(&self, signatures_hex: &str) -> Vec<Value> {
        vec![
            json!(self.to), json!(self.value), json!(fix0x(&self.data)), json!(self.operation),
            json!(self.safe_tx_gas), json!(self.base_gas), json!(self.gas_price),
            json!(self.gas_token), json!(self.refund_receiver), json!(signatures_hex),
        ]
    }
}

pub const ZERO_ADDR: &str = "0x0000000000000000000000000000000000000000";

fn fix0x(s: &str) -> String {
    if s.is_empty() || s == "0x" { "0x".into() } else if s.starts_with("0x") { s.into() } else { format!("0x{s}") }
}
fn addr_word(s: &str) -> Result<[u8; 32], String> {
    let a = parse_address(s)?;
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&a);
    Ok(w)
}
fn uint_word(s: &str) -> Result<[u8; 32], String> {
    u256::parse_uint(s.trim())
}
fn data_bytes(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.is_empty() { return Ok(vec![]); }
    crate::unhex(&format!("0x{s}"))
}

/// The three EIP-712 hashes: (domainSeparator, safeTxStructHash, safeTxHash).
pub fn safe_tx_hashes(chain_id: &str, safe: &str, t: &SafeTx) -> Result<([u8; 32], [u8; 32], [u8; 32]), String> {
    let domain_th = keccak(DOMAIN_TYPE.as_bytes());
    let safe_tx_th = keccak(SAFE_TX_TYPE.as_bytes());

    let mut d = Vec::new();
    d.extend(domain_th);
    d.extend(uint_word(chain_id)?);
    d.extend(addr_word(safe)?);
    let ds = keccak(&d);

    let data_hash = keccak(&data_bytes(&t.data)?);
    let mut s = Vec::new();
    s.extend(safe_tx_th);
    s.extend(addr_word(&t.to)?);
    s.extend(uint_word(&t.value)?);
    s.extend(data_hash);
    s.extend(uint_word(&t.operation)?);
    s.extend(uint_word(&t.safe_tx_gas)?);
    s.extend(uint_word(&t.base_gas)?);
    s.extend(uint_word(&t.gas_price)?);
    s.extend(addr_word(&t.gas_token)?);
    s.extend(addr_word(&t.refund_receiver)?);
    s.extend(uint_word(&t.nonce)?);
    let sh = keccak(&s);

    let mut b = vec![0x19, 0x01];
    b.extend(ds);
    b.extend(sh);
    Ok((ds, sh, keccak(&b)))
}

/// Order the given owner signatures (each 65-byte r||s||v) by ASCENDING recovered owner address and
/// concatenate them into the Safe `signatures` blob. Rejects a signature that does not recover and a
/// duplicate owner (two signatures from the same owner). Returns (packed blob, ordered owner addresses).
pub fn order_signatures(hash: &[u8; 32], sigs: &[Vec<u8>]) -> Result<(Vec<u8>, Vec<[u8; 20]>), String> {
    let mut rec: Vec<([u8; 20], &Vec<u8>)> = Vec::new();
    for s in sigs {
        if s.len() != 65 { return Err("owner signature must be 65 bytes (r||s||v)".into()); }
        let (owner, _low_s) = eip712::recover(hash, s)?;
        rec.push((owner, s));
    }
    rec.sort_by(|a, b| a.0.cmp(&b.0));
    for w in rec.windows(2) {
        if w[0].0 == w[1].0 { return Err("duplicate owner signature".into()); }
    }
    let mut packed = Vec::new();
    for (_, s) in &rec {
        packed.extend_from_slice(s);
    }
    Ok((packed, rec.into_iter().map(|(o, _)| o).collect()))
}

/// Build the `execTransaction` calldata: order the owner signatures and ABI-encode the call. Returns
/// (0x-hex calldata, ordered owner addresses).
pub fn exec_calldata(chain_id: &str, safe: &str, t: &SafeTx, owner_sigs: &[Vec<u8>]) -> Result<(String, Vec<[u8; 20]>), String> {
    let (_, _, hash) = safe_tx_hashes(chain_id, safe, t)?;
    let (packed, owners) = order_signatures(&hash, owner_sigs)?;
    let out = api::encode_call(EXEC_SIG, &t.args(&crate::hex(&packed)))?;
    let data = out.get("data").and_then(Value::as_str).ok_or("encode_failed")?.to_string();
    Ok((data, owners))
}

/// Decode an `execTransaction` calldata back to its `SafeTx` plus the raw `signatures` blob.
pub fn decode_exec(calldata: &str) -> Result<(SafeTx, Vec<u8>), String> {
    let d = crate::unhex(calldata)?;
    let sg = Sig::parse(EXEC_SIG)?;
    if d.len() < 4 || d[..4] != sg.selector() { return Err("not_execTransaction_calldata".into()); }
    let vals = abi::decode(&sg.inputs, &d[4..])?;
    let s = |i: usize| -> Result<String, String> { vals.get(i).and_then(Value::as_str).map(str::to_string).ok_or_else(|| format!("bad_arg_{i}")) };
    let t = SafeTx {
        to: s(0)?, value: s(1)?, data: s(2)?, operation: s(3)?, safe_tx_gas: s(4)?,
        base_gas: s(5)?, gas_price: s(6)?, gas_token: s(7)?, refund_receiver: s(8)?,
        // nonce is NOT in the calldata (the contract holds it); carried separately for verify.
        nonce: "0".into(),
    };
    let sigs = data_bytes(&s(9)?)?;
    Ok((t, sigs))
}

/// Verify an `execTransaction` calldata against the Safe's parameters: recompute the Safe tx hash (the
/// caller supplies the nonce and owner set the contract would use), recover every packed 65-byte
/// signature, and require them STRICTLY ASCENDING by owner, each an allowed owner, and at least
/// `threshold` of them. Returns the ordered recovered owners, or an `Err(reason)` (fail closed).
pub fn verify_exec(
    chain_id: &str,
    safe: &str,
    nonce: &str,
    calldata: &str,
    owner_set: &[[u8; 20]],
    threshold: usize,
) -> Result<Vec<[u8; 20]>, String> {
    let (mut t, sigs) = decode_exec(calldata)?;
    t.nonce = nonce.into();
    let (_, _, hash) = safe_tx_hashes(chain_id, safe, &t)?;
    if sigs.len() % 65 != 0 || sigs.is_empty() { return Err("signatures blob is not a whole number of 65-byte sigs".into()); }
    let mut owners = Vec::new();
    let mut prev: Option<[u8; 20]> = None;
    for chunk in sigs.chunks(65) {
        let (owner, _) = eip712::recover(&hash, chunk)?;
        if let Some(p) = prev {
            if owner <= p { return Err("signatures not strictly ascending by owner (Safe ordering)".into()); }
        }
        if !owner_set.iter().any(|o| *o == owner) {
            return Err(format!("recovered signer {} is not an owner", checksum_address(&owner)));
        }
        prev = Some(owner);
        owners.push(owner);
    }
    if owners.len() < threshold {
        return Err(format!("only {} valid owner signatures, threshold is {}", owners.len(), threshold));
    }
    Ok(owners)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typehashes_match_the_onchain_constants() {
        // Safe >= 1.3.0 published constants.
        assert_eq!(crate::hex(&keccak(DOMAIN_TYPE.as_bytes())),
            "0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218");
        assert_eq!(crate::hex(&keccak(SAFE_TX_TYPE.as_bytes())),
            "0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8");
        assert_eq!(&crate::sig::Sig::parse(EXEC_SIG).unwrap().selector(), &[0x6a, 0x76, 0x12, 0x02]);
    }

    #[test]
    fn hash_is_deterministic_and_data_sensitive() {
        let safe = "0x1111111111111111111111111111111111111111";
        let t = SafeTx::call("0x2222222222222222222222222222222222222222", "1000000000000000000", "0x", "0");
        let (_, _, h1) = safe_tx_hashes("1", safe, &t).unwrap();
        let (_, _, h2) = safe_tx_hashes("1", safe, &t).unwrap();
        assert_eq!(h1, h2);
        // A different recipient changes the hash.
        let t2 = SafeTx::call("0x3333333333333333333333333333333333333333", "1000000000000000000", "0x", "0");
        let (_, _, h3) = safe_tx_hashes("1", safe, &t2).unwrap();
        assert_ne!(h1, h3);
        // A different chain id changes the hash.
        let (_, _, h4) = safe_tx_hashes("137", safe, &t).unwrap();
        assert_ne!(h1, h4);
    }

    fn sign(sk: &secp256k1::SecretKey, hash: &[u8; 32]) -> Vec<u8> {
        use secp256k1::{Message, Secp256k1};
        let (id, rs) = Secp256k1::signing_only()
            .sign_ecdsa_recoverable(&Message::from_digest(*hash), sk)
            .serialize_compact();
        let mut v = rs.to_vec();
        v.push(27 + id.to_i32() as u8); // Safe EOA owner: v in {27,28}
        v
    }
    fn addr_of(sk: &secp256k1::SecretKey) -> [u8; 20] {
        use secp256k1::{PublicKey, Secp256k1};
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), sk);
        let h = keccak(&pk.serialize_uncompressed()[1..]);
        let mut a = [0u8; 20];
        a.copy_from_slice(&h[12..]);
        a
    }
    fn key(b: u8) -> secp256k1::SecretKey {
        let mut k = [0u8; 32];
        k[31] = b;
        secp256k1::SecretKey::from_slice(&k).unwrap()
    }

    #[test]
    fn two_of_three_round_trips_and_verifies() {
        let safe = "0x1111111111111111111111111111111111111111";
        let t = SafeTx::call("0x2222222222222222222222222222222222222222", "1000000000000000000", "0x", "5");
        let (_, _, hash) = safe_tx_hashes("1", safe, &t).unwrap();
        let (k1, k2, k3) = (key(11), key(22), key(33));
        let owner_set = [addr_of(&k1), addr_of(&k2), addr_of(&k3)];
        // Two owners sign; build the calldata.
        let sigs = vec![sign(&k1, &hash), sign(&k3, &hash)];
        let (calldata, owners) = exec_calldata("1", safe, &t, &sigs).unwrap();
        assert_eq!(owners.len(), 2);
        // Signatures come out strictly ascending by owner.
        assert!(owners[0] < owners[1]);
        // verify_exec accepts it at threshold 2.
        let got = verify_exec("1", safe, "5", &calldata, &owner_set, 2).unwrap();
        assert_eq!(got, owners);
    }

    #[test]
    fn wrong_owner_and_short_count_refuse() {
        let safe = "0x1111111111111111111111111111111111111111";
        let t = SafeTx::call("0x2222222222222222222222222222222222222222", "1", "0x", "0");
        let (_, _, hash) = safe_tx_hashes("1", safe, &t).unwrap();
        let (k1, k2, k3, intruder) = (key(11), key(22), key(33), key(99));
        let owner_set = [addr_of(&k1), addr_of(&k2), addr_of(&k3)];
        // A signature from a non-owner is refused.
        let bad = vec![sign(&k1, &hash), sign(&intruder, &hash)];
        let (cd, _) = exec_calldata("1", safe, &t, &bad).unwrap();
        assert!(verify_exec("1", safe, "0", &cd, &owner_set, 2).is_err());
        // One valid owner signature is short of threshold 2.
        let (cd2, _) = exec_calldata("1", safe, &t, &[sign(&k2, &hash)]).unwrap();
        assert!(verify_exec("1", safe, "0", &cd2, &owner_set, 2).is_err());
        // The wrong nonce changes the hash, so recovery lands on non-owners -> refused.
        let (cd3, _) = exec_calldata("1", safe, &t, &[sign(&k1, &hash), sign(&k2, &hash)]).unwrap();
        assert!(verify_exec("1", safe, "999", &cd3, &owner_set, 2).is_err());
    }
}
