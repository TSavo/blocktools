//! Destination-address validators (checksums always enforced). Used by tx-build /
//! tx-verify / tx-sign before any destination is accepted, and by the KAT tests.
use crate::chains::{self, Enc, BTC_ALPHA, XRP_ALPHA};
use bitcoin::base58;
use bitcoin::bech32::segwit;

/// Ripple-alphabet base58check decode (addresses, X-addresses, family seeds).
pub fn xrp_decode_check(s: &str) -> Result<Vec<u8>, &'static str> {
    let t: String = s.bytes().map(|ch| XRP_ALPHA.iter().position(|x| *x == ch).map(|i| BTC_ALPHA[i] as char)).collect::<Option<_>>().ok_or("bad alphabet")?;
    base58::decode_check(&t).map_err(|_| "bad base58check")
}
/// XRP family seed: "s..." secp256k1 (21 || 16 bytes) or "sEd..." ed25519 (01 E1 4B || 16 bytes).
pub fn is_xrp_seed(s: &str) -> bool {
    s.starts_with('s') && xrp_decode_check(s).map_or(false, |b| (b.len() == 17 && b[0] == 0x21) || (b.len() == 19 && b[..3] == [0x01, 0xe1, 0x4b]))
}
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AddrKind { P2pkh, P2sh, SegwitV0, Taproot, SegwitOther, Eth, Tron, Xrp, Sol, Xlm, Cosmos, Algo, Xmr }

/// Validate `addr` for `chain`. Errors are short static strings.
pub fn validate(chain: &str, addr: &str) -> Result<AddrKind, &'static str> {
    let c = chains::chain(chain).ok_or("unknown chain")?;
    if addr.is_empty() || addr.len() > 100 || !addr.is_ascii() { return Err("bad length") }
    match c.enc {
        Enc::Utxo { p2pkh, p2sh, hrp, .. } => {
            if let Some(h) = hrp {
                let lower = addr.to_ascii_lowercase();
                if lower.starts_with(&format!("{h}1")) {
                    if addr != lower && addr != addr.to_ascii_uppercase() { return Err("mixed case") }
                    let (hrp_got, ver, prog) = segwit::decode(&lower).map_err(|_| "bad bech32 checksum or program")?;
                    if hrp_got.as_str() != h { return Err("wrong network") }
                    return Ok(match (ver.to_u8(), prog.len()) { (0, 20 | 32) => AddrKind::SegwitV0, (1, 32) => AddrKind::Taproot, (0, _) => return Err("bad program"), _ => AddrKind::SegwitOther });
                }
            }
            let b = chains::decode_check_ck(c.ck(), addr)?;
            match (b.len(), b[0]) { (21, v) if v == p2pkh => Ok(AddrKind::P2pkh), (21, v) if v == p2sh => Ok(AddrKind::P2sh), (21, _) => Err("wrong network"), _ => Err("bad length") }
        }
        Enc::Eth => eth(addr).map(|_| AddrKind::Eth),
        Enc::Tron => tron_to_hex(addr).map(|_| AddrKind::Tron),
        Enc::Xmr => blocktools_monero::validate(addr).map(|_| AddrKind::Xmr),
        Enc::Xrp => {
            let b = xrp_decode_check(addr)?;
            if b.len() == 21 && b[0] == 0 && addr.starts_with('r') { return Ok(AddrKind::Xrp) }
            // X-address (XLS-5d, mainnet 0544 only): id, tag flag 0/1, u32 LE tag, 4 zero bytes
            if b.len() == 31 && b[..2] == [0x05, 0x44] && b[22] <= 1 && b[27..] == [0; 4] && (b[22] == 1 || b[23..27] == [0; 4]) { return Ok(AddrKind::Xrp) }
            Err("bad length")
        }
        Enc::Cosmos { hrp } => chains::cosmos_decode(hrp, addr).map(|_| AddrKind::Cosmos),
        Enc::Algo => chains::algo_decode(addr).map(|_| AddrKind::Algo),
        Enc::Xlm => match chains::strkey_decode(addr)? { (48, p) if p.len() == 32 => Ok(AddrKind::Xlm), (48, _) => Err("bad length"), _ => Err("wrong network") },
        Enc::Sol => { let b = base58::decode(addr).map_err(|_| "bad base58")?; if b.len() == 32 { Ok(AddrKind::Sol) } else { Err("32-byte") } }
    }
}

/// EIP-55: all-lower / all-upper accepted (no checksum), mixed case must match.
pub fn eth(addr: &str) -> Result<[u8; 20], &'static str> {
    let h = addr.strip_prefix("0x").ok_or("missing 0x")?;
    if h.len() != 40 { return Err("bad length") }
    let b = crate::hex_dec(h).ok_or("bad hex")?;
    let mixed = h.bytes().any(|c| c.is_ascii_lowercase()) && h.bytes().any(|c| c.is_ascii_uppercase());
    if mixed && checksum_eth(&b) != addr { return Err("bad EIP-55 checksum") }
    Ok(b.try_into().unwrap())
}
pub fn checksum_eth(a20: &[u8]) -> String {
    use sha3::{Digest, Keccak256};
    let a = crate::hex_enc(a20);
    let ch = crate::hex_enc(Keccak256::digest(a.as_bytes()));
    format!("0x{}", a.chars().zip(ch.chars()).map(|(c, k)| if k.to_digit(16).unwrap() >= 8 { c.to_ascii_uppercase() } else { c }).collect::<String>())
}
/// Tron base58check (0x41 + 20 bytes, checksum enforced) -> 21-byte hex "41..." without 0x.
pub fn tron_to_hex(addr: &str) -> Result<String, &'static str> {
    if !addr.starts_with('T') || addr.len() != 34 { return Err("Not a Tron address") }
    let b = base58::decode_check(addr).map_err(|_| "bad base58check")?;
    if b.len() != 21 || b[0] != 0x41 { return Err("Not a Tron address") }
    Ok(crate::hex_enc(&b))
}
/// Hex (with/without 0x; 20 bytes or 21 bytes starting 41) -> Tron address.
pub fn hex_to_tron(h: &str) -> Result<String, &'static str> {
    let h = h.strip_prefix("0x").unwrap_or(h);
    let b = crate::hex_dec(h).ok_or("Invalid hex address length")?;
    let p = match b.len() { 20 => { let mut v = vec![0x41]; v.extend(b); v } 21 if b[0] == 0x41 => b, _ => return Err("Invalid hex address length") };
    Ok(base58::encode_check(&p))
}

#[cfg(test)]
mod tests {
    #[test] fn xmr_row_validates_monero_addresses() {
        let a = "44cWztNFdAqNnycvZbUoj44vsbAEmKnx9aNgkjHdjtMsBrSeKiY8J4s2raH7EMawA2Fwo9utaRTV7Aw8EcTMNMxhH4YtKdH";
        assert_eq!(validate("xmr", a), Ok(AddrKind::Xmr));
        let mut bad = a.to_string(); bad.replace_range(10..11, "Z"); assert!(validate("xmr", &bad).is_err());
        assert!(validate("xmr", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH").is_err());
    }
    use super::*;
    use bitcoin::bip32::{ChildNumber, Xpub};
    use bitcoin::secp256k1::Secp256k1;
    use std::str::FromStr;
    const ROOT: &str = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu";

    // Prior-art KATs: docs/prior-art-crypto-plugins.md §5.
    #[test] fn tron_kats() {
        let s = Secp256k1::new();
        #[cfg(feature = "secrets")] {
            let rows = chains::derive_chain(&bitcoin::bip32::Xpriv::from_str(ROOT).unwrap(), chains::chain("tron").unwrap(), 2, &s);
            assert_eq!(rows[0].address, "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH");
            assert_eq!(rows[1].address, "TSeJkUh4Qv67VNFwY8LaAxERygNdy6NQZK");
        }
        let _ = ROOT;
        let x = Xpub::from_str("xpub6BnqJwdqnXEZdkynN5CsrYZr3MULY933SdLrswFfKPDFandTXPQDWY225FveTPUJXS8D91Ddp7FEfaGrvVxuMBGQsyoBYRLu6VMB3Ni2H2Z").unwrap();
        let pk = x.derive_pub(&s, &[ChildNumber::from(0), ChildNumber::from(0)]).unwrap().public_key;
        let mut p = vec![0x41]; p.extend(chains::keccak_addr20(&pk));
        assert_eq!(base58::encode_check(&p), "TDTkBJWfXqfCPhNAgHxmgPNHigJEg4ghww");
        // same xpub drives LTC / DOGE encoders: shape checks as in the prior art
        let h = bitcoin::hashes::hash160::Hash::hash(&pk.serialize());
        use bitcoin::hashes::Hash;
        let ltc = segwit::encode_v0(bitcoin::bech32::Hrp::parse("ltc").unwrap(), h.as_byte_array()).unwrap();
        assert_eq!(ltc.len(), 43); assert_eq!(validate("ltc", &ltc), Ok(AddrKind::SegwitV0));
        let mut d = vec![0x1e]; d.extend(h.as_byte_array());
        let doge = base58::encode_check(&d);
        assert!(doge.starts_with('D') && (33..=34).contains(&doge.len())); assert_eq!(validate("doge", &doge), Ok(AddrKind::P2pkh));
    }
    #[test] fn tron_hex_and_rejects() {
        let t = "TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW";
        assert_eq!(tron_to_hex(t).unwrap(), "415a523b449890854c8fc460ab602df9f31fe4293f");
        assert_eq!(hex_to_tron("0x5a523b449890854c8fc460ab602df9f31fe4293f").unwrap(), t);
        assert_eq!(hex_to_tron("5a523b449890854c8fc460ab602df9f31fe4293f").unwrap(), t);
        assert_eq!(hex_to_tron("415a523b449890854c8fc460ab602df9f31fe4293f").unwrap(), t);
        assert_eq!(tron_to_hex("TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMX"), Err("bad base58check"));
        for bad in ["0x1234", "D7abc123", "D7abcdef", "bc1qtest", "0x1234567890abcdef1234567890abcdef12345678"] { assert!(validate("tron", bad).is_err(), "{bad}") }
        assert_eq!(hex_to_tron("0x1234"), Err("Invalid hex address length"));
    }
    #[test] fn eip55_tokens() {
        for a in ["0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2", "0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb",
                  "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "0xdAC17F958D2ee523a2206206994597C13D831ec7"] {
            let b = eth(a).unwrap(); assert_eq!(checksum_eth(&b), a);
            let mut v = a.as_bytes().to_vec(); let i = (2..v.len()).find(|&i| v[i].is_ascii_alphabetic()).unwrap();
            v[i] ^= 0x20; let bad = String::from_utf8(v).unwrap();
            assert_eq!(eth(&bad), Err("bad EIP-55 checksum"));
            assert!(eth(&a.to_ascii_lowercase()).is_ok());
        }
    }
    #[test] fn base58_edges() {
        assert_eq!(base58::encode(&[0xff]), "5Q");
        assert_eq!(base58::encode(&[0, 0, 0]), "111");
        assert_eq!(base58::encode(&[1]), "2");
        assert_eq!(base58::decode("111").unwrap(), vec![0, 0, 0]);
    }
    #[test] fn utxo_and_others() {
        assert_eq!(validate("btc", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"), Ok(AddrKind::SegwitV0));
        assert_eq!(validate("btc", "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"), Ok(AddrKind::Taproot));
        assert!(validate("btc", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyv").is_err());
        assert!(validate("btc", "BC1QCR8TE4KR609GCAWUTMRZA0J4XV80JY8Z306FYU").is_ok());
        assert!(validate("btc", "bc1Qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu").is_err());
        assert_eq!(validate("btc", "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"), Ok(AddrKind::P2pkh));
        assert_eq!(validate("btc", "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"), Ok(AddrKind::P2sh));
        assert_eq!(validate("btc", "LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez"), Err("wrong network"));
        assert_eq!(validate("ltc", "ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wh"), Ok(AddrKind::SegwitV0));
        assert_eq!(validate("btc", "ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wh").is_err(), true);
        assert_eq!(validate("xrp", "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3"), Ok(AddrKind::Xrp));
        assert_eq!(validate("xrp", "rrrrrrrrrrrrrrrrrrrrrhoLvTp"), Ok(AddrKind::Xrp));
        assert!(validate("xrp", "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v4").is_err());
        // ripple-address-codec vectors: X-address with and without tag; testnet T-address is not mainnet
        assert_eq!(validate("xrp", "X7AcgcsBL6XDcUb289X4mJ8djcdyKaLFuhLRuNXPrDeJd9A"), Ok(AddrKind::Xrp));
        assert_eq!(validate("xrp", "XVZVpQj8YSVpNyiwXYSqvQoQqgBttTxAZwMcuJd4xteQHyt"), Ok(AddrKind::Xrp));
        assert!(validate("xrp", "T719a5UwUCnEs54UsxG9CJYYDhwmFCqkr7wxCcNcfZ6p5GZ").is_err());
        assert!(is_xrp_seed("sp5fghtJtpUorTwvof1NpDXAzNwf5") && is_xrp_seed("sEdSKaCy2JT7JaM7v95H9SxkhP9wS2r"));
        assert!(!is_xrp_seed("rU6K7V3Po4snVhBBaU29sesqs2qTQJWDw1"));
        assert_eq!(validate("sol", "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"), Ok(AddrKind::Sol));
        for n in [0usize, 20, 33] { assert_eq!(validate("sol", &base58::encode(&vec![7u8; n])).err(), Some(if n == 0 { "bad length" } else { "32-byte" })) }
    }
    #[cfg(all(feature = "ed25519", feature = "secrets"))]
    #[test] fn solana_key1() {
        let mut sk = [0u8; 32]; sk[31] = 1;
        let r = chains::sol_row("", &sk);
        let pk = base58::decode(&r.address).unwrap();
        assert_eq!(crate::hex_enc(&pk), "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29");
    }
}
