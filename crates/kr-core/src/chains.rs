//! Data-driven chain table: how a secp256k1 / ed25519 key becomes an address
//! on each chain. Adding a chain = adding a row (plus an encoder if it is new).
//! Encodings only; all primitives come from rust-bitcoin / secp256k1 / sha3 / ed25519-dalek.
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::hashes::{hash160, sha512, Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1::{All, PublicKey, Secp256k1, SecretKey};
use bitcoin::bech32::{self, Hrp};
use sha3::{Digest, Keccak256};
use std::str::FromStr;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Enc {
    /// Bitcoin-family UTXO chain: base58 versions, optional segwit hrp, WIF version.
    Utxo { p2pkh: u8, p2sh: u8, hrp: Option<&'static str>, wif: u8, taproot: bool },
    Eth,
    Tron,
    Xrp,
    /// ed25519, SLIP-0010, path m/44'/501'/i'/0' (Phantom/Solflare/solana-keygen style).
    Sol,
}
#[derive(Clone, Copy, Debug)]
pub struct Chain { pub name: &'static str, pub coin: u32, pub enc: Enc, pub default_count: u32 }

pub const CHAINS: &[Chain] = &[
    Chain { name: "btc", coin: 0, enc: Enc::Utxo { p2pkh: 0x00, p2sh: 0x05, hrp: Some("bc"), wif: 0x80, taproot: true }, default_count: 10 },
    Chain { name: "ltc", coin: 2, enc: Enc::Utxo { p2pkh: 0x30, p2sh: 0x32, hrp: Some("ltc"), wif: 0xb0, taproot: false }, default_count: 10 },
    Chain { name: "doge", coin: 3, enc: Enc::Utxo { p2pkh: 0x1e, p2sh: 0x16, hrp: None, wif: 0x9e, taproot: false }, default_count: 10 },
    Chain { name: "eth", coin: 60, enc: Enc::Eth, default_count: 5 },
    Chain { name: "tron", coin: 195, enc: Enc::Tron, default_count: 10 },
    Chain { name: "xrp", coin: 144, enc: Enc::Xrp, default_count: 10 },
    Chain { name: "sol", coin: 501, enc: Enc::Sol, default_count: 10 },
];
pub fn chain(name: &str) -> Option<&'static Chain> { CHAINS.iter().find(|c| c.name == name) }

pub struct Row { pub chain: &'static str, pub kind: &'static str, pub path: String, pub address: String, pub secret_field: &'static str, pub secret: String }

fn b58check(payload: &[u8]) -> String { bitcoin::base58::encode_check(payload) }
const XRP_ALPHA: &[u8; 58] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
const BTC_ALPHA: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/// Ripple base58check: same digits as Bitcoin's base58check, different alphabet.
pub fn xrp_b58check(payload: &[u8]) -> String {
    b58check(payload).bytes().map(|c| XRP_ALPHA[BTC_ALPHA.iter().position(|x| *x == c).unwrap()] as char).collect()
}
fn h160(b: &[u8]) -> [u8; 20] { hash160::Hash::hash(b).to_byte_array() }
fn ver(v: u8, b: &[u8]) -> Vec<u8> { let mut x = vec![v]; x.extend_from_slice(b); x }

pub fn wif(version: u8, sk: &SecretKey, compressed: bool) -> String {
    let mut p = ver(version, &sk.secret_bytes());
    if compressed { p.push(1) }
    b58check(&p)
}
fn segwit_v0(hrp: &str, prog: &[u8]) -> String {
    bech32::segwit::encode_v0(Hrp::parse(hrp).expect("static hrp"), prog).expect("20-byte program")
}
fn keccak_addr20(pk: &PublicKey) -> [u8; 20] {
    let h = Keccak256::digest(&pk.serialize_uncompressed()[1..]);
    h[12..].try_into().unwrap()
}

/// Address rows for one secp256k1 key on one chain. `kinds` = which script types
/// (None = all the chain supports). `uncompressed` adds legacy uncompressed p2pkh.
pub fn secp_rows(c: &Chain, path: &str, sk: &SecretKey, uncompressed: bool, secp: &Secp256k1<All>) -> Vec<Row> {
    let pk = PublicKey::from_secret_key(secp, sk);
    let hex = crate::hex_enc(sk.secret_bytes());
    let row = |kind, address: String, secret_field, secret: String| Row { chain: c.name, kind, path: path.to_string(), address, secret_field, secret };
    match c.enc {
        Enc::Utxo { p2pkh, p2sh, hrp, wif: wv, taproot } => {
            let cpk = pk.serialize();
            let mut v = vec![row("p2pkh", b58check(&ver(p2pkh, &h160(&cpk))), "wif", wif(wv, sk, true))];
            if uncompressed {
                v.push(row("p2pkh-uncompressed", b58check(&ver(p2pkh, &h160(&pk.serialize_uncompressed()))), "wif", wif(wv, sk, false)));
            }
            if let Some(h) = hrp {
                let mut redeem = vec![0u8, 20]; redeem.extend_from_slice(&h160(&cpk));
                v.push(row("p2sh-p2wpkh", b58check(&ver(p2sh, &h160(&redeem))), "wif", wif(wv, sk, true)));
                v.push(row("p2wpkh", segwit_v0(h, &h160(&cpk)), "wif", wif(wv, sk, true)));
            }
            if taproot {
                let a = bitcoin::Address::p2tr(secp, pk.x_only_public_key().0, None, bitcoin::Network::Bitcoin);
                v.push(row("p2tr", a.to_string(), "wif", wif(wv, sk, true)));
            }
            v
        }
        Enc::Eth => vec![row("eth", crate::eth_address(sk, secp), "private_key", hex)],
        Enc::Tron => vec![row("tron", b58check(&ver(0x41, &keccak_addr20(&pk))), "private_key", hex)],
        Enc::Xrp => vec![row("xrp", xrp_b58check(&ver(0x00, &h160(&pk.serialize()))), "private_key", hex)],
        Enc::Sol => vec![],
    }
}
/// Script-type -> BIP purpose for UTXO chains.
fn purpose(kind: &str) -> u32 { match kind { "p2sh-p2wpkh" => 49, "p2wpkh" => 84, "p2tr" => 86, _ => 44 } }

/// ed25519 key from a 32-byte seed: (address = base58 pubkey, secret = base58(seed||pub), the
/// 64-byte keypair format Solana wallets import).
pub fn sol_row(path: &str, seed: &[u8; 32]) -> Row {
    let sk = ed25519_dalek::SigningKey::from_bytes(seed);
    let pubk = sk.verifying_key().to_bytes();
    let mut kp = seed.to_vec(); kp.extend_from_slice(&pubk);
    let secret = bitcoin::base58::encode(&kp);
    kp.iter_mut().for_each(|b| *b = 0);
    Row { chain: "sol", kind: "sol", path: path.into(), address: bitcoin::base58::encode(&pubk), secret_field: "private_key", secret }
}
/// SLIP-0010 ed25519 derivation (hardened only) from a BIP39 seed.
pub fn slip10_ed25519(seed: &[u8], path: &[u32]) -> [u8; 32] {
    let mut e = HmacEngine::<sha512::Hash>::new(b"ed25519 seed");
    e.input(seed);
    let mut i = Hmac::<sha512::Hash>::from_engine(e).to_byte_array();
    for idx in path {
        let mut e = HmacEngine::<sha512::Hash>::new(&i[32..]);
        e.input(&[0]); e.input(&i[..32]); e.input(&(idx | 1 << 31).to_be_bytes());
        i = Hmac::<sha512::Hash>::from_engine(e).to_byte_array();
    }
    i[..32].try_into().unwrap()
}

/// Standard per-chain rows from a BIP32 master key (secp256k1 chains) for i < count.
pub fn derive_chain(master: &Xpriv, c: &Chain, count: u32, secp: &Secp256k1<All>) -> Vec<Row> {
    let kinds: &[&str] = match c.enc {
        Enc::Utxo { hrp: Some(_), taproot: true, .. } => &["p2pkh", "p2sh-p2wpkh", "p2wpkh", "p2tr"],
        Enc::Utxo { hrp: Some(_), .. } => &["p2pkh", "p2sh-p2wpkh", "p2wpkh"],
        Enc::Utxo { .. } => &["p2pkh"],
        Enc::Sol => return vec![],
        _ => &[""],
    };
    let mut out = Vec::new();
    for kind in kinds {
        let acct_s = format!("m/{}'/{}'/0'", if kind.is_empty() { 44 } else { purpose(kind) }, c.coin);
        let acct = DerivationPath::from_str(&acct_s).unwrap();
        let ak = master.derive_priv(secp, &acct).unwrap();
        for i in 0..count {
            let leaf = ak.derive_priv(secp, &[ChildNumber::Normal { index: 0 }, ChildNumber::Normal { index: i }]).unwrap();
            let path = format!("{acct_s}/0/{i}");
            out.extend(secp_rows(c, &path, &leaf.private_key, false, secp).into_iter().filter(|r| kind.is_empty() || r.kind == *kind));
        }
    }
    out
}
/// Solana rows from a BIP39 seed (64 bytes): m/44'/501'/i'/0'.
pub fn derive_sol(seed: &[u8], count: u32) -> Vec<Row> {
    (0..count).map(|i| sol_row(&format!("m/44'/501'/{i}'/0'"), &slip10_ed25519(seed, &[44, 501, i, 0]))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    // Known-answer tests. All keys are public textbook values (private key 1) or the public
    // BIP39 phrase "abandon x11 about"; cross-checked independently by scripts/kat.py.
    fn one() -> SecretKey { let mut b = [0u8; 32]; b[31] = 1; SecretKey::from_slice(&b).unwrap() }
    #[test] fn privkey_one() {
        let s = Secp256k1::new();
        let r = secp_rows(chain("btc").unwrap(), "", &one(), true, &s);
        let a: Vec<&str> = r.iter().map(|r| r.address.as_str()).collect();
        assert_eq!(a[0], "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
        assert_eq!(a[1], "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm");
        assert_eq!(r[1].secret, "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf");
        assert_eq!(r[0].secret, "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn");
        assert_eq!(secp_rows(chain("eth").unwrap(), "", &one(), false, &s)[0].address, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
    }
    #[test] fn xrp_account_zero() {
        assert_eq!(xrp_b58check(&[0u8; 21]), "rrrrrrrrrrrrrrrrrrrrrhoLvTp");
        let mut one = [0u8; 21]; one[20] = 1;
        assert_eq!(xrp_b58check(&one), "rrrrrrrrrrrrrrrrrrrrBZbvji");
    }
}
#[cfg(test)]
mod kat_key_one {
    use super::*;
    // Private key 1 (textbook value): BIP173 p2wpkh vector and Tron/XRP/LTC/DOGE encodings.
    #[test] fn other_chains() {
        let s = Secp256k1::new(); let mut b = [0u8; 32]; b[31] = 1; let k = SecretKey::from_slice(&b).unwrap();
        let a = |c: &str, kind: &str| secp_rows(chain(c).unwrap(), "", &k, true, &s).into_iter().find(|r| r.kind == kind).unwrap().address;
        assert_eq!(a("btc", "p2wpkh"), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert_eq!(a("tron", "tron"), "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC");
        assert_eq!(a("ltc", "p2wpkh"), "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9");
    }
}
