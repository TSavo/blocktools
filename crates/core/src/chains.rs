//! Data-driven chain table: how a secp256k1 / ed25519 key becomes an address
//! on each chain. Adding a chain = adding a row (plus an encoder if it is new).
//! Encodings only; all primitives come from rust-bitcoin / secp256k1 / sha3 / ed25519-dalek.
#[cfg(feature = "secrets")]
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::hashes::{hash160, Hash};
#[cfg(feature = "secrets")]
use bitcoin::hashes::{sha512, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1::{PublicKey, Secp256k1};
#[cfg(feature = "secrets")]
use bitcoin::secp256k1::{All, SecretKey};
use bitcoin::bech32::{self, Hrp};
use sha3::{Digest, Keccak256};
#[cfg(feature = "secrets")]
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
/// How transactions are signed on a UTXO chain. Only `Standard` (Bitcoin legacy/BIP143
/// sighash, Bitcoin tx serialisation) is built and signed by tx-build/tx-sign; the others are
/// derive / validate / decode-address only until implemented and tested.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Sign { Standard, ForkId(u8), PosTime, Unknown }
/// A public block explorer / API. Only listed when it answered from this project's CI box.
#[derive(Clone, Copy, Debug)]
pub struct Source { pub name: &'static str, pub url: &'static str, pub api: &'static str, pub checked: &'static str }
#[derive(Clone, Copy, Debug)]
pub struct Chain {
    pub name: &'static str, pub ticker: &'static str, pub title: &'static str,
    /// SLIP-44 coin type (BIP44 path). Rows with no SLIP-44 entry are `verified: false`.
    pub coin: u32, pub enc: Enc, pub default_count: u32, pub sign: Sign,
    /// true = every parameter checked against the coin's own source (chainparams/base58.h) and
    /// SLIP-44, and an independent known-answer test passes. false rows are never "supported".
    pub verified: bool,
    /// Where the parameters came from (repo/path), for review.
    pub source: &'static str,
    pub sources: &'static [Source],
}
const fn u(name: &'static str, ticker: &'static str, title: &'static str, coin: u32, p2pkh: u8, p2sh: u8, wif: u8, hrp: Option<&'static str>,
           sign: Sign, verified: bool, source: &'static str, sources: &'static [Source]) -> Chain {
    Chain { name, ticker, title, coin, enc: Enc::Utxo { p2pkh, p2sh, hrp, wif, taproot: false }, default_count: 10, sign, verified, source, sources }
}
const D: &str = "2026-10-24";
const fn cz(t: &'static str, api: &'static str) -> Source { Source { name: "chainz.cryptoid.info", url: t, api, checked: D } }
use Sign::*;
pub const CHAINS: &[Chain] = &[
    Chain { name: "btc", ticker: "BTC", title: "Bitcoin", coin: 0, enc: Enc::Utxo { p2pkh: 0x00, p2sh: 0x05, hrp: Some("bc"), wif: 0x80, taproot: true }, default_count: 10, sign: Standard, verified: true,
            source: "bitcoin/bitcoin src/kernel/chainparams.cpp", sources: &[Source { name: "blockstream.info", url: "https://blockstream.info/address/{addr}", api: "esplora:https://blockstream.info/api", checked: D }] },
    u("ltc", "LTC", "Litecoin", 2, 48, 50, 176, Some("ltc"), Standard, true, "litecoin-project/litecoin src/chainparams.cpp", &[Source { name: "litecoinspace.org", url: "https://litecoinspace.org/address/{addr}", api: "esplora:https://litecoinspace.org/api", checked: D }]),
    u("doge", "DOGE", "Dogecoin", 3, 30, 22, 158, None, Standard, true, "dogecoin/dogecoin src/chainparams.cpp", &[]),
    Chain { name: "eth", ticker: "ETH", title: "Ethereum / EVM", coin: 60, enc: Enc::Eth, default_count: 5, sign: Standard, verified: true, source: "EIP-55, EIP-155, EIP-1559", sources: &[] },
    Chain { name: "tron", ticker: "TRX", title: "Tron", coin: 195, enc: Enc::Tron, default_count: 10, sign: Unknown, verified: true, source: "tronprotocol docs: 0x41 || keccak20, base58check", sources: &[] },
    Chain { name: "xrp", ticker: "XRP", title: "XRP Ledger", coin: 144, enc: Enc::Xrp, default_count: 10, sign: Unknown, verified: true, source: "xrpl.org: account ID, ripple base58 alphabet", sources: &[] },
    Chain { name: "sol", ticker: "SOL", title: "Solana", coin: 501, enc: Enc::Sol, default_count: 10, sign: Unknown, verified: true, source: "SLIP-0010 ed25519, m/44'/501'/i'/0'", sources: &[] },
    // ---- Bitcoin-family long tail. Bytes are decimal as written in each coin's source. ----
    u("qtum", "QTUM", "Qtum", 2301, 58, 50, 128, Some("qc"), Standard, true, "qtumproject/qtum src/kernel/chainparams.cpp", &[]),
    u("ftc", "FTC", "Feathercoin", 8, 14, 5, 142, Some("fc"), Standard, true, "FeatherCoin/Feathercoin src/chainparams.cpp", &[]),
    u("nmc", "NMC", "Namecoin", 7, 52, 13, 180, Some("nc"), Standard, true, "namecoin/namecoin-core src/kernel/chainparams.cpp", &[]),
    u("dash", "DASH", "Dash", 5, 76, 16, 204, None, Standard, true, "dashpay/dash src/chainparams.cpp", &[cz("https://chainz.cryptoid.info/dash/address.dws?{addr}", "cryptoid:https://chainz.cryptoid.info/dash/api.dws")]),
    u("vtc", "VTC", "Vertcoin", 28, 71, 5, 128, Some("vtc"), Standard, true, "vertcoin-project/vertcoin-core src/chainparams.cpp", &[cz("https://chainz.cryptoid.info/vtc/address.dws?{addr}", "cryptoid:https://chainz.cryptoid.info/vtc/api.dws")]),
    u("dgb", "DGB", "DigiByte", 20, 30, 63, 128, Some("dgb"), Standard, true, "DigiByte-Core/digibyte src/chainparams.cpp", &[cz("https://chainz.cryptoid.info/dgb/address.dws?{addr}", "cryptoid:https://chainz.cryptoid.info/dgb/api.dws")]),
    u("via", "VIA", "Viacoin", 14, 71, 33, 199, Some("via"), Standard, true, "viacoin/viacoin src/chainparams.cpp", &[]),
    u("mona", "MONA", "Monacoin", 22, 50, 55, 176, Some("mona"), Standard, true, "monacoinproject/monacoin src/chainparams.cpp", &[]),
    u("rvn", "RVN", "Ravencoin", 175, 60, 122, 128, None, Standard, true, "RavenProject/Ravencoin src/chainparams.cpp", &[Source { name: "blockbook.ravencoin.org", url: "https://blockbook.ravencoin.org/address/{addr}", api: "blockbook:https://blockbook.ravencoin.org/api", checked: D }]),
    u("xpm", "XPM", "Primecoin", 24, 23, 83, 151, None, Standard, true, "primecoin/primecoin src/base58.h (WIF = 128 + PUBKEY_ADDRESS)", &[cz("https://chainz.cryptoid.info/xpm/address.dws?{addr}", "cryptoid:https://chainz.cryptoid.info/xpm/api.dws")]),
    u("trc", "TRC", "Terracoin", 83, 0, 5, 128, None, Standard, true, "terracoin/terracoin src/chainparams.cpp", &[]),
    u("mec", "MEC", "Megacoin", 217, 50, 5, 178, Some("mec"), Standard, true, "LIMXTEC/Megacoin src/chainparams.cpp", &[]),
    u("aur", "AUR", "Auroracoin", 85, 23, 5, 176, None, Standard, true, "aurarad/auroracoin src/chainparams.cpp", &[cz("https://chainz.cryptoid.info/aur/address.dws?{addr}", "cryptoid:https://chainz.cryptoid.info/aur/api.dws")]),
    u("bch", "BCH", "Bitcoin Cash (legacy addresses)", 145, 0, 5, 128, None, ForkId(0), true, "same legacy bytes as Bitcoin; SIGHASH_FORKID", &[]),
    u("bsv", "BSV", "Bitcoin SV (legacy addresses)", 236, 0, 5, 128, None, ForkId(0), true, "same legacy bytes as Bitcoin; SIGHASH_FORKID", &[]),
    u("btg", "BTG", "Bitcoin Gold", 156, 38, 23, 128, Some("btg"), ForkId(79), true, "BTCGPU/BTCGPU src/chainparams.cpp", &[]),
    u("ppc", "PPC", "Peercoin", 6, 55, 117, 183, Some("pc"), PosTime, true, "peercoin/peercoin src/kernel/chainparams.cpp", &[cz("https://chainz.cryptoid.info/ppc/address.dws?{addr}", "cryptoid:https://chainz.cryptoid.info/ppc/api.dws")]),
    u("nvc", "NVC", "Novacoin", 50, 8, 20, 136, None, PosTime, true, "novacoin-project/novacoin src/base58.h (WIF = 128 + PUBKEY_ADDRESS)", &[cz("https://chainz.cryptoid.info/nvc/address.dws?{addr}", "cryptoid:https://chainz.cryptoid.info/nvc/api.dws")]),
    u("clam", "CLAM", "Clams", 23, 137, 13, 133, None, PosTime, true, "nochowderforyou/clams src/chainparams.cpp", &[cz("https://chainz.cryptoid.info/clam/address.dws?{addr}", "cryptoid:https://chainz.cryptoid.info/clam/api.dws")]),
    u("blk", "BLK", "Blackcoin", 10, 25, 85, 153, None, PosTime, true, "CoinBlack/blackcoin src/chainparams.cpp", &[cz("https://chainz.cryptoid.info/blk/address.dws?{addr}", "cryptoid:https://chainz.cryptoid.info/blk/api.dws")]),
    u("rdd", "RDD", "Reddcoin", 4, 61, 5, 189, Some("rdd"), PosTime, true, "reddcoin-project/reddcoin src/chainparams.cpp", &[]),
    u("pot", "POT", "Potcoin", 81, 55, 110, 183, None, PosTime, true, "potcoin/Potcoin src/base58.h (WIF = 128 + PUBKEY_ADDRESS)", &[cz("https://chainz.cryptoid.info/pot/address.dws?{addr}", "cryptoid:https://chainz.cryptoid.info/pot/api.dws")]),
    u("qrk", "QRK", "Quark", 82, 58, 9, 186, None, Unknown, true, "quark-project/quark src/chainparams.cpp", &[cz("https://chainz.cryptoid.info/qrk/address.dws?{addr}", "cryptoid:https://chainz.cryptoid.info/qrk/api.dws")]),
    // No SLIP-44 coin type registered: address encoding is from source, derivation path is not.
    u("wdc", "WDC", "Worldcoin", 0, 73, 5, 201, None, Standard, false, "worldcoinproject/worldcoin-v0.8 src/base58.h; no SLIP-44 entry", &[cz("https://chainz.cryptoid.info/wdc/address.dws?{addr}", "cryptoid:https://chainz.cryptoid.info/wdc/api.dws")]),
    u("anc", "ANC", "Anoncoin", 0, 23, 15, 151, None, Standard, false, "Anoncoin/anoncoin src/chainparams.cpp; no SLIP-44 entry", &[]),
];
/// Not in the table, on purpose: Zcash (2-byte versions, ZIP-243/244 sighash) and Groestlcoin
/// (Groestl-512 base58 checksum) need encoders this crate does not have.
pub const EXCLUDED: &[(&str, &str)] = &[("zec", "two-byte version prefixes and ZIP-243/244 sighash: not implemented"), ("grs", "Groestl hash in base58check: not implemented")];
pub fn chain(name: &str) -> Option<&'static Chain> { CHAINS.iter().find(|c| c.name == name) }
/// Supported = verified row. Tools refuse unverified rows unless the caller opts in.
pub fn supported(name: &str) -> Option<&'static Chain> { chain(name).filter(|c| c.verified) }

#[cfg(feature = "secrets")]
pub struct Row { pub chain: &'static str, pub kind: &'static str, pub path: String, pub address: String, pub secret_field: &'static str, pub secret: String }

fn b58check(payload: &[u8]) -> String { bitcoin::base58::encode_check(payload) }
pub(crate) const XRP_ALPHA: &[u8; 58] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
pub(crate) const BTC_ALPHA: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/// Ripple base58check: same digits as Bitcoin's base58check, different alphabet.
pub fn xrp_b58check(payload: &[u8]) -> String {
    b58check(payload).bytes().map(|c| XRP_ALPHA[BTC_ALPHA.iter().position(|x| *x == c).unwrap()] as char).collect()
}
fn h160(b: &[u8]) -> [u8; 20] { hash160::Hash::hash(b).to_byte_array() }
fn ver(v: u8, b: &[u8]) -> Vec<u8> { let mut x = vec![v]; x.extend_from_slice(b); x }

#[cfg(feature = "secrets")]
pub fn wif(version: u8, sk: &SecretKey, compressed: bool) -> String {
    let mut p = ver(version, &sk.secret_bytes());
    if compressed { p.push(1) }
    b58check(&p)
}
fn segwit_v0(hrp: &str, prog: &[u8]) -> String {
    bech32::segwit::encode_v0(Hrp::parse(hrp).expect("static hrp"), prog).expect("20-byte program")
}
pub(crate) fn keccak_addr20(pk: &PublicKey) -> [u8; 20] {
    let h = Keccak256::digest(&pk.serialize_uncompressed()[1..]);
    h[12..].try_into().unwrap()
}

/// Public address row: no key material. This is what default (secrets-off) builds produce.
#[derive(Clone, Debug, PartialEq)]
pub struct AddrRow { pub chain: &'static str, pub kind: &'static str, pub path: String, pub address: String }

/// Address rows for one secp256k1 PUBLIC key on one chain (all script types the chain
/// supports). `uncompressed` adds legacy uncompressed p2pkh.
pub fn pub_rows(c: &Chain, path: &str, pk: &PublicKey, uncompressed: bool) -> Vec<AddrRow> {
    let row = |kind, address: String| AddrRow { chain: c.name, kind, path: path.to_string(), address };
    match c.enc {
        Enc::Utxo { p2pkh, p2sh, hrp, taproot, .. } => {
            let cpk = pk.serialize();
            let mut v = vec![row("p2pkh", b58check(&ver(p2pkh, &h160(&cpk))))];
            if uncompressed { v.push(row("p2pkh-uncompressed", b58check(&ver(p2pkh, &h160(&pk.serialize_uncompressed()))))) }
            if let Some(h) = hrp {
                let mut redeem = vec![0u8, 20]; redeem.extend_from_slice(&h160(&cpk));
                v.push(row("p2sh-p2wpkh", b58check(&ver(p2sh, &h160(&redeem)))));
                v.push(row("p2wpkh", segwit_v0(h, &h160(&cpk))));
            }
            if taproot {
                let secp = Secp256k1::verification_only();
                v.push(row("p2tr", bitcoin::Address::p2tr(&secp, pk.x_only_public_key().0, None, bitcoin::Network::Bitcoin).to_string()));
            }
            v
        }
        Enc::Eth => vec![row("eth", crate::eth_address_from_pubkey(&pk.serialize_uncompressed()))],
        Enc::Tron => vec![row("tron", b58check(&ver(0x41, &keccak_addr20(pk))))],
        Enc::Xrp => vec![row("xrp", xrp_b58check(&ver(0x00, &h160(&pk.serialize()))))],
        Enc::Sol => vec![],
    }
}
/// Solana address of a 32-byte ed25519 public key (base58).
pub fn sol_address(pubkey: &[u8; 32]) -> String { bitcoin::base58::encode(pubkey) }

/// Address rows plus the private key, for one secp256k1 key. Feature `secrets` only.
#[cfg(feature = "secrets")]
pub fn secp_rows(c: &Chain, path: &str, sk: &SecretKey, uncompressed: bool, secp: &Secp256k1<All>) -> Vec<Row> {
    let pk = PublicKey::from_secret_key(secp, sk);
    pub_rows(c, path, &pk, uncompressed).into_iter().map(|r| {
        let (secret_field, secret) = match c.enc {
            Enc::Utxo { wif: wv, .. } => ("wif", wif(wv, sk, r.kind != "p2pkh-uncompressed")),
            _ => ("private_key", crate::hex_enc(sk.secret_bytes())),
        };
        Row { chain: r.chain, kind: r.kind, path: r.path, address: r.address, secret_field, secret }
    }).collect()
}
/// Script-type -> BIP purpose for UTXO chains.
#[cfg(feature = "secrets")]
fn purpose(kind: &str) -> u32 { match kind { "p2sh-p2wpkh" => 49, "p2wpkh" => 84, "p2tr" => 86, _ => 44 } }

/// ed25519 key from a 32-byte seed: (address = base58 pubkey, secret = base58(seed||pub), the
/// 64-byte keypair format Solana wallets import).
#[cfg(all(feature = "ed25519", feature = "secrets"))]
pub fn sol_row(path: &str, seed: &[u8; 32]) -> Row {
    let sk = ed25519_dalek::SigningKey::from_bytes(seed);
    let pubk = sk.verifying_key().to_bytes();
    let mut kp = seed.to_vec(); kp.extend_from_slice(&pubk);
    let secret = bitcoin::base58::encode(&kp);
    kp.iter_mut().for_each(|b| *b = 0);
    Row { chain: "sol", kind: "sol", path: path.into(), address: bitcoin::base58::encode(&pubk), secret_field: "private_key", secret }
}
/// SLIP-0010 ed25519 derivation (hardened only) from a BIP39 seed.
#[cfg(feature = "secrets")]
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
#[cfg(feature = "secrets")]
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
#[cfg(all(feature = "ed25519", feature = "secrets"))]
pub fn derive_sol(seed: &[u8], count: u32) -> Vec<Row> {
    (0..count).map(|i| sol_row(&format!("m/44'/501'/{i}'/0'"), &slip10_ed25519(seed, &[44, 501, i, 0]))).collect()
}

#[cfg(all(test, feature = "secrets"))]
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
#[cfg(all(test, feature = "secrets"))]
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

/// Standard output script -> (kind, address) on a UTXO chain. None for non-standard scripts
/// (bare multisig, OP_RETURN, ...); callers show those as "nonstandard".
pub fn script_to_address(c: &Chain, s: &[u8]) -> Option<(&'static str, String)> {
    let Enc::Utxo { p2pkh, p2sh, hrp, .. } = c.enc else { return None };
    let seg = |v: u8, p: &[u8]| -> Option<String> {
        let h = Hrp::parse(hrp?).ok()?;
        bech32::segwit::encode(h, bech32::Fe32::try_from(v).ok()?, p).ok()
    };
    match s {
        [0x76, 0xa9, 0x14, h @ .., 0x88, 0xac] if h.len() == 20 => Some(("p2pkh", b58check(&ver(p2pkh, h)))),
        [0xa9, 0x14, h @ .., 0x87] if h.len() == 20 => Some(("p2sh", b58check(&ver(p2sh, h)))),
        [0x00, 0x14, h @ ..] if h.len() == 20 => Some(("p2wpkh", seg(0, h)?)),
        [0x00, 0x20, h @ ..] if h.len() == 32 => Some(("p2wsh", seg(0, h)?)),
        [0x51, 0x20, h @ ..] if h.len() == 32 => Some(("p2tr", seg(1, h)?)),
        // Pay-to-pubkey (early coinbase era): shown as the P2PKH address of that key.
        [0x41, k @ .., 0xac] if k.len() == 65 => Some(("p2pk", b58check(&ver(p2pkh, &h160(k))))),
        [0x21, k @ .., 0xac] if k.len() == 33 => Some(("p2pk", b58check(&ver(p2pkh, &h160(k))))),
        _ => None,
    }
}
/// Inverse of script_to_address for the standard kinds (destinations for tx-build).
pub fn address_to_script(c: &Chain, a: &str) -> Option<Vec<u8>> {
    let Enc::Utxo { p2pkh, p2sh, hrp, .. } = c.enc else { return None };
    if let Some(h) = hrp {
        if a.to_ascii_lowercase().starts_with(&format!("{h}1")) {
            let (hh, v, p) = bech32::segwit::decode(a).ok()?;
            if hh.as_str() != h { return None }
            let v = v.to_u8();
            if !matches!((v, p.len()), (0, 20) | (0, 32) | (1, 32)) { return None }
            let mut s = vec![if v == 0 { 0 } else { 0x50 + v }, p.len() as u8]; s.extend(p); return Some(s);
        }
    }
    let b = bitcoin::base58::decode_check(a).ok()?;
    if b.len() != 21 { return None }
    let h = &b[1..];
    if b[0] == p2pkh { let mut s = vec![0x76, 0xa9, 0x14]; s.extend(h); s.extend([0x88, 0xac]); Some(s) }
    else if b[0] == p2sh { let mut s = vec![0xa9, 0x14]; s.extend(h); s.push(0x87); Some(s) }
    else { None }
}

#[cfg(test)]
mod pub_kat {
    use super::*;
    // Public key of private key 1 = generator G (textbook value); no secret involved.
    #[test] fn generator_addresses() {
        let g = PublicKey::from_slice(&crate::hex_dec("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap()).unwrap();
        let r = pub_rows(chain("btc").unwrap(), "", &g, true);
        assert_eq!(r[0].address, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
        assert_eq!(r[1].address, "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm");
        assert_eq!(r.iter().find(|r| r.kind == "p2wpkh").unwrap().address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert_eq!(pub_rows(chain("eth").unwrap(), "", &g, false)[0].address, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
        assert_eq!(pub_rows(chain("tron").unwrap(), "", &g, false)[0].address, "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC");
    }
}

#[cfg(all(test, feature = "secrets"))]
mod kat_long_tail {
    use super::*;
    // Generated by scripts/kat-chains.py (independent base58check, version bytes copied from each
    // coin's source). Private key 1 / generator G are textbook public values.
    const V: &[(&str, &str, &str)] = &[
        ("btc", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"),
        ("ltc", "LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ", "T33ydQRKp4FCW5LCLLUB7deioUMoveiwekdwUwyfRDeGZm76aUjV"),
        ("doge", "DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE", "QNcdLVw8fHkixm6NNyN6nVwxKek4u7qrioRbQmjxac5TVoTtZuot"),
        ("qtum", "QXHFfTBKYXjaaTH1e7Rox8CcdNPGHVhM59", "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"),
        ("ftc", "6pQiLg4eJbM2bP9CZemnccDzwB3kz2Ae1x", "N1LYBvAjrq6XNUt5Xm3p3iSALhXdYRWE7jTWTWCSix24zWLX171A"),
        ("nmc", "N7FdkoPbHSxKfrSVVbRu3NZtrLqc1oKpAR", "TdNVv3rvWfukQ9PGYe3kJL2foDARGKorJX8TimN3P8f7h5uGyJzz"),
        ("dash", "XmN7PQYWKn5MJFna5fRYgP6mxT2F7xpekE", "XBHddvWWiMu3nZhhpTXBQWJMmdz5JNKJD85b9fgKAckCT2coW3Y4"),
        ("vtc", "Vkg6Ts44mskyD668xZkxFkjqovjXX9yUzZ", "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"),
        ("dgb", "DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE", "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"),
        ("via", "Vkg6Ts44mskyD668xZkxFkjqovjXX9yUzZ", "WSPUn7i1qbKMuyds45YiRdpvXTyp8GxfPuxwMPwqiDye3Nc8SkGq"),
        ("mona", "MJaRnao1s62a2zAKSkmG582KbLKianqb7v", "T33ydQRKp4FCW5LCLLUB7deioUMoveiwekdwUwyfRDeGZm76aUjV"),
        ("rvn", "RKxTdfmtxtfLDKZBgx6SvNkBtNu9jRYnLh", "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"),
        ("xpm", "AST9CekEhDWuxHPynRmeyjg5biNFSijvb3", "PLZDLNQqSDLm98zzWSbrDHHYacLW4Bwmai4gVbKJ9FoUXV7pNBkk"),
        ("trc", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"),
        ("mec", "MJaRnao1s62a2zAKSkmG582KbLKianqb7v", "TLDEmj98AN5UT7MjSVFxhyqhJLm7bVGPydtCbrfrQB9h8RTVrfwH"),
        ("aur", "AST9CekEhDWuxHPynRmeyjg5biNFSijvb3", "T33ydQRKp4FCW5LCLLUB7deioUMoveiwekdwUwyfRDeGZm76aUjV"),
        ("bch", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"),
        ("bsv", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"),
        ("btg", "GUXByHDZLvU4DnVH9imSFckt3HEQ5cFgE5", "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"),
        ("ppc", "PKGSi8HTQzLx89rkZrRrVkPFjrcSC55NP9", "U57PdXwd38fAKhRaCsERgrK8YWmNmad2nqzrQ8QKrZvFY5Su3RGB"),
        ("nvc", "4QP6S2Gv3WZmgnJgR8mshrbHA9W6hQiTxR", "M7rkkx1LoubhXNoUDJgTGfsEr6KiXuss95ij6n7sn5VoJX3uPDSV"),
        ("clam", "xJyuT2j5dnLoBhHraFjzG2hmMDjnS3fefx", "Lg7s3TveHSrHbpmAZ5Vmt9an6nim2f4gekrLRR5bJeEfTXVDHAET"),
        ("blk", "BF8MAsLp7aSfb9g9qGSHwzDerit8nAZAJX", "PdiUUh8dnXB36B2XcbPdodUX5Ujoj2VDubJwcW1V8DJu69XHZWGg"),
        ("rdd", "RjJ4cn5Bg58D2khGiNRmQW1yWtA6Py9kWa", "UxbB4W72649zAoWBXKbnTtt437yHn6FPmVjdkrUtoSSXE4gwagjA"),
        ("pot", "PKGSi8HTQzLx89rkZrRrVkPFjrcSC55NP9", "U57PdXwd38fAKhRaCsERgrK8YWmNmad2nqzrQ8QKrZvFY5Su3RGB"),
        ("qrk", "QXHFfTBKYXjaaTH1e7Rox8CcdNPGHVhM59", "UWrHM22KZbQaFFTss6R75NbbHpNLGqSDHAsF5VScL1BPP51rGEYX"),
        ("wdc", "WZMJS5eeCEgiqxNK1QRbE1HR4wFQwmCjJV", "WjYjvSRpBu9ds1fQAELW1z1u2LP7o7W7ioDCUJe2hBV4c2yyqEp3"),
        ("anc", "AST9CekEhDWuxHPynRmeyjg5biNFSijvb3", "PLZDLNQqSDLm98zzWSbrDHHYacLW4Bwmai4gVbKJ9FoUXV7pNBkk"),
    ];
    #[test] fn every_utxo_row_matches_independent_vector() {
        let s = Secp256k1::new(); let mut b = [0u8; 32]; b[31] = 1; let k = SecretKey::from_slice(&b).unwrap();
        for (n, p2pkh, w) in V {
            let r = secp_rows(chain(n).unwrap(), "", &k, false, &s);
            assert_eq!(r[0].address, *p2pkh, "{n} p2pkh"); assert_eq!(r[0].secret, *w, "{n} wif");
            assert!(crate::validate::validate(n, p2pkh).is_ok(), "{n} validate");
        }
        for c in CHAINS { if let Enc::Utxo { hrp: Some(h), .. } = c.enc { assert!(blocktools_schema::HRPS.contains(&h), "schema HRPS missing {h}") } }
        for c in CHAINS { assert!(blocktools_schema::CHAINS.contains(&c.name), "schema CHAINS missing {}", c.name) }
        // every UTXO row in the table has a vector
        for c in CHAINS.iter().filter(|c| matches!(c.enc, Enc::Utxo { .. })) { assert!(V.iter().any(|v| v.0 == c.name), "{} has no KAT", c.name) }
    }
}
