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
    /// Cosmos SDK: secp256k1, bech32(hrp, ripemd160(sha256(compressed pubkey))), m/44'/118'/0'/0/i
    Cosmos { hrp: &'static str },
    /// Stellar: ed25519, SLIP-0010, SEP-0005 path m/44'/148'/i'; StrKey G... / S...
    Xlm,
    /// Monero: ed25519 spend/view keys from its own 25-word seed (crates/monero); not secp-derivable.
    Xmr,
}
/// How transactions are signed on a UTXO chain. Only `Standard` (Bitcoin legacy/BIP143
/// sighash, Bitcoin tx serialisation) is built and signed by tx-build/tx-sign; the others are
/// derive / validate / decode-address only until implemented and tested.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Sign { Standard, ForkId(u8), PosTime, Unknown,
    /// Bitcoin serialisation and sighash layout, but txid, legacy sighash and the BIP143 digest
    /// (and its hashPrevouts/hashSequence/hashOutputs) are single SHA-256 (Groestlcoin).
    Sha256Single }
impl Enc { /// ed25519 chain (SLIP-0010, hardened only; no xpub).
    pub fn ed25519(self) -> bool { matches!(self, Enc::Sol | Enc::Xlm) } }
impl Sign { /// tx-build / tx-sign build and sign this scheme.
    pub fn buildable(self) -> bool { matches!(self, Sign::Standard | Sign::Sha256Single) } }
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
/// Sources measured by SwapChan's keyless probes (old-coins plan, 2026-10-24): balance + UTXO list.
const SP: &str = "2026-10-24 (SwapChan probe: balance+utxo)";
const fn bb(name: &'static str, url: &'static str, api: &'static str) -> Source { Source { name, url, api, checked: SP } }
const fn cz(t: &'static str, api: &'static str) -> Source { Source { name: "chainz.cryptoid.info", url: t, api, checked: "2026-10-24 (balance only; unspent needs an API key)" } }
use Sign::*;
pub const CHAINS: &[Chain] = &[
    Chain { name: "btc", ticker: "BTC", title: "Bitcoin", coin: 0, enc: Enc::Utxo { p2pkh: 0x00, p2sh: 0x05, hrp: Some("bc"), wif: 0x80, taproot: true }, default_count: 10, sign: Standard, verified: true,
            source: "bitcoin/bitcoin src/kernel/chainparams.cpp", sources: &[Source { name: "blockstream.info", url: "https://blockstream.info/address/{addr}", api: "esplora:https://blockstream.info/api", checked: D }] },
    u("ltc", "LTC", "Litecoin", 2, 48, 50, 176, Some("ltc"), Standard, true, "litecoin-project/litecoin src/chainparams.cpp", &[Source { name: "litecoinspace.org", url: "https://litecoinspace.org/address/{addr}", api: "esplora:https://litecoinspace.org/api", checked: D }]),
    u("doge", "DOGE", "Dogecoin", 3, 30, 22, 158, None, Standard, true, "dogecoin/dogecoin src/chainparams.cpp", &[]),
    Chain { name: "eth", ticker: "ETH", title: "Ethereum / EVM", coin: 60, enc: Enc::Eth, default_count: 5, sign: Standard, verified: true, source: "EIP-55, EIP-155, EIP-1559", sources: &[] },
    Chain { name: "tron", ticker: "TRX", title: "Tron", coin: 195, enc: Enc::Tron, default_count: 10, sign: Unknown, verified: true, source: "tronprotocol docs: 0x41 || keccak20, base58check", sources: &[] },
    Chain { name: "xrp", ticker: "XRP", title: "XRP Ledger", coin: 144, enc: Enc::Xrp, default_count: 10, sign: Unknown, verified: true, source: "xrpl.org: account ID, ripple base58 alphabet", sources: &[] },
    Chain { name: "atom", ticker: "ATOM", title: "Cosmos Hub", coin: 118, enc: Enc::Cosmos { hrp: "cosmos" }, default_count: 10, sign: Unknown, verified: true, source: "cosmjs Secp256k1HdWallet: m/44'/118'/0'/0/i, bech32 cosmos", sources: &[] },
    Chain { name: "xlm", ticker: "XLM", title: "Stellar", coin: 148, enc: Enc::Xlm, default_count: 10, sign: Unknown, verified: true, source: "SEP-0005: SLIP-0010 ed25519, m/44'/148'/i'", sources: &[] },
    Chain { name: "sol", ticker: "SOL", title: "Solana", coin: 501, enc: Enc::Sol, default_count: 10, sign: Unknown, verified: true, source: "SLIP-0010 ed25519, m/44'/501'/i'/0'", sources: &[] },
    Chain { name: "xmr", ticker: "XMR", title: "Monero", coin: 128, enc: Enc::Xmr, default_count: 1, sign: Unknown, verified: true, source: "monero-project/monero src/cryptonote_config.h (netbytes 18/24/53), KAT monero-python test_seed.py", sources: &[] },
    // ---- Bitcoin-family long tail. Bytes are decimal as written in each coin's source. ----
    u("qtum", "QTUM", "Qtum", 2301, 58, 50, 128, Some("qc"), Standard, true, "qtumproject/qtum src/kernel/chainparams.cpp", &[bb("qtum.info", "https://qtum.info/address/{addr}", "qtuminfo:https://qtum.info/api")]),
    u("ftc", "FTC", "Feathercoin", 8, 14, 5, 142, Some("fc"), Standard, true, "FeatherCoin/Feathercoin src/chainparams.cpp", &[]),
    u("nmc", "NMC", "Namecoin", 7, 52, 13, 180, Some("nc"), Standard, true, "namecoin/namecoin-core src/kernel/chainparams.cpp", &[]),
    u("dash", "DASH", "Dash", 5, 76, 16, 204, None, Standard, true, "dashpay/dash src/chainparams.cpp", &[bb("blockbook.dash.zelcore.io", "https://blockbook.dash.zelcore.io/address/{addr}", "blockbook:https://blockbook.dash.zelcore.io/api"), bb("insight.dash.org", "https://insight.dash.org/insight/address/{addr}", "insight:https://insight.dash.org/insight-api")]),
    u("vtc", "VTC", "Vertcoin", 28, 71, 5, 128, Some("vtc"), Standard, true, "vertcoin-project/vertcoin-core src/chainparams.cpp", &[bb("blockbook.vtc.zelcore.io", "https://blockbook.vtc.zelcore.io/address/{addr}", "blockbook:https://blockbook.vtc.zelcore.io/api")]),
    u("dgb", "DGB", "DigiByte", 20, 30, 63, 128, Some("dgb"), Standard, true, "DigiByte-Core/digibyte src/chainparams.cpp", &[bb("blockbook.dgb.zelcore.io", "https://blockbook.dgb.zelcore.io/address/{addr}", "blockbook:https://blockbook.dgb.zelcore.io/api")]),
    u("via", "VIA", "Viacoin", 14, 71, 33, 199, Some("via"), Standard, true, "viacoin/viacoin src/chainparams.cpp", &[bb("blockbook.viacoin.org", "https://blockbook.viacoin.org/address/{addr}", "blockbook:https://blockbook.viacoin.org/api")]),
    u("mona", "MONA", "Monacoin", 22, 50, 55, 176, Some("mona"), Standard, true, "monacoinproject/monacoin src/chainparams.cpp", &[bb("mona.insight.monaco-ex.org", "https://mona.insight.monaco-ex.org/insight/address/{addr}", "insight:https://mona.insight.monaco-ex.org/insight-api-monacoin")]),
    u("rvn", "RVN", "Ravencoin", 175, 60, 122, 128, None, Standard, true, "RavenProject/Ravencoin src/chainparams.cpp", &[bb("blockbook.rvn.zelcore.io", "https://blockbook.rvn.zelcore.io/address/{addr}", "blockbook:https://blockbook.rvn.zelcore.io/api"), Source { name: "blockbook.ravencoin.org", url: "https://blockbook.ravencoin.org/address/{addr}", api: "blockbook:https://blockbook.ravencoin.org/api", checked: D }]),
    u("xpm", "XPM", "Primecoin", 24, 23, 83, 151, None, Standard, true, "primecoin/primecoin src/base58.h (WIF = 128 + PUBKEY_ADDRESS)", &[cz("https://chainz.cryptoid.info/xpm/address.dws?{addr}", "cryptoid:https://chainz.cryptoid.info/xpm/api.dws")]),
    u("trc", "TRC", "Terracoin", 83, 0, 5, 128, None, Standard, true, "terracoin/terracoin src/chainparams.cpp", &[]),
    u("mec", "MEC", "Megacoin", 217, 50, 5, 178, Some("mec"), Standard, true, "LIMXTEC/Megacoin src/chainparams.cpp", &[]),
    u("aur", "AUR", "Auroracoin", 85, 23, 5, 176, None, Standard, true, "aurarad/auroracoin src/chainparams.cpp", &[cz("https://chainz.cryptoid.info/aur/address.dws?{addr}", "cryptoid:https://chainz.cryptoid.info/aur/api.dws")]),
    u("bch", "BCH", "Bitcoin Cash (legacy addresses)", 145, 0, 5, 128, None, ForkId(0), true, "same legacy bytes as Bitcoin; SIGHASH_FORKID", &[]),
    u("bsv", "BSV", "Bitcoin SV (legacy addresses)", 236, 0, 5, 128, None, ForkId(0), true, "same legacy bytes as Bitcoin; SIGHASH_FORKID", &[bb("whatsonchain.com", "https://whatsonchain.com/address/{addr}", "woc:https://api.whatsonchain.com/v1/bsv/main")]),
    u("btg", "BTG", "Bitcoin Gold", 156, 38, 23, 128, Some("btg"), ForkId(79), true, "BTCGPU/BTCGPU src/chainparams.cpp", &[]),
    u("ppc", "PPC", "Peercoin", 6, 55, 117, 183, Some("pc"), PosTime, true, "peercoin/peercoin src/kernel/chainparams.cpp", &[bb("blockbook.peercoin.net", "https://blockbook.peercoin.net/address/{addr}", "blockbook:https://blockbook.peercoin.net/api")]),
    u("nvc", "NVC", "Novacoin", 50, 8, 20, 136, None, PosTime, true, "novacoin-project/novacoin src/base58.h (WIF = 128 + PUBKEY_ADDRESS)", &[cz("https://chainz.cryptoid.info/nvc/address.dws?{addr}", "cryptoid:https://chainz.cryptoid.info/nvc/api.dws")]),
    u("clam", "CLAM", "Clams", 23, 137, 13, 133, None, PosTime, true, "nochowderforyou/clams src/chainparams.cpp", &[cz("https://chainz.cryptoid.info/clam/address.dws?{addr}", "cryptoid:https://chainz.cryptoid.info/clam/api.dws")]),
    u("blk", "BLK", "Blackcoin", 10, 25, 85, 153, None, Standard, true, "CoinBlack/blackcoin src/chainparams.cpp; tx layout: v2 Bitcoin format, no nTime (mainnet txs in tx/tests/data/pos_mainnet.txt)", &[cz("https://chainz.cryptoid.info/blk/address.dws?{addr}", "cryptoid:https://chainz.cryptoid.info/blk/api.dws")]),
    u("rdd", "RDD", "Reddcoin", 4, 61, 5, 189, Some("rdd"), PosTime, true, "reddcoin-project/reddcoin src/chainparams.cpp", &[bb("blockbook.reddcoin.com", "https://blockbook.reddcoin.com/address/{addr}", "blockbook:https://blockbook.reddcoin.com/api")]),
    u("pot", "POT", "Potcoin", 81, 55, 110, 183, None, PosTime, true, "potcoin/Potcoin src/base58.h (WIF = 128 + PUBKEY_ADDRESS)", &[cz("https://chainz.cryptoid.info/pot/address.dws?{addr}", "cryptoid:https://chainz.cryptoid.info/pot/api.dws")]),
    u("qrk", "QRK", "Quark", 82, 58, 9, 186, None, Unknown, true, "quark-project/quark src/chainparams.cpp", &[cz("https://chainz.cryptoid.info/qrk/address.dws?{addr}", "cryptoid:https://chainz.cryptoid.info/qrk/api.dws")]),
    u("grs", "GRS", "Groestlcoin", 17, 36, 5, 128, Some("grs"), Sha256Single, true, "Groestlcoin/groestlcoin src/kernel/chainparams.cpp; Groestl-512 base58 checksum; KAT groestlcoinjs-lib test/integration", &[]),
    // No SLIP-44 coin type registered: address encoding is from source, derivation path is not.
    u("wdc", "WDC", "Worldcoin", 0, 73, 5, 201, None, Standard, false, "worldcoinproject/worldcoin-v0.8 src/base58.h; no SLIP-44 entry", &[cz("https://chainz.cryptoid.info/wdc/address.dws?{addr}", "cryptoid:https://chainz.cryptoid.info/wdc/api.dws")]),
    u("anc", "ANC", "Anoncoin", 0, 23, 15, 151, None, Standard, false, "Anoncoin/anoncoin src/chainparams.cpp; no SLIP-44 entry", &[]),
];
/// Not in the table, on purpose: Zcash (2-byte versions, ZIP-243/244 sighash) needs encoders
/// this crate does not have.
pub const EXCLUDED: &[(&str, &str)] = &[("zec", "two-byte version prefixes: handled outside this table (blocktools-tx zcash module; transparent only)")];
/// Base58check checksum flavour. Groestlcoin uses groestl512(groestl512(x))[..4] for addresses,
/// WIF and extended keys (groestlcoin src/base58.cpp, hash.h `HashGroestl`); everyone else sha256d.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Ck { Sha256d, Groestl }
impl Chain { pub fn ck(&self) -> Ck { if self.name == "grs" { Ck::Groestl } else { Ck::Sha256d } } }
fn groestl4(b: &[u8]) -> [u8; 4] {
    use groestl::{Digest as _, Groestl512};
    let h = Groestl512::digest(Groestl512::digest(b));
    [h[0], h[1], h[2], h[3]]
}
/// Base58check with the chain's checksum.
pub fn b58check_ck(ck: Ck, payload: &[u8]) -> String {
    match ck { Ck::Sha256d => bitcoin::base58::encode_check(payload), Ck::Groestl => { let mut v = payload.to_vec(); v.extend_from_slice(&groestl4(payload)); bitcoin::base58::encode(&v) } }
}
pub fn decode_check_ck(ck: Ck, s: &str) -> Result<Vec<u8>, &'static str> {
    match ck {
        Ck::Sha256d => bitcoin::base58::decode_check(s).map_err(|_| "bad base58check"),
        Ck::Groestl => {
            let mut v = bitcoin::base58::decode(s).map_err(|_| "bad base58check")?;
            if v.len() < 5 { return Err("bad base58check") }
            let n = v.len() - 4;
            if v[n..] != groestl4(&v[..n]) { return Err("bad base58check") }
            v.truncate(n); Ok(v)
        }
    }
}
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
pub fn wif(version: u8, sk: &SecretKey, compressed: bool) -> String { wif_ck(Ck::Sha256d, version, sk, compressed) }
#[cfg(feature = "secrets")]
pub fn wif_ck(ck: Ck, version: u8, sk: &SecretKey, compressed: bool) -> String {
    let mut p = ver(version, &sk.secret_bytes());
    if compressed { p.push(1) }
    let s = b58check_ck(ck, &p);
    zeroize::Zeroize::zeroize(&mut p);
    s
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
            let b58check = |p: &[u8]| b58check_ck(c.ck(), p);
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
        Enc::Cosmos { hrp } => vec![row("cosmos", cosmos_address(hrp, &h160(&pk.serialize())))],
        Enc::Sol | Enc::Xlm | Enc::Xmr => vec![],
    }
}
/// Cosmos SDK account address: plain bech32 (not segwit) of a 20-byte hash.
pub fn cosmos_address(hrp: &str, h: &[u8]) -> String { bech32::encode::<bech32::Bech32>(Hrp::parse(hrp).expect("static hrp"), h).expect("20 bytes") }
/// Decode a Cosmos bech32 address; returns the 20-byte hash when the hrp matches.
pub fn cosmos_decode(hrp: &str, a: &str) -> Result<Vec<u8>, &'static str> {
    let (h, d) = bech32::decode(a).map_err(|_| "bad bech32")?;
    if h.as_str() != hrp { return Err("wrong network") }
    if a.chars().any(|c| c.is_ascii_uppercase()) || bech32::primitives::decode::CheckedHrpstring::new::<bech32::Bech32>(a).is_err() { return Err("bad bech32") }
    if d.len() != 20 { return Err("bad length") }
    Ok(d)
}
/// CRC16-XModem (poly 0x1021, init 0), as used by Stellar StrKey.
fn crc16_xmodem(d: &[u8]) -> u16 {
    let mut c: u16 = 0;
    for &b in d { c ^= (b as u16) << 8; for _ in 0..8 { c = if c & 0x8000 != 0 { (c << 1) ^ 0x1021 } else { c << 1 } } }
    c
}
const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/// Stellar StrKey: base32(version || payload || crc16-xmodem LE), no padding.
/// Versions: 6<<3 = 'G' account id, 18<<3 = 'S' seed.
pub fn strkey_encode(version: u8, payload: &[u8]) -> String {
    let mut d = vec![version]; d.extend_from_slice(payload);
    let c = crc16_xmodem(&d); d.extend_from_slice(&c.to_le_bytes());
    let (mut out, mut acc, mut bits) = (String::new(), 0u32, 0);
    for b in &d { acc = (acc << 8) | *b as u32; bits += 8; while bits >= 5 { bits -= 5; out.push(B32[((acc >> bits) & 31) as usize] as char) } }
    if bits > 0 { out.push(B32[((acc << (5 - bits)) & 31) as usize] as char) }
    d.iter_mut().for_each(|b| *b = 0);
    out
}
/// Decode a StrKey; checks the alphabet, length, canonical trailing bits and the CRC.
pub fn strkey_decode(s: &str) -> Result<(u8, Vec<u8>), &'static str> {
    let (mut d, mut acc, mut bits) = (Vec::new(), 0u32, 0);
    for ch in s.bytes() {
        let v = B32.iter().position(|&x| x == ch).ok_or("bad base32")? as u32;
        acc = (acc << 5) | v; bits += 5;
        if bits >= 8 { bits -= 8; d.push((acc >> bits) as u8) }
    }
    if bits >= 5 || acc & ((1 << bits) - 1) != 0 { return Err("bad base32") }
    if d.len() < 3 { return Err("bad length") }
    let (body, ck) = d.split_at(d.len() - 2);
    if crc16_xmodem(body).to_le_bytes() != ck { return Err("bad checksum") }
    Ok((body[0], body[1..].to_vec()))
}
/// Stellar account id (G...) of a 32-byte ed25519 public key.
pub fn xlm_address(pubkey: &[u8; 32]) -> String { strkey_encode(6 << 3, pubkey) }
/// Solana address of a 32-byte ed25519 public key (base58).
pub fn sol_address(pubkey: &[u8; 32]) -> String { bitcoin::base58::encode(pubkey) }

/// Address rows plus the private key, for one secp256k1 key. Feature `secrets` only.
#[cfg(feature = "secrets")]
pub fn secp_rows(c: &Chain, path: &str, sk: &SecretKey, uncompressed: bool, secp: &Secp256k1<All>) -> Vec<Row> {
    let pk = PublicKey::from_secret_key(secp, sk);
    pub_rows(c, path, &pk, uncompressed).into_iter().map(|r| {
        let (secret_field, secret) = match c.enc {
            Enc::Utxo { wif: wv, .. } => ("wif", wif_ck(c.ck(), wv, sk, r.kind != "p2pkh-uncompressed")),
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
/// Stellar row from a 32-byte ed25519 seed: address G..., secret S... (StrKey seed).
#[cfg(all(feature = "ed25519", feature = "secrets"))]
pub fn xlm_row(path: &str, seed: &[u8; 32]) -> Row {
    let pubk = ed25519_dalek::SigningKey::from_bytes(seed).verifying_key().to_bytes();
    Row { chain: "xlm", kind: "xlm", path: path.into(), address: xlm_address(&pubk), secret_field: "private_key", secret: strkey_encode(18 << 3, seed) }
}
/// ed25519 row for an ed25519 chain (sol / xlm).
#[cfg(all(feature = "ed25519", feature = "secrets"))]
pub fn ed_row(c: &Chain, path: &str, seed: &[u8; 32]) -> Row { if c.enc == Enc::Xlm { xlm_row(path, seed) } else { sol_row(path, seed) } }
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
        Enc::Sol | Enc::Xlm => return vec![],
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
    let b58check = |p: &[u8]| b58check_ck(c.ck(), p);
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
    let b = decode_check_ck(c.ck(), a).ok()?;
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
        // every UTXO row in the table has a vector (grs: Groestl checksum, covered by grs_kats /
        // grs_wif_and_bip32_kats below from groestlcoinjs-lib and Electrum-GRS)
        for c in CHAINS.iter().filter(|c| matches!(c.enc, Enc::Utxo { .. }) && c.name != "grs") { assert!(V.iter().any(|v| v.0 == c.name), "{} has no KAT", c.name) }
    }
    /// Groestlcoin KATs from groestlcoinjs-lib test/integration (addresses.spec.ts, bip32.spec.ts),
    /// an implementation independent of this crate.
    #[test] fn grs_kats() {
        let c = chain("grs").unwrap();
        let one = PublicKey::from_slice(&crate::hex_dec("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap()).unwrap();
        let r = pub_rows(c, "", &one, false);
        let get = |k: &str| r.iter().find(|x| x.kind == k).unwrap().address.clone();
        assert_eq!(get("p2pkh"), "Ffqz14cyvZYJavD76t6oHNDJnGiWcZMVxR");
        assert_eq!(get("p2sh-p2wpkh"), "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJFpSXbA");
        assert_eq!(get("p2wpkh"), "grs1qw508d6qejxtdg4y5r3zarvary0c5xw7k3k4sj5");
        for a in ["Ffqz14cyvZYJavD76t6oHNDJnGiWcZMVxR", "Fob4maNwBGVRPmMcRLS6qtTJfKeySAMsWq", "FnTgcvXm6QMPVrYsYptMCCAVk8hVnEzS4Y", "36NUkt6FWUi3LAWBqWRdDmdTWbt94yx2nc",
                  "grs1q75f6dv4q8ug7zhujrsp5t0hzf33lllnr3fe7e2pra3v24mzl8rrqy6wvnm"] {
            assert!(crate::validate::validate("grs", a).is_ok(), "{a}");
        }
        // sha256d-checksummed lookalikes are rejected: same payload, Bitcoin checksum
        let p = decode_check_ck(Ck::Groestl, "Ffqz14cyvZYJavD76t6oHNDJnGiWcZMVxR").unwrap();
        assert_eq!(crate::validate::validate("grs", &bitcoin::base58::encode_check(&p)), Err("bad base58check"));
        assert!(crate::validate::validate("btc", "Ffqz14cyvZYJavD76t6oHNDJnGiWcZMVxR").is_err());
    }
    /// Electrum-GRS tests/test_bitcoin.py Test_keyImport (Groestl-checksummed WIF -> address) and
    /// groestlcoinjs-lib bip32.spec.ts (seed dd..dd, m/0'/0/0 and m/44'/0'/0'/0/0).
    #[cfg(feature = "secrets")]
    #[test] fn grs_wif_and_bip32_kats() {
        let secp = Secp256k1::new();
        let c = chain("grs").unwrap();
        for (w, kind, addr) in [("KzMFjMC2MPadjvX5Cd7b8AKKjjpBSoRKUTpoAtN6B3J9ezXB3Zhj", "p2pkh", "FbkiHMrpZbJLsNXSRMiWwFnda7zWRSX12q"),
                                ("5Hxn5C4SQuiV6e62A1MtZmbSeQyrLFhu5uYks62pU5VBUva3Y5H", "p2pkh-uncompressed", "FkYzwNGW2hqKQhm6GAt4UyLdbdsBBnEF2p"),
                                ("Kz6SuyPM5VktY5dr2d2YqdVgBA6LCWkiHqXJaC3BzxnMPSUjPJw2", "p2wpkh", "grs1qqmpt7u5e9hfznljta5gnvhyvfd2kdd0rc7t09c"),
                                ("Kz9XebiCXL2BZzhYJViiHDzn5iup1povWV8aqstzWU4sz1JQ3L2h", "p2sh-p2wpkh", "3GeVJB3oKr7psgKR6BTXSxKtWUkfrFK6LQ")] {
            let d = decode_check_ck(Ck::Groestl, w).unwrap();
            assert_eq!(d[0], 0x80);
            let sk = SecretKey::from_slice(&d[1..33]).unwrap();
            let rows = secp_rows(c, "", &sk, d.len() == 33, &secp);
            let r = rows.iter().find(|r| r.kind == kind).unwrap();
            assert_eq!(r.address, addr); assert_eq!(r.secret, w);
        }
        let root = Xpriv::new_master(bitcoin::Network::Bitcoin, &[0xdd; 32]).unwrap();
        for (p, a) in [("m/0'/0/0", "FnTgcvXm6QMPVrYsYptMCCAVk8hVnEzS4Y"), ("m/44'/0'/0'/0/0", "FWdhNkjqgejN6E87pTDwXrvwcCXzkN8RTM")] {
            let k = root.derive_priv(&secp, &DerivationPath::from_str(p).unwrap()).unwrap();
            assert_eq!(secp_rows(c, p, &k.private_key, false, &secp)[0].address, a);
        }
    }
}