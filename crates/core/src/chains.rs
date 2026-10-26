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
    /// Algorand: ed25519 key from the native 25-word mnemonic (no BIP32 path); address =
    /// base32(pub || sha512/256(pub)[28..])
    Algo,
    /// Substrate / Polkadot: sr25519 root key (no derivation path), SS58 address with this prefix.
    Ss58 { prefix: u8 },
    /// Stellar: ed25519, SLIP-0010, SEP-0005 path m/44'/148'/i'; StrKey G... / S...
    Xlm,
    /// Cardano Shelley: Icarus master (PBKDF2 of BIP39 entropy), BIP32-Ed25519, CIP-1852
    /// m/1852'/1815'/0'/0/i payment + m/1852'/1815'/0'/2/0 stake, base address bech32 addr1.
    Ada,
    /// TON: ed25519 key from the native 24-word TON mnemonic; address = wallet v4r2 contract
    /// (StateInit cell hash), workchain 0, user-friendly non-bounceable base64url (UQ...).
    Ton,
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
    pub fn ed25519(self) -> bool { matches!(self, Enc::Sol | Enc::Xlm) }
    /// Keys not derived from a BIP39 seed by path (own mnemonic formats).
    pub fn native_seed(self) -> bool { matches!(self, Enc::Algo | Enc::Ada | Enc::Ton | Enc::Xmr | Enc::Ss58 { .. }) } }
impl Sign { /// tx-build CLI can sign this scheme without a special layout (legacy / single-SHA).
    /// Not the chain-table `buildable` / chainParams `sweep_build` bit — that is `Chain::tx_format`.
    pub fn buildable(self) -> bool { matches!(self, Sign::Standard | Sign::Sha256Single) } }
/// A public block explorer / API. Only listed when it answered from this project's CI box.
#[derive(Clone, Copy, Debug)]
pub struct Source { pub name: &'static str, pub url: &'static str, pub api: &'static str, pub checked: &'static str }
#[derive(Clone, Copy, Debug)]
pub struct Chain {
    pub name: &'static str, pub ticker: &'static str, pub title: &'static str,
    /// SLIP-44 coin type (BIP44 path). Use `slip44()` for JSON: None when no registry entry
    /// (wdc/anc/bcc keep a placeholder 0 here only so path templates still compile; they are unverified).
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
    Chain { name: "algo", ticker: "ALGO", title: "Algorand", coin: 283, enc: Enc::Algo, default_count: 1, sign: Unknown, verified: true, source: "py-algorand-sdk: native 25-word mnemonic, sha512/256 checksum", sources: &[] },
    Chain { name: "dot", ticker: "DOT", title: "Polkadot", coin: 354, enc: Enc::Ss58 { prefix: 0 }, default_count: 1, sign: Unknown, verified: true, source: "substrate subkey: mini-secret = PBKDF2(entropy), sr25519, SS58 prefix 0", sources: &[] },
    Chain { name: "ada", ticker: "ADA", title: "Cardano", coin: 1815, enc: Enc::Ada, default_count: 5, sign: Unknown, verified: true, source: "CIP-1852/CIP-0019: Icarus master, BIP32-Ed25519, base address (Yoroi/Eternl/Daedalus Shelley)", sources: &[] },
    Chain { name: "ton", ticker: "TON", title: "TON", coin: 607, enc: Enc::Ton, default_count: 1, sign: Unknown, verified: true, source: "tonsdk/tonweb: TON mnemonic (HMAC-SHA512 + PBKDF2 \"TON default seed\"), wallet v4r2, workchain 0", sources: &[] },
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
    u("qrk", "QRK", "Quark", 82, 58, 9, 186, None, Standard, true, "quark-project/quark src/chainparams.cpp; tx format Bitcoin-legacy, COIN = 1e5, confirmed on 10 mainnet txs (tx/tests/qrk.rs)", &[cz("https://chainz.cryptoid.info/qrk/address.dws?{addr}", "cryptoid:https://chainz.cryptoid.info/qrk/api.dws")]),
    Chain { name: "grs", ticker: "GRS", title: "Groestlcoin", coin: 17, enc: Enc::Utxo { p2pkh: 36, p2sh: 5, hrp: Some("grs"), wif: 128, taproot: true }, default_count: 10, sign: Sha256Single, verified: true,
            source: "Groestlcoin/groestlcoin src/kernel/chainparams.cpp; Groestl-512 base58 checksum; KAT groestlcoinjs-lib test/integration; p2tr: Groestlcoin bip341_wallet_vectors.json (identical to Bitcoin's)", sources: &[] },
    // No SLIP-44 coin type registered: address encoding is from source, derivation path is not.
    u("wdc", "WDC", "Worldcoin", 0, 73, 5, 201, None, Standard, false, "worldcoinproject/worldcoin-v0.8 src/base58.h; no SLIP-44 entry; tx format Bitcoin-legacy confirmed on 4 mainnet txs (tx/tests/wdc.rs)", &[cz("https://chainz.cryptoid.info/wdc/address.dws?{addr}", "cryptoid:https://chainz.cryptoid.info/wdc/api.dws")]),
    u("anc", "ANC", "Anoncoin", 0, 23, 15, 151, None, Standard, false, "Anoncoin/anoncoin src/chainparams.cpp; no SLIP-44 entry", &[]),
    u("bcc", "BCC", "BitConnect", 0, 18, 85, 146, None, PosTime, false, "bitconnectcoin/bitconnectcoin@3ab3d19 src/base58.h:279-280 (PUBKEY_ADDRESS 18, SCRIPT_ADDRESS 85), :408 (WIF = 128 + PUBKEY_ADDRESS = 146); tx nTime src/main.h:443; no SLIP-44 entry (268 BCC is BCChain)", &[]),
];
/// Not in the table, on purpose: Zcash (2-byte versions, ZIP-243/244 sighash) needs encoders
/// this crate does not have.
pub const EXCLUDED: &[(&str, &str)] = &[("zec", "two-byte version prefixes: handled outside this table (blocktools-tx zcash module; transparent only)")];
/// Base58check checksum flavour. Groestlcoin uses groestl512(groestl512(x))[..4] for addresses,
/// WIF and extended keys (groestlcoin src/base58.cpp, hash.h `HashGroestl`); everyone else sha256d.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Ck { Sha256d, Groestl }
impl Chain {
    pub fn ck(&self) -> Ck { if self.name == "grs" { Ck::Groestl } else { Ck::Sha256d } }
    /// SLIP-44 coin type for exports. `None` when the registry has no entry (not the same as BTC's 0).
    pub fn slip44(&self) -> Option<u32> {
        match self.name { "wdc" | "anc" | "bcc" => None, _ => Some(self.coin) }
    }
    /// PoS nTime layouts that `build_unsigned_sweep` / `pos::layout` cover (measured).
    const POS_SWEEP: &'static [&'static str] = &["ppc", "nvc", "clam", "rdd"];
    /// Unsigned-sweep format and whether a builder accepts this chain.
    /// Rule for `buildable` / `sweep_build`: true only when an unsigned-sweep builder exists
    /// and is covered by a test (verified UTXO standard/forkid/sha256-single, or PosTime with a
    /// listed layout). EVM and account-family are false here (they use other builders). Zcash
    /// transparent is outside CHAINS and handled by the facade.
    pub fn tx_format(&self) -> (&'static str, bool) {
        match (self.enc, self.sign) {
            (Enc::Utxo { .. }, Sign::Standard) => ("legacy", self.verified || crate::chain_spec::tx_ready(self.name, false).is_ok() && crate::chain_spec::is_spec(self.name)),
            (Enc::Utxo { .. }, Sign::ForkId(_)) => ("forkid", self.verified),
            (Enc::Utxo { .. }, Sign::PosTime) => ("pos-ntime", self.verified && Self::POS_SWEEP.contains(&self.name)),
            (Enc::Utxo { .. }, Sign::Unknown) => ("unknown", false),
            (Enc::Utxo { .. }, Sign::Sha256Single) => ("legacy-sha256", self.verified),
            (Enc::Eth, _) => ("evm", false),
            _ => ("account", false),
        }
    }
}
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
/// Table row by name, or the process's chain spec (crate::chain_spec) when it has that name.
pub fn chain(name: &str) -> Option<&'static Chain> { CHAINS.iter().find(|c| c.name == name).or_else(|| crate::chain_spec::chain().filter(|c| c.name == name)) }
/// Supported = verified row, or the explicitly loaded chain spec (unverified, flagged everywhere).
pub fn supported(name: &str) -> Option<&'static Chain> { chain(name).filter(|c| c.verified || crate::chain_spec::is_spec(c.name)) }
/// True when `name` is the chain spec loaded in this process (crate::chain_spec).
pub fn chain_spec_loaded(name: &str) -> bool { crate::chain_spec::is_spec(name) }
/// "unverified chain spec" banner for plain summaries (None for table chains).
pub fn chain_spec_banner(name: &str) -> Option<String> { crate::chain_spec::banner(name) }
/// Verified rows plus the loaded spec chain: what auto-detect and "all chains" defaults use.
pub fn detectable() -> impl Iterator<Item = &'static Chain> { CHAINS.iter().filter(|c| c.verified).chain(crate::chain_spec::chain()) }

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
            // Chain spec without p2pkh: no addresses at all (tools print spec_missing_p2pkh).
            if crate::chain_spec::missing(c.name, "p2pkh").is_some() { return vec![] }
            let no_p2sh = crate::chain_spec::missing(c.name, "p2sh").is_some();
            let cpk = pk.serialize();
            let b58check = |p: &[u8]| b58check_ck(c.ck(), p);
            let mut v = vec![row("p2pkh", b58check(&ver(p2pkh, &h160(&cpk))))];
            if uncompressed { v.push(row("p2pkh-uncompressed", b58check(&ver(p2pkh, &h160(&pk.serialize_uncompressed()))))) }
            if let Some(h) = hrp {
                let mut redeem = vec![0u8, 20]; redeem.extend_from_slice(&h160(&cpk));
                if !no_p2sh { v.push(row("p2sh-p2wpkh", b58check(&ver(p2sh, &h160(&redeem))))) }
                v.push(row("p2wpkh", segwit_v0(h, &h160(&cpk))));
            }
            if taproot {
                let secp = Secp256k1::verification_only();
                let spk = bitcoin::ScriptBuf::new_p2tr(&secp, pk.x_only_public_key().0, None);
                let h = Hrp::parse(hrp.unwrap_or("bc")).expect("static hrp");
                v.push(row("p2tr", bech32::segwit::encode(h, bech32::Fe32::P, &spk.as_bytes()[2..]).expect("32-byte program")));
            }
            v
        }
        Enc::Eth => vec![row("eth", crate::eth_address_from_pubkey(&pk.serialize_uncompressed()))],
        Enc::Tron => vec![row("tron", b58check(&ver(0x41, &keccak_addr20(pk))))],
        Enc::Xrp => vec![row("xrp", xrp_b58check(&ver(0x00, &h160(&pk.serialize()))))],
        Enc::Cosmos { hrp } => vec![row("cosmos", cosmos_address(hrp, &h160(&pk.serialize())))],
        Enc::Sol | Enc::Xlm | Enc::Algo | Enc::Ada | Enc::Ton | Enc::Ss58 { .. } | Enc::Xmr => vec![],
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
/// RFC 4648 base32, no padding (Stellar StrKey, Algorand addresses).
pub fn b32_encode(d: &[u8]) -> String {
    let (mut out, mut acc, mut bits) = (String::new(), 0u32, 0);
    for b in d { acc = (acc << 8) | *b as u32; bits += 8; while bits >= 5 { bits -= 5; out.push(B32[((acc >> bits) & 31) as usize] as char) } }
    if bits > 0 { out.push(B32[((acc << (5 - bits)) & 31) as usize] as char) }
    out
}
/// Inverse of b32_encode; rejects other characters and non-zero trailing bits.
pub fn b32_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    let (mut d, mut acc, mut bits) = (Vec::new(), 0u32, 0);
    for ch in s.bytes() {
        let v = B32.iter().position(|&x| x == ch).ok_or("bad base32")? as u32;
        acc = ((acc << 5) | v) & 0xffff; bits += 5;
        if bits >= 8 { bits -= 8; d.push((acc >> bits) as u8) }
    }
    if bits >= 5 || acc & ((1 << bits) - 1) != 0 { return Err("bad base32") }
    Ok(d)
}
/// Stellar StrKey: base32(version || payload || crc16-xmodem LE), no padding.
/// Versions: 6<<3 = 'G' account id, 18<<3 = 'S' seed.
pub fn strkey_encode(version: u8, payload: &[u8]) -> String {
    let mut d = vec![version]; d.extend_from_slice(payload);
    let c = crc16_xmodem(&d); d.extend_from_slice(&c.to_le_bytes());
    let out = b32_encode(&d);
    d.iter_mut().for_each(|b| *b = 0);
    out
}
/// Decode a StrKey; checks the alphabet, length, canonical trailing bits and the CRC.
pub fn strkey_decode(s: &str) -> Result<(u8, Vec<u8>), &'static str> {
    let d = b32_decode(s)?;
    if d.len() < 3 { return Err("bad length") }
    let (body, ck) = d.split_at(d.len() - 2);
    if crc16_xmodem(body).to_le_bytes() != ck { return Err("bad checksum") }
    Ok((body[0], body[1..].to_vec()))
}
/// Algorand address of a 32-byte ed25519 public key.
pub fn algo_address(pubkey: &[u8; 32]) -> String {
    use bitcoin::hashes::{sha512_256, Hash};
    let h = sha512_256::Hash::hash(pubkey).to_byte_array();
    let mut d = pubkey.to_vec(); d.extend_from_slice(&h[28..]);
    b32_encode(&d)
}
/// Algorand address -> 32-byte public key (checks length and the 4-byte checksum).
pub fn algo_decode(a: &str) -> Result<[u8; 32], &'static str> {
    if a.len() != 58 { return Err("bad length") }
    let d = b32_decode(a)?;
    let pk: [u8; 32] = d[..32].try_into().map_err(|_| "bad length")?;
    if algo_address(&pk) != a { return Err("bad checksum") }
    Ok(pk)
}
/// Algorand row: address plus `private_key` = base64(seed || pub), the 64-byte algosdk key.
#[cfg(all(feature = "ed25519", feature = "secrets"))]
pub fn algo_row(path: &str, seed: &[u8; 32]) -> Row {
    let pubk = ed25519_dalek::SigningKey::from_bytes(seed).verifying_key().to_bytes();
    let mut kp = seed.to_vec(); kp.extend_from_slice(&pubk);
    let secret = crate::b64::encode(&kp);
    kp.iter_mut().for_each(|b| *b = 0);
    Row { chain: "algo", kind: "algo", path: path.into(), address: algo_address(&pubk), secret_field: "private_key", secret }
}
/// Algorand 25-word mnemonic -> 32-byte key: 24 words of 11 bits (little-endian packing) + a
/// checksum word = first 11 bits of sha512/256(key). BIP39 English words, full words only.
#[cfg(feature = "algo")]
pub fn algo_mnemonic_key(m: &str) -> Result<zeroize::Zeroizing<[u8; 32]>, &'static str> {
    use bitcoin::hashes::{sha512_256, Hash};
    let l = bip39::Language::English;
    let ws: Vec<&str> = m.split_whitespace().collect();
    if ws.len() != 25 { return Err("bad length") }
    let ix: Vec<u32> = ws.iter().map(|w| l.find_word(&w.to_lowercase()).map(|i| i as u32).ok_or("bad word")).collect::<Result<_, _>>()?;
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(34));
    let (mut acc, mut bits) = (0u64, 0);
    for &i in &ix[..24] { acc |= (i as u64) << bits; bits += 11; while bits >= 8 { out.push(acc as u8); acc >>= 8; bits -= 8 } }
    if bits > 0 { out.push(acc as u8) }
    if out.len() != 33 || out[32] != 0 { return Err("bad checksum") }
    let key: [u8; 32] = out[..32].try_into().unwrap();
    let h = sha512_256::Hash::hash(&key).to_byte_array();
    if ((h[0] as u32) | ((h[1] as u32) << 8)) & 2047 != ix[24] { return Err("bad checksum") }
    Ok(zeroize::Zeroizing::new(key))
}
// ---- Cardano ----
const BECH: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
fn bech_polymod(v: &[u8]) -> u32 {
    let g = [0x3b6a57b2u32, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut c = 1u32;
    for &x in v { let b = c >> 25; c = ((c & 0x1ffffff) << 5) ^ x as u32; for (i, gi) in g.iter().enumerate() { if (b >> i) & 1 == 1 { c ^= gi } } }
    c
}
fn bech_hrp_exp(h: &str) -> Vec<u8> { let mut v: Vec<u8> = h.bytes().map(|b| b >> 5).collect(); v.push(0); v.extend(h.bytes().map(|b| b & 31)); v }
fn to5(d: &[u8]) -> Vec<u8> {
    let (mut acc, mut bits, mut out) = (0u32, 0, Vec::new());
    for &b in d { acc = (acc << 8) | b as u32; bits += 8; while bits >= 5 { bits -= 5; out.push(((acc >> bits) & 31) as u8) } }
    if bits > 0 { out.push(((acc << (5 - bits)) & 31) as u8) }
    out
}
/// Plain bech32 (BIP173 checksum) without the 90-char limit, as Cardano uses.
pub fn bech32_long(hrp: &str, data: &[u8]) -> String {
    let d = to5(data);
    let mut v = bech_hrp_exp(hrp); v.extend(&d); v.extend([0; 6]);
    let p = bech_polymod(&v) ^ 1;
    let mut s = format!("{hrp}1");
    for x in d.iter().copied().chain((0..6).map(|i| ((p >> (5 * (5 - i))) & 31) as u8)) { s.push(BECH[x as usize] as char) }
    s
}
/// Decode long bech32 -> (hrp, bytes). Lowercase only, checksum checked, no padding bits left set.
pub fn bech32_long_decode(s: &str) -> Result<(String, Vec<u8>), &'static str> {
    let p = s.rfind('1').ok_or("no separator")?;
    let (hrp, rest) = (&s[..p], &s[p + 1..]);
    if hrp.is_empty() || rest.len() < 6 || s.bytes().any(|b| b.is_ascii_uppercase()) { return Err("bad bech32") }
    let d: Vec<u8> = rest.bytes().map(|b| BECH.iter().position(|&x| x == b).map(|i| i as u8)).collect::<Option<_>>().ok_or("bad bech32")?;
    let mut v = bech_hrp_exp(hrp); v.extend(&d);
    if bech_polymod(&v) != 1 { return Err("bad checksum") }
    let d = &d[..d.len() - 6];
    let (mut acc, mut bits, mut out) = (0u32, 0, Vec::new());
    for &x in d { acc = (acc << 5) | x as u32; bits += 5; if bits >= 8 { bits -= 8; out.push((acc >> bits) as u8) } }
    if bits >= 5 || (acc & ((1 << bits) - 1)) != 0 { return Err("bad padding") }
    Ok((hrp.into(), out))
}
/// Cardano mainnet base address (header 0x01): payment and stake key hashes (blake2b-224).
pub fn ada_base_address(pay_pub: &[u8; 32], stake_pub: &[u8; 32]) -> String {
    let mut d = vec![0x01];
    d.extend(crate::blake2b::blake2b(28, &[0; 16], pay_pub)); d.extend(crate::blake2b::blake2b(28, &[0; 16], stake_pub));
    bech32_long("addr", &d)
}
/// Validate a Cardano mainnet Shelley address (addr1..., base/pointer/enterprise header, network 1).
pub fn ada_decode(a: &str) -> Result<Vec<u8>, &'static str> {
    let (h, d) = bech32_long_decode(a)?;
    if h != "addr" { return Err("wrong network") }
    if d.is_empty() || d[0] & 0x0f != 1 { return Err("wrong network") }
    let ok = match d[0] >> 4 { 0..=3 => d.len() == 57, 6 | 7 => d.len() == 29, 4 | 5 => d.len() > 29, _ => false };
    if !ok { return Err("bad length") }
    Ok(d)
}
/// Icarus master key (CIP-3): PBKDF2-HMAC-SHA512(password = passphrase, salt = BIP39 entropy, 4096, 96), clamped.
#[cfg(feature = "cardano")]
pub fn ada_icarus_master(m: &str, pw: &str) -> Result<zeroize::Zeroizing<[u8; 96]>, &'static str> {
    let mn = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, m).map_err(|_| "bad mnemonic")?;
    let ent = zeroize::Zeroizing::new(mn.to_entropy());
    let mut k = zeroize::Zeroizing::new([0u8; 96]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(pw.as_bytes(), &ent, 4096, &mut k[..]);
    k[0] &= 0xf8; k[31] &= 0x1f; k[31] |= 0x40;
    Ok(k)
}
#[cfg(feature = "cardano")]
fn ada_pub(kl: &[u8]) -> [u8; 32] {
    let s = curve25519_dalek::Scalar::from_bytes_mod_order(kl.try_into().unwrap());
    curve25519_dalek::EdwardsPoint::mul_base(&s).compress().to_bytes()
}
/// BIP32-Ed25519 (Khovratovich-Law, V2 as in Icarus) child of an extended key kL||kR||c.
#[cfg(feature = "cardano")]
fn ada_child(k: &[u8; 96], i: u32) -> zeroize::Zeroizing<[u8; 96]> {
    use bitcoin::hashes::{hmac::{Hmac, HmacEngine}, sha512, HashEngine, Hash};
    let hmac = |tag: u8, body: &[u8]| { let mut e = HmacEngine::<sha512::Hash>::new(&k[64..]); e.input(&[tag]); e.input(body); e.input(&i.to_le_bytes()); zeroize::Zeroizing::new(Hmac::<sha512::Hash>::from_engine(e).to_byte_array()) };
    let (z, cc) = if i >= 0x8000_0000 { (hmac(0, &k[..64]), hmac(1, &k[..64])) } else { let a = ada_pub(&k[..32]); (hmac(2, &a), hmac(3, &a)) };
    let mut o = zeroize::Zeroizing::new([0u8; 96]);
    let mut carry = 0u16; // kL' = kL + 8 * zL[..28]
    for j in 0..32 { let zl = if j < 28 { z[j] as u16 } else { 0 }; let zp = if j > 0 && j <= 28 { (z[j - 1] as u16) >> 5 } else { 0 };
        let v = k[j] as u16 + ((zl << 3) & 0xff) + zp + carry; o[j] = v as u8; carry = v >> 8; }
    carry = 0; // kR' = kR + zR mod 2^256
    for j in 0..32 { let v = k[32 + j] as u16 + z[32 + j] as u16 + carry; o[32 + j] = v as u8; carry = v >> 8; }
    o[64..].copy_from_slice(&cc[32..]);
    o
}
#[cfg(feature = "cardano")]
fn ada_path(m: &[u8; 96], p: &[u32]) -> zeroize::Zeroizing<[u8; 96]> {
    let mut k = zeroize::Zeroizing::new(*m);
    for &i in p { k = ada_child(&k, i) }
    k
}
/// Cardano rows i < count: base address of m/1852'/1815'/0'/0/i with stake key m/1852'/1815'/0'/2/0;
/// `private_key` = hex extended payment key kL||kR (128 hex chars).
#[cfg(all(feature = "cardano", feature = "secrets"))]
pub fn ada_rows(master: &[u8; 96], count: u32) -> Vec<Row> {
    const H: u32 = 0x8000_0000;
    let acct = ada_path(master, &[1852 | H, 1815 | H, H]);
    let stake = ada_path(&acct, &[2, 0]);
    let sp = ada_pub(&stake[..32]);
    (0..count).map(|i| {
        let k = ada_path(&acct, &[0, i]);
        Row { chain: "ada", kind: "ada-base", path: format!("m/1852'/1815'/0'/0/{i}"), address: ada_base_address(&ada_pub(&k[..32]), &sp), secret_field: "private_key", secret: crate::hex_enc(&k[..64]) }
    }).collect()
}
/// Wallet v4r2 code cell: representation hash and depth (tonsdk / ton-blockchain wallet-v4 R2).
const TON_V4R2_CODE_HASH: &str = "feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0";
const TON_V4R2_CODE_DEPTH: u16 = 7;
/// Standard cell hash: sha256(d1 d2 data(+completion bit) depth(refs) hash(refs)), ordinary, level 0.
fn ton_cell_hash(data: &[u8], bits: usize, refs: &[([u8; 32], u16)]) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash};
    let mut d = vec![refs.len() as u8, ((bits / 8) + bits.div_ceil(8)) as u8];
    let mut body = data[..bits.div_ceil(8)].to_vec();
    if bits % 8 != 0 { let last = body.len() - 1; let k = bits % 8; body[last] = (body[last] & (0xff << (8 - k))) | (0x80 >> k); }
    d.extend_from_slice(&body);
    for r in refs { d.extend_from_slice(&r.1.to_be_bytes()) }
    for r in refs { d.extend_from_slice(&r.0) }
    sha256::Hash::hash(&d).to_byte_array()
}
/// Account id of wallet v4r2 (subwallet 698983191, seqno 0, empty plugins) for a public key.
pub fn ton_v4r2_account(pubkey: &[u8; 32]) -> [u8; 32] {
    let mut data = vec![0u8; 4]; data.extend_from_slice(&698983191u32.to_be_bytes()); data.extend_from_slice(pubkey); data.push(0);
    let dh = ton_cell_hash(&data, 321, &[]);
    let code: [u8; 32] = crate::hex_dec(TON_V4R2_CODE_HASH).unwrap().try_into().unwrap();
    // StateInit: split_depth? 0, special? 0, code 1, data 1, library 0
    ton_cell_hash(&[0b0011_0000], 5, &[(code, TON_V4R2_CODE_DEPTH), (dh, 0)])
}
/// User-friendly TON address: base64url(tag || workchain || account || crc16), tag 0x51 (non-bounceable) or 0x11.
pub fn ton_address(account: &[u8; 32], bounceable: bool) -> String {
    let mut d = vec![if bounceable { 0x11 } else { 0x51 }, 0]; d.extend_from_slice(account);
    let c = crc16_xmodem(&d); d.extend_from_slice(&c.to_be_bytes());
    crate::b64::encode(&d).replace('+', "-").replace('/', "_")
}
/// Parse a user-friendly (EQ/UQ, url or std alphabet) or raw "0:hex" mainnet workchain-0 address -> account id.
pub fn ton_decode(a: &str) -> Result<[u8; 32], &'static str> {
    if let Some(h) = a.strip_prefix("0:") { return crate::hex_dec(h).and_then(|b| b.try_into().ok()).ok_or("bad raw address") }
    if a.len() != 48 { return Err("bad length") }
    let d = crate::b64::decode(&a.replace('-', "+").replace('_', "/")).ok_or("bad base64")?;
    if d.len() != 36 { return Err("bad length") }
    if d[0] != 0x11 && d[0] != 0x51 { return Err("wrong network") }
    if d[1] != 0 { return Err("unsupported workchain") }
    if crc16_xmodem(&d[..34]).to_be_bytes() != d[34..] { return Err("bad checksum") }
    Ok(d[2..34].try_into().unwrap())
}
/// TON 24-word mnemonic (no password) -> ed25519 seed: entropy = HMAC-SHA512(mnemonic, ""),
/// must pass PBKDF2(entropy, "TON seed version", 390)[0] == 0; seed = PBKDF2(entropy, "TON default seed", 100000)[..32].
#[cfg(feature = "ton")]
fn ton_basic_seed(ent: &[u8]) -> bool {
    let mut chk = zeroize::Zeroizing::new([0u8; 64]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(ent, b"TON seed version", 390, &mut chk[..]);
    chk[0] == 0
}
/// Cheap shape check (no 100k-round PBKDF2): 24 BIP39-list words, passes the TON seed-version
/// check and is NOT a valid BIP39 mnemonic (those stay "mnemonic").
#[cfg(feature = "ton")]
pub fn is_ton_mnemonic(m: &str) -> bool {
    use bitcoin::hashes::{hmac::{Hmac, HmacEngine}, sha512, Hash};
    let ws: Vec<String> = m.split_whitespace().map(|w| w.to_lowercase()).collect();
    if ws.len() != 24 || ws.iter().any(|w| bip39::Language::English.find_word(w).is_none()) { return false }
    let norm = zeroize::Zeroizing::new(ws.join(" "));
    if bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &norm).is_ok() { return false }
    let e = HmacEngine::<sha512::Hash>::new(norm.as_bytes());
    ton_basic_seed(&zeroize::Zeroizing::new(Hmac::<sha512::Hash>::from_engine(e).to_byte_array())[..])
}
#[cfg(feature = "ton")]
pub fn ton_mnemonic_key(m: &str) -> Result<zeroize::Zeroizing<[u8; 32]>, &'static str> {
    use bitcoin::hashes::{hmac::{Hmac, HmacEngine}, sha512, HashEngine, Hash};
    let ws: Vec<String> = m.split_whitespace().map(|w| w.to_lowercase()).collect();
    if ws.len() != 24 { return Err("bad length") }
    if ws.iter().any(|w| bip39::Language::English.find_word(w).is_none()) { return Err("bad word") }
    let norm = zeroize::Zeroizing::new(ws.join(" "));
    let mut e = HmacEngine::<sha512::Hash>::new(norm.as_bytes()); e.input(b"");
    let ent = zeroize::Zeroizing::new(Hmac::<sha512::Hash>::from_engine(e).to_byte_array());
    if !ton_basic_seed(&ent[..]) { return Err("not a TON mnemonic") }
    let mut out = zeroize::Zeroizing::new([0u8; 64]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(&ent[..], b"TON default seed", 100000, &mut out[..]);
    let mut k = zeroize::Zeroizing::new([0u8; 32]); k.copy_from_slice(&out[..32]);
    Ok(k)
}
/// TON row: wallet v4r2 non-bounceable address; `private_key` = hex ed25519 seed.
#[cfg(all(feature = "ed25519", feature = "secrets"))]
pub fn ton_row(path: &str, seed: &[u8; 32]) -> Row {
    let pubk = ed25519_dalek::SigningKey::from_bytes(seed).verifying_key().to_bytes();
    Row { chain: "ton", kind: "ton-v4r2", path: path.into(), address: ton_address(&ton_v4r2_account(&pubk), false), secret_field: "private_key", secret: crate::hex_enc(seed) }
}
/// SS58 address (1-byte prefix < 64): base58(prefix || pub || blake2b-512("SS58PRE" || prefix || pub)[..2]).
pub fn ss58_address(prefix: u8, pubkey: &[u8; 32]) -> String {
    let mut d = vec![prefix]; d.extend_from_slice(pubkey);
    let mut pre = b"SS58PRE".to_vec(); pre.extend_from_slice(&d);
    d.extend_from_slice(&crate::blake2b::blake2b(64, &[0; 16], &pre)[..2]);
    bitcoin::base58::encode(&d)
}
/// SS58 address -> public key; checks prefix, length and checksum.
pub fn ss58_decode(prefix: u8, a: &str) -> Result<[u8; 32], &'static str> {
    let d = bitcoin::base58::decode(a).map_err(|_| "bad base58")?;
    if d.len() != 35 { return Err("bad length") }
    if d[0] != prefix { return Err("wrong network") }
    let pk: [u8; 32] = d[1..33].try_into().unwrap();
    if ss58_address(prefix, &pk) != a { return Err("bad checksum") }
    Ok(pk)
}
/// Substrate mini-secret from a BIP39 mnemonic: PBKDF2-HMAC-SHA512(entropy, "mnemonic" || pw, 2048)[..32].
#[cfg(feature = "sr25519")]
pub fn substrate_mini_secret(m: &str, pw: &str) -> Result<zeroize::Zeroizing<[u8; 32]>, &'static str> {
    let mn = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, m).map_err(|_| "bad mnemonic")?;
    let ent = zeroize::Zeroizing::new(mn.to_entropy());
    let mut out = zeroize::Zeroizing::new([0u8; 64]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(&ent, format!("mnemonic{pw}").as_bytes(), 2048, &mut out[..]);
    let mut k = zeroize::Zeroizing::new([0u8; 32]); k.copy_from_slice(&out[..32]);
    Ok(k)
}
/// Polkadot row from a mini-secret: sr25519 (Ed25519 expansion, as substrate), SS58 address;
/// `private_key` = 0x-hex mini-secret (the "raw seed" polkadot.js / subkey import).
#[cfg(all(feature = "sr25519", feature = "secrets"))]
pub fn ss58_row(c: &Chain, path: &str, mini: &[u8; 32]) -> Row {
    let Enc::Ss58 { prefix } = c.enc else { panic!("not ss58") };
    let pk = schnorrkel::MiniSecretKey::from_bytes(mini).expect("32 bytes").expand_to_public(schnorrkel::ExpansionMode::Ed25519).to_bytes();
    Row { chain: c.name, kind: "sr25519", path: path.into(), address: ss58_address(prefix, &pk), secret_field: "private_key", secret: format!("0x{}", crate::hex_enc(mini)) }
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
            // Chain spec without a WIF byte: the address is shown, the key is not encoded (never guessed).
            Enc::Utxo { .. } if crate::chain_spec::missing(c.name, "wif").is_some() => ("missing", "spec_missing_wif".to_string()),
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
        Enc::Sol | Enc::Xlm | Enc::Algo | Enc::Ada | Enc::Ton | Enc::Ss58 { .. } => return vec![],
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
    let (no_pkh, no_sh) = (crate::chain_spec::missing(c.name, "p2pkh").is_some(), crate::chain_spec::missing(c.name, "p2sh").is_some());
    if no_pkh && !matches!(s, [0x00 | 0x51, ..]) { return None }
    if no_sh && matches!(s, [0xa9, 0x14, .., 0x87]) { return None }
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
            // BIP-173: all-lowercase or all-uppercase; mixed case is invalid.
            if a.bytes().any(|b| b.is_ascii_uppercase()) && a.bytes().any(|b| b.is_ascii_lowercase()) { return None }
            let (hh, v, p) = bech32::segwit::decode(a).ok()?;
            if !hh.as_str().eq_ignore_ascii_case(h) { return None }
            let v = v.to_u8();
            if !matches!((v, p.len()), (0, 20) | (0, 32) | (1, 32)) { return None }
            let mut s = vec![if v == 0 { 0 } else { 0x50 + v }, p.len() as u8]; s.extend(p); return Some(s);
        }
    }
    let b = decode_check_ck(c.ck(), a).ok()?;
    if b.len() != 21 { return None }
    let h = &b[1..];
    let (no_pkh, no_sh) = (crate::chain_spec::missing(c.name, "p2pkh").is_some(), crate::chain_spec::missing(c.name, "p2sh").is_some());
    if b[0] == p2pkh && !no_pkh { let mut s = vec![0x76, 0xa9, 0x14]; s.extend(h); s.extend([0x88, 0xac]); Some(s) }
    else if b[0] == p2sh && !no_sh { let mut s = vec![0xa9, 0x14]; s.extend(h); s.push(0x87); Some(s) }
    else { None }
}

#[cfg(test)]
mod pub_kat {
    use super::*;
    // Public key of private key 1 = generator G (textbook value); no secret involved.
    #[test] fn bech32_case() {
        let c = chain("btc").unwrap();
        let lo = address_to_script(c, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
        assert_eq!(address_to_script(c, "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"), Some(lo));
        assert_eq!(address_to_script(c, "bc1qW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), None);
        let l = chain("ltc").unwrap();
        assert!(address_to_script(l, "LTC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KGMN4N9").is_some());
        assert!(address_to_script(l, "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9").is_some());
    }
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
        ("bcc", "8Rm8H7Fo9KCXs7hYfL74Z7K9TC5XnPGnWq", "Nbf4UZcLZSm5GYw9k4dPEQp7LSLEt6b8mVx2hKapgs2v7q8URJUQ"),
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
/// Fee-warning limits used by verify-tx (`high_fee` above `fee` base units, `high_fee_rate`
/// above `rate` base units per vbyte). Default is the Bitcoin-tuned 1,000,000 / 500.
/// Per-coin rows: limit = 20 x the measured median fee rate x a 1,000 vB sweep (rate limit =
/// 20 x median), never below the default. Measured 2026-10-24 from recent mainnet blocks;
/// coins whose measured median keeps them under the default (DASH, MONA, TRC, PPC, ...) use it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FeeWarn { pub fee: u64, pub rate: u64, pub basis: &'static str }
impl FeeWarn {
    /// Absolute fee limit for a tx of `vsize` vbytes. `fee` was sized for 1000 vB, so the limit
    /// is `fee` per started 1000 vB (a 147-input sweep of ~22 kvB gets 22 x `fee`).
    pub fn fee_for(&self, vsize: u64) -> u64 { self.fee.saturating_mul(vsize.div_ceil(1000).max(1)) }
    /// Hard cap on a requested fee rate (builders refuse above it): 4 x the warning rate, never
    /// below 2000 per byte. Derived from the measured medians in FEE_WARN.
    pub fn rate_cap(&self) -> u64 { self.rate.saturating_mul(4).max(2000) }
}
pub const FEE_WARN_DEFAULT: FeeWarn = FeeWarn { fee: 1_000_000, rate: 500, basis: "default (Bitcoin-tuned)" };
pub const FEE_WARN: &[(&str, FeeWarn)] = &[
    ("dgb", FeeWarn { fee: 10_000_000, rate: 10_000, basis: "median 512 sat/vB over 60 txs, blocks 24444779-24445073 (blockbook.dgb.zelcore.io)" }),
    ("rvn", FeeWarn { fee: 20_000_000, rate: 20_000, basis: "median 1004 sat/vB over 60 txs, blocks 4596227-4596275 (blockbook.rvn.zelcore.io)" }),
    ("qtum", FeeWarn { fee: 14_000_000, rate: 14_000, basis: "median 700 sat/vB over 100 txs, blocks 6253698-6255768 (qtum.info recent-txs)" }),
    ("xpm", FeeWarn { fee: 2_000_000_000, rate: 2_000_000, basis: "median 100312 sat/B over 30 txs (exact size, raw rebuilt and sha256d-checked), blocks 7064002-7064118 (chainz.cryptoid.info)" }),
    ("vtc", FeeWarn { fee: 2_000_000, rate: 2_000, basis: "median 101 sat/vB over 60 txs, blocks 2703728-2703858 (blockbook.vtc.zelcore.io)" }),
    ("doge", FeeWarn { fee: 1_200_000_000, rate: 1_200_000, basis: "median 60463 sat/B over 100 txs (sha256d-checked), blocks 6429664-6429671 (blockbook.doge.zelcore.io); policy min 1000 sat/B is far below" }),
    ("ftc", FeeWarn { fee: 40_000_000, rate: 40_000, basis: "median 2000 sat/vB over 100 txs (21 segwit), blocks 6407004-6408299 (blockbook.feathercoin.com)" }),
    ("mona", FeeWarn { fee: 2_000_000, rate: 2_000, basis: "bimodal: median 2.54 sat/vB, p75/p90 100 sat/vB (Monacoin Core DEFAULT_TRANSACTION_MINFEE) over 100 txs, exact vsize, txid-checked, blocks 4142748-4143093 (mona.insight.monaco-ex.org); limit = 20 x the 100 mode" }),
    ("aur", FeeWarn { fee: 2_000_000, rate: 2_000, basis: "median 102.8 sat/B over 30 txs (exact size, raw rebuilt and sha256d-checked), blocks 5913204-5913347 (chainz.cryptoid.info)" }),
];
pub fn fee_warn(name: &str) -> FeeWarn { FEE_WARN.iter().find(|(n, _)| *n == name).map(|(_, f)| *f).unwrap_or(FEE_WARN_DEFAULT) }

#[cfg(test)]
mod grs_p2tr {
    use super::*;
    /// BIP341 wallet vector scriptPubKey[0] (Groestlcoin ships bip341_wallet_vectors.json
    /// byte-identical to Bitcoin's). grs1p string from an independent BIP350 reference
    /// encoder (Python, checked against the vector's bc1p address).
    #[test]
    fn grs_p2tr_bip341_vector() {
        let pk = PublicKey::from_slice(&<Vec<u8> as bitcoin::hex::FromHex>::from_hex("02d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d").unwrap()).unwrap();
        let p2tr = |n: &str| pub_rows(chain(n).unwrap(), "", &pk, false).into_iter().find(|r| r.kind == "p2tr").unwrap().address;
        assert_eq!(p2tr("btc"), "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5");
        assert_eq!(p2tr("grs"), "grs1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dpsm7geds");
    }
}

fn js(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() { match c { '"' => o.push_str("\\\""), '\\' => o.push_str("\\\\"), c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)), c => o.push(c) } }
    o.push('"'); o
}
/// One chain as a JSON object: name, ticker, title, SLIP-44 coin type, curve, address encoding
/// (with its version bytes / hrp), signer kind, whether unsigned-sweep builds it (`buildable` = `Chain::tx_format().1`), verified, source.
/// Public data only (no keys). Used by the `chain-table` tool, wasm `chainTable` and the C ABI.
pub fn chain_json(c: &Chain) -> String {
    let curve = match c.enc { Enc::Sol | Enc::Xlm | Enc::Algo | Enc::Ton => "ed25519", Enc::Ada => "ed25519-bip32", Enc::Ss58 { .. } => "sr25519", Enc::Xmr => "ed25519-monero", _ => "secp256k1" };
    let (enc, extra) = match c.enc {
        Enc::Utxo { p2pkh, p2sh, hrp, wif, taproot } => ("utxo", format!(",\"p2pkh\":{p2pkh},\"p2sh\":{p2sh},\"wif\":{wif},\"hrp\":{},\"taproot\":{taproot}", hrp.map_or("null".into(), js))),
        Enc::Cosmos { hrp } => ("cosmos", format!(",\"hrp\":{}", js(hrp))),
        Enc::Ss58 { prefix } => ("ss58", format!(",\"ss58_prefix\":{prefix}")),
        e => (match e { Enc::Eth => "eth", Enc::Tron => "tron", Enc::Xrp => "xrp", Enc::Sol => "sol", Enc::Algo => "algo", Enc::Xlm => "xlm", Enc::Ada => "ada", Enc::Ton => "ton", _ => "xmr" }, String::new()),
    };
    let sign = match c.sign { Sign::Standard => "standard".to_string(), Sign::ForkId(f) => format!("forkid:{f}"), Sign::PosTime => "pos_time".into(), Sign::Unknown => if matches!(c.enc, Enc::Utxo { .. }) { "none".into() } else { "account_family".into() }, Sign::Sha256Single => "sha256_single".into() };

    let coin = c.slip44().map_or("null".into(), |n| n.to_string());
    let (_, buildable) = c.tx_format();
    format!("{{\"name\":{},\"ticker\":{},\"title\":{},\"coin_type\":{coin},\"curve\":\"{curve}\",\"encoding\":\"{enc}\"{extra},\"native_seed\":{},\"sign\":\"{sign}\",\"buildable\":{buildable},\"default_count\":{},\"verified\":{},\"source\":{}}}",
        js(c.name), js(c.ticker), js(c.title), c.enc.native_seed(), c.default_count, c.verified, js(c.source))
}
/// The whole registry as a JSON array (see `chain_json`).
pub fn table_json() -> String { format!("[{}]", CHAINS.iter().map(chain_json).collect::<Vec<_>>().join(",")) }

#[cfg(test)]
mod table_tests {
    #[test]
    fn table_is_json_and_complete() {
        let t = super::table_json();
        let v: Vec<&str> = t.matches("\"name\":").collect();
        assert_eq!(v.len(), super::CHAINS.len());
        let btc = super::chain_json(super::chain("btc").unwrap());
        assert!(btc.starts_with("{\"name\":\"btc\",\"ticker\":\"BTC\",\"title\":\"Bitcoin\",\"coin_type\":0,\"curve\":\"secp256k1\",\"encoding\":\"utxo\",\"p2pkh\":0,\"p2sh\":5,\"wif\":128,\"hrp\":\"bc\",\"taproot\":true"), "{btc}");
        assert!(super::chain_json(super::chain("bch").unwrap()).contains("\"sign\":\"forkid:0\""));
        assert!(super::chain_json(super::chain("atom").unwrap()).contains("\"hrp\":\"cosmos\""));
                assert!(super::chain_json(super::chain("ton").unwrap()).contains("\\\"TON default seed\\\""));
        // buildable == sweep rule; forkid/pos true; eth/wdc false; no-SLIP44 -> null coin_type
        assert!(super::chain_json(super::chain("bch").unwrap()).contains("\"buildable\":true"));
        assert!(super::chain_json(super::chain("nvc").unwrap()).contains("\"buildable\":true"));
        assert!(super::chain_json(super::chain("eth").unwrap()).contains("\"buildable\":false"));
        assert!(super::chain_json(super::chain("wdc").unwrap()).contains("\"buildable\":false"));
        assert!(super::chain_json(super::chain("wdc").unwrap()).contains("\"coin_type\":null"));
        assert!(super::chain_json(super::chain("anc").unwrap()).contains("\"coin_type\":null"));
        assert_eq!(super::chain("btc").unwrap().slip44(), Some(0));
    }
}
