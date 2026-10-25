//! bitcoinj wallet protobufs (MultiBit Classic 0.5+ `.wallet`, bitcoinj apps) and MultiBit HD
//! `mbhd.wallet.aes`. Formats as read from bitcoinj `wallet.proto` and MultiBit HD source,
//! confirmed on the btcrecover public test wallets (see crates/secrets/tests/bitcoinj.rs):
//! * Wallet: field 1 network id, 3 Key (repeated), 5 encryption type (2 = scrypt+AES),
//!   6 ScryptParameters {1 salt, 2 n=16384, 3 r=8, 4 p=1}.
//! * Key: 1 type (1 ORIGINAL, 2 ENCRYPTED_SCRYPT_AES, 3 DETERMINISTIC_MNEMONIC, 4 DETERMINISTIC_KEY),
//!   2 secret bytes, 3 public key, 6 EncryptedData {1 iv, 2 ciphertext}, 8 seed, 9 encrypted seed.
//! * Password bytes: UTF-16BE of the password (bitcoinj KeyCrypterScrypt); key = scrypt(32);
//!   AES-256-CBC, PKCS7.
//! * MBHD outer layer: scrypt(UTF-16BE pw, salt 3551038075a3b0c5, 16384, 8, 1) and AES-256-CBC
//!   with the fixed IV a344391f538311b329548616c489723e over the whole file.
//! Every decrypted key is checked against its stored public key, and an HD seed against the
//! stored root key, so a wrong password or misread never yields a key.
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey};
use zeroize::Zeroizing;

pub const MAX_FILE: usize = 16 << 20;
const MBHD_SALT: [u8; 8] = [0x35, 0x51, 0x03, 0x80, 0x75, 0xa3, 0xb0, 0xc5];
const MBHD_IV: [u8; 16] = [0xa3, 0x44, 0x39, 0x1f, 0x53, 0x83, 0x11, 0xb3, 0x29, 0x54, 0x86, 0x16, 0xc4, 0x89, 0x72, 0x3e];

pub enum Secret {
    /// WIF (mainnet, compression as stored)
    Wif(Zeroizing<String>),
    /// BIP32 master xprv of an HD wallet (MultiBit HD account is m/0')
    Master(Zeroizing<String>),
}

enum V<'a> { I(u64), B(&'a [u8]) }
fn varint(b: &[u8], p: &mut usize) -> Option<u64> {
    let mut r = 0u64;
    for s in (0..64).step_by(7) { let c = *b.get(*p)?; *p += 1; r |= ((c & 0x7f) as u64) << s; if c < 0x80 { return Some(r) } }
    None
}
fn fields(b: &[u8]) -> Option<Vec<(u64, V<'_>)>> {
    let (mut p, mut o) = (0, Vec::new());
    while p < b.len() {
        let k = varint(b, &mut p)?;
        let v = match k & 7 {
            0 => V::I(varint(b, &mut p)?),
            2 => { let n = varint(b, &mut p)? as usize; let e = p.checked_add(n).filter(|e| *e <= b.len())?; let s = &b[p..e]; p = e; V::B(s) }
            1 => { p += 8; if p > b.len() { return None } V::I(0) }
            5 => { p += 4; if p > b.len() { return None } V::I(0) }
            _ => return None,
        };
        o.push((k >> 3, v));
    }
    Some(o)
}
fn bytes<'a>(f: &[(u64, V<'a>)], n: u64) -> Option<&'a [u8]> { f.iter().find_map(|(k, v)| match v { V::B(b) if *k == n => Some(*b), _ => None }) }
fn int(f: &[(u64, V<'_>)], n: u64) -> Option<u64> { f.iter().find_map(|(k, v)| match v { V::I(i) if *k == n => Some(*i), _ => None }) }

fn utf16be(pw: &str) -> Zeroizing<Vec<u8>> { Zeroizing::new(pw.encode_utf16().flat_map(|c| c.to_be_bytes()).collect()) }
fn scrypt32(pw: &[u8], salt: &[u8], n: u64, r: u64, p: u64) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    if !n.is_power_of_two() || n < 2 || n > 1 << 20 || r == 0 || r > 32 || p == 0 || p > 16 { return Err("unsupported") }
    let params = scrypt::Params::new(n.trailing_zeros() as u8, r as u32, p as u32).map_err(|_| "unsupported")?;
    let mut k = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(pw, salt, &params, &mut k[..]).map_err(|_| "unsupported")?;
    Ok(k)
}
fn aes_cbc(key: &[u8; 32], iv: &[u8], ct: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if iv.len() != 16 || ct.is_empty() || ct.len() % 16 != 0 { return None }
    let mut buf = Zeroizing::new(ct.to_vec());
    let n = cbc::Decryptor::<aes::Aes256>::new(key.into(), iv.into()).decrypt_padded_mut::<Pkcs7>(&mut buf).ok()?.len();
    buf.truncate(n); Some(buf)
}

/// True if `data` is a cleartext bitcoinj protobuf (network id first).
pub fn is_bitcoinj(data: &[u8]) -> bool { data.len() > 14 && data[0] == 0x0a && data[2..].starts_with(b"org.bitcoin") }

/// Open a bitcoinj wallet, or a MultiBit HD `.wallet.aes`. Errors: "unsupported", "wrong_password",
/// "testnet" (non-mainnet network id), "no_keys".
pub fn open(data: &[u8], password: &str) -> Result<Vec<Secret>, &'static str> {
    if data.len() > MAX_FILE { return Err("unsupported") }
    if is_bitcoinj(data) { return wallet(data, password) }
    if data.len() < 32 || data.len() % 16 != 0 { return Err("unsupported") }
    let k = scrypt32(&utf16be(password), &MBHD_SALT, 16384, 8, 1)?;
    let pt = aes_cbc(&k, &MBHD_IV, data).filter(|p| is_bitcoinj(p)).ok_or("wrong_password")?;
    wallet(&pt, password)
}

fn wallet(data: &[u8], password: &str) -> Result<Vec<Secret>, &'static str> {
    let f = fields(data).ok_or("unsupported")?;
    if bytes(&f, 1) != Some(b"org.bitcoin.production") { return Err("testnet") }
    let enc = int(&f, 5).unwrap_or(1);
    let key = match (enc, bytes(&f, 6)) {
        (1, _) => None,
        (2, Some(sp)) => {
            let s = fields(sp).ok_or("unsupported")?;
            Some(scrypt32(&utf16be(password), bytes(&s, 1).ok_or("unsupported")?, int(&s, 2).unwrap_or(16384), int(&s, 3).unwrap_or(8), int(&s, 4).unwrap_or(1))?)
        }
        _ => return Err("unsupported"),
    };
    let dec = |kf: &[(u64, V<'_>)], enc_field: u64, clear_field: u64| -> Result<Option<Zeroizing<Vec<u8>>>, &'static str> {
        if let Some(e) = bytes(kf, enc_field) {
            let k = key.as_ref().ok_or("unsupported")?;
            let ef = fields(e).ok_or("unsupported")?;
            return aes_cbc(k, bytes(&ef, 1).ok_or("unsupported")?, bytes(&ef, 2).ok_or("unsupported")?).map(Some).ok_or("wrong_password")
        }
        Ok(bytes(kf, clear_field).map(|b| Zeroizing::new(b.to_vec())))
    };
    let secp = Secp256k1::new();
    let mut root: Option<&[u8]> = None;
    let mut out = Vec::new();
    let mut seeds = Vec::new();
    for (n, v) in &f {
        let (3, V::B(kb)) = (n, v) else { continue };
        let kf = fields(kb).ok_or("unsupported")?;
        match int(&kf, 1) {
            Some(1) | Some(2) => {
                let Some(sk) = dec(&kf, 6, 2)? else { continue };
                let pk = bytes(&kf, 3).ok_or("unsupported")?;
                let s = SecretKey::from_slice(&sk).map_err(|_| "wrong_password")?;
                let p = PublicKey::from_secret_key(&secp, &s);
                let compressed = match pk.len() { 33 => true, 65 => false, _ => return Err("unsupported") };
                let ok = if compressed { p.serialize()[..] == *pk } else { p.serialize_uncompressed()[..] == *pk };
                if !ok { return Err("wrong_password") }
                let w = bitcoin::PrivateKey { compressed, network: bitcoin::NetworkKind::Main, inner: s };
                out.push(Secret::Wif(Zeroizing::new(w.to_wif())));
            }
            Some(3) => { if let Some(sd) = dec(&kf, 9, 8)? { seeds.push(sd) } }
            Some(4) => {
                let d = bytes(&kf, 7).and_then(fields).ok_or("unsupported")?;
                if !d.iter().any(|(k, _)| *k == 2) && root.is_none() { root = bytes(&kf, 3) }
            }
            _ => {}
        }
    }
    for sd in seeds {
        let m = bitcoin::bip32::Xpriv::new_master(bitcoin::NetworkKind::Main, &sd).map_err(|_| "wrong_password")?;
        let rp = root.ok_or("unsupported")?;
        if m.private_key.public_key(&secp).serialize()[..] != *rp { return Err("wrong_password") }
        out.push(Secret::Master(Zeroizing::new(m.to_string())));
    }
    if out.is_empty() { Err("no_keys") } else { Ok(out) }
}
