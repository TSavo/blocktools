//! dat-read: Bitcoin Core wallet.dat (legacy Berkeley DB or SQLite descriptor
//! wallet) -> private keys on stdout.
//! stdin: line 1 = wallet passphrase (empty line if unencrypted), rest = wallet.dat bytes.
//! Output CONTAINS SECRETS ("wif" per legacy key; "xprv" per HD descriptor, at the
//! descriptor's account level; pipe it into `derive` for addresses).
//! Bounded: wallet <= 256 MiB, KDF iterations <= 10M, every parse offset checked.
mod bdb;
mod sqlite;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use bitcoin::bip32::{Xpriv, Xpub};
use bitcoin::hashes::{sha256d, sha512, Hash};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::collections::BTreeMap;
use std::io::{BufRead, Read};
use std::str::FromStr;
use zeroize::Zeroizing;

type Dec = cbc::Decryptor<aes::Aes256>;
const T: &str = "dat-read";

fn status(s: &str) { println!(r#"{{"tool":"{T}","status":"{s}"}}"#); }
fn die(s: &str) -> ! { status(s); std::process::exit(2) }

/// Bitcoin CompactSize-prefixed byte vector.
fn vec_at(b: &[u8], i: &mut usize) -> Option<Vec<u8>> {
    let first = *b.get(*i)?; *i += 1;
    let n = match first {
        0xfd => { let v = u16::from_le_bytes(b.get(*i..*i + 2)?.try_into().ok()?) as usize; *i += 2; v }
        0xfe => { let v = u32::from_le_bytes(b.get(*i..*i + 4)?.try_into().ok()?) as usize; *i += 4; v }
        0xff => return None,
        n => n as usize,
    };
    let v = b.get(*i..i.checked_add(n)?)?.to_vec(); *i += n; Some(v)
}
fn u32_at(b: &[u8], i: &mut usize) -> Option<u32> { let v = u32::from_le_bytes(b.get(*i..*i + 4)?.try_into().ok()?); *i += 4; Some(v) }

/// The 32-byte secret inside Core's DER CPrivKey (SEC1: 02 01 01 04 20 <key>).
fn der_secret(der: &[u8]) -> Option<[u8; 32]> {
    let p = der.windows(5).position(|w| w == [0x02, 0x01, 0x01, 0x04, 0x20])? + 5;
    der.get(p..p + 32)?.try_into().ok()
}

fn aes_dec(key: &[u8], iv: &[u8], ct: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let d = Dec::new_from_slices(key, iv).ok()?;
    d.decrypt_padded_vec_mut::<Pkcs7>(ct).ok().map(Zeroizing::new)
}

/// CCrypter::BytesToKeySHA512AES.
fn bytes_to_key(pw: &[u8], salt: &[u8], rounds: u32) -> Zeroizing<[u8; 64]> {
    let mut d = Zeroizing::new(Vec::with_capacity(pw.len() + salt.len()));
    d.extend_from_slice(pw); d.extend_from_slice(salt);
    let mut h = Zeroizing::new(sha512::Hash::hash(&d).to_byte_array());
    for _ in 1..rounds { *h = sha512::Hash::hash(&h[..]).to_byte_array(); }
    h
}

struct MKey { ct: Vec<u8>, salt: Vec<u8>, method: u32, rounds: u32 }

/// `steps`: derivation steps between the descriptor's key and the account level
/// (e.g. Core 0.21 writes `xpub/84'/0'/0'/0/*` on the *master* xpub).
enum Desc { Hd { kind: &'static str, path: String, steps: Vec<String>, branch: Option<u32>, xpub: Xpub }, Other }

/// Parse just enough of a Core descriptor: pkh/wpkh/sh(wpkh)/tr over [origin]xpub/branch/*.
fn parse_desc(s: &str) -> Desc {
    let s = s.split('#').next().unwrap_or("");
    let (kind, inner) = if let Some(r) = s.strip_prefix("sh(wpkh(") { ("p2sh-p2wpkh", r.strip_suffix("))")) }
        else if let Some(r) = s.strip_prefix("wpkh(") { ("p2wpkh", r.strip_suffix(')')) }
        else if let Some(r) = s.strip_prefix("pkh(") { ("p2pkh", r.strip_suffix(')')) }
        else if let Some(r) = s.strip_prefix("tr(") { ("p2tr", r.strip_suffix(')')) }
        else { return Desc::Other };
    let Some(inner) = inner else { return Desc::Other };
    let (origin, keyexp) = match inner.strip_prefix('[').and_then(|r| r.split_once(']')) { Some((o, k)) => (Some(o), k), None => (None, inner) };
    let mut parts = keyexp.split('/');
    let Ok(xpub) = Xpub::from_str(parts.next().unwrap_or("")) else { return Desc::Other };
    let rest: Vec<String> = parts.map(|x| x.replace('h', "'").replace('H', "'")).collect();
    if rest.len() > 10 { return Desc::Other; }
    let (steps, branch) = match rest.as_slice() {
        [pre @ .., b, w] if w == "*" => (pre.to_vec(), b.parse().ok()),
        all => (all.to_vec(), None),
    };
    let path = match origin {
        Some(o) => { let mut it = o.split('/'); it.next(); let p: Vec<String> = it.map(|x| x.replace('h', "'").replace('H', "'")).collect();
            if p.is_empty() { "m".into() } else { format!("m/{}", p.join("/")) } }
        None => "m".into(),
    };
    let path = if steps.is_empty() { path } else { format!("{path}/{}", steps.join("/")) };
    Desc::Hd { kind, path, steps, branch, xpub }
}

fn main() {
    let mut inp = std::io::stdin().lock().take(256 << 20);
    let mut pw = Zeroizing::new(Vec::new());
    if inp.read_until(b'\n', &mut pw).is_err() { die("bad_input"); }
    while matches!(pw.last(), Some(b'\n' | b'\r')) { pw.pop(); }
    let mut file = Vec::new();
    if inp.read_to_end(&mut file).is_err() { die("bad_input"); }
    let rows = sqlite::read(&file).or_else(|| bdb::read(&file)).unwrap_or_else(|| die("unsupported"));

    let secp = Secp256k1::new();
    let mut mkeys = Vec::new();
    let mut plain: Vec<(Vec<u8>, [u8; 32])> = Vec::new();   // (pubkey, secret)
    let mut crypt: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();    // (pubkey, ciphertext)
    let mut descs: Vec<String> = Vec::new();
    for (k, v) in &rows {
        let mut i = 0;
        let Some(ty) = vec_at(k, &mut i) else { continue };
        let (mut j, mut vi) = (i, 0usize);
        match ty.as_slice() {
            b"mkey" => {
                let (Some(ct), Some(salt), Some(method), Some(rounds)) = (vec_at(v, &mut vi), vec_at(v, &mut vi), u32_at(v, &mut vi), u32_at(v, &mut vi)) else { continue };
                mkeys.push(MKey { ct, salt, method, rounds });
            }
            b"key" | b"walletdescriptorkey" => {
                if ty == b"walletdescriptorkey" { j += 32; }
                let (Some(pk), Some(der)) = (vec_at(k, &mut j), vec_at(v, &mut vi)) else { continue };
                if let Some(s) = der_secret(&der) { plain.push((pk, s)); }
            }
            b"ckey" | b"walletdescriptorckey" => {
                if ty == b"walletdescriptorckey" { j += 32; }
                let (Some(pk), Some(ct)) = (vec_at(k, &mut j), vec_at(v, &mut vi)) else { continue };
                crypt.push((pk, ct));
            }
            b"walletdescriptor" => {
                if let Some(d) = vec_at(v, &mut vi) { if d.len() < 4096 { if let Ok(s) = String::from_utf8(d) { descs.push(s); } } }
            }
            _ => {}
        }
    }

    // Decrypt encrypted keys with the master key.
    let mut secrets: BTreeMap<Vec<u8>, Zeroizing<[u8; 32]>> = BTreeMap::new();
    for (pk, s) in plain { secrets.insert(pk, Zeroizing::new(s)); }
    if !crypt.is_empty() {
        let mk = mkeys.first().unwrap_or_else(|| die("bad_input"));
        if mk.method != 0 { die("unsupported"); }
        if mk.rounds == 0 || mk.rounds > 10_000_000 || mk.salt.len() != 8 { die("bad_input"); }
        let kiv = bytes_to_key(&pw, &mk.salt, mk.rounds);
        let master = aes_dec(&kiv[..32], &kiv[32..48], &mk.ct).filter(|m| m.len() == 32).unwrap_or_else(|| die("wrong_password"));
        let mut ok = 0;
        for (pk, ct) in &crypt {
            let iv = sha256d::Hash::hash(pk).to_byte_array();
            let Some(s) = aes_dec(&master, &iv[..16], ct).filter(|s| s.len() == 32) else { continue };
            let Ok(sk) = SecretKey::from_slice(&s) else { continue };
            let p = PublicKey::from_secret_key(&secp, &sk);
            if p.serialize().as_slice() == pk.as_slice() || p.serialize_uncompressed().as_slice() == pk.as_slice() {
                secrets.insert(pk.clone(), Zeroizing::new(sk.secret_bytes())); ok += 1;
            }
        }
        // Wrong passphrases almost always fail the padding check above; a key that
        // decrypts but does not match its public key also means wrong password.
        if ok == 0 { die("wrong_password"); }
    }

    // HD descriptors -> account-level xprv lines.
    let mut used = Vec::new();
    let mut n = 0u64;
    for d in &descs {
        if let Desc::Hd { kind, path, steps, branch, xpub } = parse_desc(d) {
            let pk = xpub.public_key.serialize().to_vec();
            let Some(s) = secrets.get(&pk) else { continue };
            let Ok(sk) = SecretKey::from_slice(&s[..]) else { continue };
            let x = Xpriv { network: bitcoin::NetworkKind::Main, depth: xpub.depth, parent_fingerprint: xpub.parent_fingerprint,
                            child_number: xpub.child_number, private_key: sk, chain_code: xpub.chain_code };
            let x = if steps.is_empty() { x } else {
                let Ok(dp) = bitcoin::bip32::DerivationPath::from_str(&format!("m/{}", steps.join("/"))) else { continue };
                let Ok(a) = x.derive_priv(&secp, &dp) else { continue }; a };
            let br = branch.map(|b| format!(r#","branch":{b}"#)).unwrap_or_default();
            println!(r#"{{"tool":"{T}","status":"ok","index":{n},"kind":"{kind}","path":"{path}"{br},"xprv":"{x}"}}"#);
            used.push(pk); n += 1;
        }
    }
    // Remaining bare keys (legacy wallets, imported keys).
    for (pk, s) in &secrets {
        if used.contains(pk) { continue; }
        let Ok(sk) = SecretKey::from_slice(&s[..]) else { continue };
        for r in kr_core::key_rows(&sk, pk.len() == 33) {
            println!(r#"{{"tool":"{T}","status":"ok","index":{n},"kind":"{}","address":"{}","wif":"{}"}}"#, r.kind, r.address, r.secret);
        }
        n += 1;
    }
    println!(r#"{{"tool":"{T}","status":"done","count":{n}}}"#);
}
