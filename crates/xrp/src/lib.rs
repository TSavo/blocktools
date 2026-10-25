//! XRP Ledger: family seeds (secp256k1 "s..." and ed25519 "sEd..."), classic r-addresses,
//! X-addresses (XLS-5d), and Payment binary encode/decode/sign. Secrets stay in Zeroizing buffers.
use bitcoin::hashes::{ripemd160, sha256, Hash};
use secp256k1::{PublicKey, Secp256k1, SecretKey, Message, Scalar};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

pub const ALPHABET: &[u8] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

pub fn sha512half(b: &[u8]) -> [u8; 32] { let h = Sha512::digest(b); let mut o = [0u8; 32]; o.copy_from_slice(&h[..32]); o }
fn dsha(b: &[u8]) -> [u8; 32] { sha256::Hash::hash(&sha256::Hash::hash(b).to_byte_array()).to_byte_array() }

pub fn b58_encode(data: &[u8]) -> String {
    let zeros = data.iter().take_while(|&&b| b == 0).count();
    let mut n: Vec<u8> = vec![];
    for &b in data { let mut c = b as u32; for d in n.iter_mut() { c += (*d as u32) << 8; *d = (c % 58) as u8; c /= 58; } while c > 0 { n.push((c % 58) as u8); c /= 58; } }
    let mut s: String = std::iter::repeat(ALPHABET[0] as char).take(zeros).collect();
    s.extend(n.iter().rev().map(|&d| ALPHABET[d as usize] as char)); s
}
pub fn b58_decode(s: &str) -> Option<Vec<u8>> {
    let mut n: Vec<u8> = vec![];
    for ch in s.bytes() { let mut c = ALPHABET.iter().position(|&a| a == ch)? as u32; for d in n.iter_mut() { c += (*d as u32) * 58; *d = c as u8; c >>= 8; } while c > 0 { n.push(c as u8); c >>= 8; } }
    let zeros = s.bytes().take_while(|&b| b == ALPHABET[0]).count();
    let mut o = vec![0u8; zeros]; o.extend(n.iter().rev()); Some(o)
}
pub fn check_encode(p: &[u8]) -> String { let mut d = p.to_vec(); d.extend_from_slice(&dsha(p)[..4]); b58_encode(&d) }
pub fn check_decode(s: &str) -> Option<Vec<u8>> {
    let d = b58_decode(s)?; if d.len() < 5 { return None; }
    let (p, c) = d.split_at(d.len() - 4); (dsha(p)[..4] == *c).then(|| p.to_vec())
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Algo { Secp256k1, Ed25519 }

/// Decode a family seed. "sEd..." (prefix 01 E1 4B) is ed25519; "s..." (prefix 21) is secp256k1.
pub fn decode_seed(s: &str) -> Result<(Algo, Zeroizing<[u8; 16]>), &'static str> {
    let d = Zeroizing::new(check_decode(s.trim()).ok_or("xrp_seed_bad_checksum")?);
    let mut e = Zeroizing::new([0u8; 16]);
    match d.len() {
        19 if d[..3] == [0x01, 0xe1, 0x4b] => { e.copy_from_slice(&d[3..]); Ok((Algo::Ed25519, e)) }
        17 if d[0] == 0x21 => { e.copy_from_slice(&d[1..]); Ok((Algo::Secp256k1, e)) }
        _ => Err("xrp_not_a_family_seed"),
    }
}
pub fn is_seed_shape(s: &str) -> bool { s.starts_with('s') && decode_seed(s).is_ok() }

/// A signing key. `public` is the 33-byte XRPL public key (ED-prefixed for ed25519).
pub struct Key { pub algo: Algo, secret: Zeroizing<[u8; 32]>, pub public: [u8; 33] }

fn secp_scalar(input: &[u8]) -> SecretKey {
    for i in 0u32.. { let mut b = input.to_vec(); b.extend_from_slice(&i.to_be_bytes());
        if let Ok(k) = SecretKey::from_slice(&sha512half(&b)) { return k; } }
    unreachable!()
}

/// Account key 0 of a family seed (the rippled/xrpl.js default).
pub fn key_from_seed(algo: Algo, entropy: &[u8; 16]) -> Key {
    match algo {
        Algo::Ed25519 => {
            let sk = Zeroizing::new(sha512half(entropy));
            let pk = ed25519_dalek::SigningKey::from_bytes(&sk).verifying_key().to_bytes();
            let mut p = [0xedu8; 33]; p[1..].copy_from_slice(&pk);
            Key { algo, secret: sk, public: p }
        }
        Algo::Secp256k1 => {
            let s = Secp256k1::new();
            let root = secp_scalar(entropy);
            let root_pub = PublicKey::from_secret_key(&s, &root).serialize();
            let mut b = root_pub.to_vec(); b.extend_from_slice(&0u32.to_be_bytes());
            let tweak = secp_scalar(&b);
            let k = root.add_tweak(&Scalar::from(tweak)).expect("valid");
            Key { algo, public: PublicKey::from_secret_key(&s, &k).serialize(), secret: Zeroizing::new(k.secret_bytes()) }
        }
    }
}
/// A raw secp256k1 private key (for example from a BIP39/BIP44 m/44'/144'/0'/0/i derivation).
pub fn key_from_secp_secret(sk: &[u8; 32]) -> Result<Key, &'static str> {
    let k = SecretKey::from_slice(sk).map_err(|_| "bad_secret")?;
    Ok(Key { algo: Algo::Secp256k1, public: PublicKey::from_secret_key(&Secp256k1::new(), &k).serialize(), secret: Zeroizing::new(*sk) })
}

pub fn account_id(public: &[u8; 33]) -> [u8; 20] { ripemd160::Hash::hash(&sha256::Hash::hash(public).to_byte_array()).to_byte_array() }
pub fn classic(id: &[u8; 20]) -> String { let mut p = vec![0u8]; p.extend_from_slice(id); check_encode(&p) }
impl Key { pub fn address(&self) -> String { classic(&account_id(&self.public)) } }

pub fn decode_classic(a: &str) -> Option<[u8; 20]> {
    let p = check_decode(a)?; (p.len() == 21 && p[0] == 0 && a.starts_with('r')).then(|| p[1..].try_into().unwrap())
}
/// X-address (XLS-5d): prefix 0544 mainnet / 0493 testnet, id, tag flag, u32 LE tag, 4 reserved zero bytes.
pub fn x_address(id: &[u8; 20], tag: Option<u32>, test: bool) -> String {
    let mut p = if test { vec![0x04, 0x93] } else { vec![0x05, 0x44] };
    p.extend_from_slice(id); p.push(tag.is_some() as u8); p.extend_from_slice(&tag.unwrap_or(0).to_le_bytes()); p.extend_from_slice(&[0; 4]);
    check_encode(&p)
}
/// Returns (account id, tag, is_testnet).
pub fn decode_x(a: &str) -> Option<([u8; 20], Option<u32>, bool)> {
    let p = check_decode(a)?;
    if p.len() != 31 || p[27..] != [0; 4] || p[22] > 1 { return None; }
    let test = match &p[..2] { [0x05, 0x44] => false, [0x04, 0x93] => true, _ => return None };
    let tag = u32::from_le_bytes(p[23..27].try_into().unwrap());
    if p[22] == 0 && tag != 0 { return None; }
    Some((p[2..22].try_into().unwrap(), (p[22] == 1).then_some(tag), test))
}
/// Any destination form -> (account id, tag from X-address if any).
pub fn parse_destination(a: &str) -> Result<([u8; 20], Option<u32>), &'static str> {
    if let Some(id) = decode_classic(a) { return Ok((id, None)); }
    match decode_x(a) { Some((id, t, false)) => Ok((id, t)), Some((_, _, true)) => Err("xrp_testnet_x_address"), None => Err("xrp_bad_address") }
}

// ---------- binary codec (the Payment subset) ----------
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Memo { pub memo_type: Option<Vec<u8>>, pub memo_data: Option<Vec<u8>>, pub memo_format: Option<Vec<u8>> }
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Payment {
    pub account: [u8; 20], pub destination: [u8; 20], pub amount_drops: u64, pub fee_drops: u64, pub sequence: u32,
    pub flags: u32, pub source_tag: Option<u32>, pub destination_tag: Option<u32>, pub last_ledger_sequence: Option<u32>,
    pub signing_pub_key: Vec<u8>, pub txn_signature: Option<Vec<u8>>, pub memos: Vec<Memo>,
}
fn header(o: &mut Vec<u8>, t: u8, f: u8) {
    match (t < 16, f < 16) { (true, true) => o.push(t << 4 | f), (true, false) => { o.push(t << 4); o.push(f) }
        (false, true) => { o.push(f); o.push(t) } (false, false) => { o.extend_from_slice(&[0, t, f]) } }
}
fn vl(o: &mut Vec<u8>, b: &[u8]) {
    let n = b.len();
    if n <= 192 { o.push(n as u8) } else if n <= 12480 { let m = n - 193; o.push(193 + (m >> 8) as u8); o.push(m as u8) }
    else { let m = n - 12481; o.extend_from_slice(&[241 + (m >> 16) as u8, (m >> 8) as u8, m as u8]) }
    o.extend_from_slice(b)
}
fn drops(d: u64) -> [u8; 8] { (d | 0x4000_0000_0000_0000).to_be_bytes() }

impl Payment {
    /// Canonical serialization; `signing` omits TxnSignature (the signing form).
    pub fn encode(&self, signing: bool) -> Vec<u8> {
        let mut o = vec![];
        header(&mut o, 1, 2); o.extend_from_slice(&0u16.to_be_bytes());           // TransactionType = Payment
        header(&mut o, 2, 2); o.extend_from_slice(&self.flags.to_be_bytes());
        if let Some(t) = self.source_tag { header(&mut o, 2, 3); o.extend_from_slice(&t.to_be_bytes()) }
        header(&mut o, 2, 4); o.extend_from_slice(&self.sequence.to_be_bytes());
        if let Some(t) = self.destination_tag { header(&mut o, 2, 14); o.extend_from_slice(&t.to_be_bytes()) }
        if let Some(t) = self.last_ledger_sequence { header(&mut o, 2, 27); o.extend_from_slice(&t.to_be_bytes()) }
        header(&mut o, 6, 1); o.extend_from_slice(&drops(self.amount_drops));
        header(&mut o, 6, 8); o.extend_from_slice(&drops(self.fee_drops));
        header(&mut o, 7, 3); vl(&mut o, &self.signing_pub_key);
        if !signing { if let Some(s) = &self.txn_signature { header(&mut o, 7, 4); vl(&mut o, s) } }
        header(&mut o, 8, 1); vl(&mut o, &self.account);
        header(&mut o, 8, 3); vl(&mut o, &self.destination);
        if !self.memos.is_empty() {
            header(&mut o, 15, 9);
            for m in &self.memos {
                header(&mut o, 14, 10);
                for (f, v) in [(12, &m.memo_type), (13, &m.memo_data), (14, &m.memo_format)] { if let Some(v) = v { header(&mut o, 7, f); vl(&mut o, v) } }
                o.push(0xe1);
            }
            o.push(0xf1);
        }
        o
    }
    pub fn signing_bytes(&self) -> Vec<u8> { let mut b = vec![0x53, 0x54, 0x58, 0x00]; b.extend(self.encode(true)); b }
    pub fn hash(&self) -> [u8; 32] { let mut b = vec![0x54, 0x58, 0x4e, 0x00]; b.extend(self.encode(false)); sha512half(&b) }

    /// Decode a Payment blob. Any field outside this subset is refused (never silently dropped).
    pub fn decode(b: &[u8]) -> Result<Payment, String> {
        let mut r = Rd { b, i: 0 }; let mut p = Payment::default(); let mut seen_type = false; let (mut have_acct, mut have_dest, mut have_amt) = (false, false, false);
        while r.i < b.len() {
            let (t, f) = r.header()?;
            match (t, f) {
                (1, 2) => { if r.u16()? != 0 { return Err("not_a_payment".into()) } seen_type = true }
                (2, 2) => p.flags = r.u32()?, (2, 3) => p.source_tag = Some(r.u32()?), (2, 4) => p.sequence = r.u32()?,
                (2, 14) => p.destination_tag = Some(r.u32()?), (2, 27) => p.last_ledger_sequence = Some(r.u32()?),
                (6, 1) => { p.amount_drops = r.xrp()?; have_amt = true } (6, 8) => p.fee_drops = r.xrp()?,
                (7, 3) => p.signing_pub_key = r.vl()?, (7, 4) => p.txn_signature = Some(r.vl()?),
                (8, 1) => { p.account = r.acct()?; have_acct = true } (8, 3) => { p.destination = r.acct()?; have_dest = true }
                (15, 9) => loop {
                    let (t, f) = r.header()?;
                    if (t, f) == (15, 1) { break }
                    if (t, f) != (14, 10) { return Err(format!("unsupported_field:{t}/{f}")) }
                    let mut m = Memo::default();
                    loop { let (t, f) = r.header()?; match (t, f) { (14, 1) => break,
                        (7, 12) => m.memo_type = Some(r.vl()?), (7, 13) => m.memo_data = Some(r.vl()?), (7, 14) => m.memo_format = Some(r.vl()?),
                        _ => return Err(format!("unsupported_field:{t}/{f}")) } }
                    p.memos.push(m);
                },
                _ => return Err(format!("unsupported_field:{t}/{f}")),
            }
        }
        if !(seen_type && have_acct && have_dest && have_amt) { return Err("incomplete_payment".into()) }
        Ok(p)
    }
}
struct Rd<'a> { b: &'a [u8], i: usize }
impl Rd<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], String> { let s = self.b.get(self.i..self.i + n).ok_or("truncated")?; self.i += n; Ok(s) }
    fn u8(&mut self) -> Result<u8, String> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16, String> { Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap())) }
    fn u32(&mut self) -> Result<u32, String> { Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap())) }
    fn header(&mut self) -> Result<(u8, u8), String> {
        let h = self.u8()?; let (mut t, mut f) = (h >> 4, h & 15);
        if t == 0 { t = self.u8()? } if f == 0 { f = self.u8()? } Ok((t, f))
    }
    fn vl(&mut self) -> Result<Vec<u8>, String> {
        let a = self.u8()? as usize;
        let n = if a <= 192 { a } else if a <= 240 { 193 + ((a - 193) << 8) + self.u8()? as usize } else if a <= 254 { let x = self.u8()? as usize; let y = self.u8()? as usize; 12481 + ((a - 241) << 16) + (x << 8) + y } else { return Err("bad_vl".into()) };
        Ok(self.take(n)?.to_vec())
    }
    fn xrp(&mut self) -> Result<u64, String> {
        let v = u64::from_be_bytes(self.take(8)?.try_into().unwrap());
        if v & 0x8000_0000_0000_0000 != 0 { return Err("issued_currency_amount_unsupported".into()) }
        if v & 0x4000_0000_0000_0000 == 0 { return Err("negative_amount".into()) }
        Ok(v & 0x3fff_ffff_ffff_ffff)
    }
    fn acct(&mut self) -> Result<[u8; 20], String> { self.vl()?.try_into().map_err(|_| "bad_account".into()) }
}

/// Sign: secp256k1 = ECDSA (RFC6979, low-S, DER) over sha512half(STX\0 || tx); ed25519 = over STX\0 || tx.
pub fn sign(p: &mut Payment, k: &Key) -> Result<(), &'static str> {
    if p.signing_pub_key != k.public { p.signing_pub_key = k.public.to_vec() }
    if p.account != account_id(&k.public) { return Err("key_does_not_match_account") }
    let m = p.signing_bytes();
    p.txn_signature = Some(sign_bytes(k, &m));
    Ok(())
}
/// secp256k1 signs sha512half(msg) (ripple-keypairs convention). ed25519 always signs msg itself.
pub fn sign_bytes(k: &Key, msg: &[u8]) -> Vec<u8> {
    match k.algo {
        Algo::Secp256k1 => { let s = Secp256k1::new(); let sk = SecretKey::from_slice(&k.secret[..]).unwrap();
            let mut sig = s.sign_ecdsa(&Message::from_digest(sha512half(msg)), &sk); sig.normalize_s(); sig.serialize_der().to_vec() }
        Algo::Ed25519 => { use ed25519_dalek::Signer; ed25519_dalek::SigningKey::from_bytes(&k.secret).sign(msg).to_bytes().to_vec() }
    }
}
pub fn verify(p: &Payment) -> bool {
    let (Some(sig), pk) = (&p.txn_signature, &p.signing_pub_key) else { return false };
    let m = p.signing_bytes();
    if pk.len() == 33 && pk[0] == 0xed {
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(pk[1..].try_into().unwrap()) else { return false };
        let Ok(s) = ed25519_dalek::Signature::from_slice(sig) else { return false };
        vk.verify_strict(&m, &s).is_ok()
    } else {
        let (Ok(pk), Ok(s)) = (PublicKey::from_slice(pk), secp256k1::ecdsa::Signature::from_der(sig)) else { return false };
        Secp256k1::verification_only().verify_ecdsa(&Message::from_digest(sha512half(&m)), &s, &pk).is_ok()
    }
}
