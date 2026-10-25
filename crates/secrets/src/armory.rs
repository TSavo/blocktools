//! Armory (PyBtcWallet, 1.35-era) `.wallet` reader. Layout (little-endian): "\xbaWALLET\0", version,
//! network magic, flags (bit0 encrypted, bit1 watching-only), unique id, created, 32+256 labels,
//! highest used index, KDF params (mem u64, iters u32, salt 32, hash256 checksum 4) in 256 bytes,
//! crypto params 256, root PyBtcAddress (237 bytes), 1024 unused, then typed entries.
//! KDF: Armory ROMix (SHA-512 lookup table of mem/64 hashes, mem/128 lookups, first 32 bytes), applied
//! `iters` times. Private keys: AES-256-CFB(key, per-address IV). Chained keys: priv_{i+1} =
//! priv_i * (hash256(pub65_i) XOR chaincode) mod n. Every returned key must reproduce the public key
//! stored for its entry, else `wrong_password` (or `corrupt`). Mainnet only.
use aes::cipher::{BlockEncrypt, KeyInit};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

pub const MAX_FILE: usize = 64 << 20;
const ADDR: usize = 237;
const ROOT: usize = 846;
const ENTRIES: usize = ROOT + ADDR + 1024;
const MAX_MEM: u64 = 256 << 20;

pub fn is_armory(d: &[u8]) -> bool { d.len() > ENTRIES && d.starts_with(b"\xbaWALLET\x00") }

fn h256(b: &[u8]) -> [u8; 32] { Sha256::digest(Sha256::digest(b)).into() }
fn u64le(b: &[u8]) -> u64 { u64::from_le_bytes(b[..8].try_into().unwrap()) }

/// One Armory ROMix iteration.
fn romix(pw: &[u8], salt: &[u8], mem: u64) -> Zeroizing<Vec<u8>> {
    let n = (mem / 64) as usize;
    let mut lut = Zeroizing::new(vec![0u8; n * 64]);
    let mut h = Sha512::new(); h.update(pw); h.update(salt);
    lut[..64].copy_from_slice(&h.finalize());
    for i in 1..n { let x = Sha512::digest(&lut[(i - 1) * 64..i * 64]); lut[i * 64..(i + 1) * 64].copy_from_slice(&x); }
    let mut x = Zeroizing::new(lut[(n - 1) * 64..].to_vec());
    let mut y = Zeroizing::new([0u8; 64]);
    for _ in 0..n / 2 {
        let j = u32::from_le_bytes(x[60..64].try_into().unwrap()) as usize % n;
        for k in 0..64 { y[k] = x[k] ^ lut[j * 64 + k]; }
        x.copy_from_slice(&Sha512::digest(&y[..]));
    }
    Zeroizing::new(x[..32].to_vec())
}

fn cfb_decrypt(key: &[u8], iv: &[u8], ct: &[u8]) -> Zeroizing<[u8; 32]> {
    let c = aes::Aes256::new_from_slice(key).unwrap();
    let mut out = Zeroizing::new([0u8; 32]);
    let mut fb = aes::Block::clone_from_slice(iv);
    for blk in 0..2 {
        c.encrypt_block(&mut fb);
        for k in 0..16 { out[blk * 16 + k] = ct[blk * 16 + k] ^ fb[k]; }
        fb = aes::Block::clone_from_slice(&ct[blk * 16..blk * 16 + 16]);
    }
    out
}

struct Addr<'a> { b: &'a [u8] }
impl Addr<'_> {
    fn flags(&self) -> u64 { u64le(&self.b[28..]) }
    fn chaincode(&self) -> &[u8] { &self.b[36..68] }
    fn index(&self) -> i64 { u64le(&self.b[72..]) as i64 }
    fn iv(&self) -> &[u8] { &self.b[88..104] }
    fn priv32(&self) -> &[u8] { &self.b[108..140] }
    fn pub65(&self) -> &[u8] { &self.b[144..209] }
    fn has_priv(&self) -> bool { self.flags() & 1 == 1 }
}

/// Returns (chain index, uncompressed WIF) for every stored address, sorted by index.
pub fn open(d: &[u8], password: &str) -> Result<Vec<(i64, Zeroizing<String>)>, &'static str> {
    if !is_armory(d) || d.len() > MAX_FILE { return Err("bad_input") }
    if d[12..16] != [0xf9, 0xbe, 0xb4, 0xd9] { return Err("unsupported_network") }
    let wflags = u64le(&d[16..]);
    if wflags & 2 != 0 { return Err("watching_only") }
    if wflags & 4 != 0 { return Err("unsupported_multisig") }
    let encrypted = wflags & 1 == 1;
    let root = Addr { b: &d[ROOT..ROOT + ADDR] };
    if !root.has_priv() { return Err("watching_only") }
    let key = if encrypted {
        let k = &d[334..378];
        if h256(k)[..4] != d[378..382] { return Err("corrupt") }
        let (mem, iters) = (u64le(k), u32::from_le_bytes(k[8..12].try_into().unwrap()));
        if mem < 128 || mem > MAX_MEM || mem % 64 != 0 || iters == 0 || iters > 100_000 { return Err("unsupported_kdf") }
        let mut m = Zeroizing::new(password.as_bytes().to_vec());
        for _ in 0..iters { m = romix(&m, &k[12..44], mem); }
        Some(m)
    } else { None };
    let secp = Secp256k1::new();
    let plain = |a: &Addr| -> Zeroizing<[u8; 32]> {
        match &key { Some(k) => cfb_decrypt(k, a.iv(), a.priv32()), None => Zeroizing::new(a.priv32().try_into().unwrap()) }
    };
    let rp = plain(&root);
    let mut sk = SecretKey::from_slice(&rp[..]).map_err(|_| if encrypted { "wrong_password" } else { "corrupt" })?;
    if PublicKey::from_secret_key(&secp, &sk).serialize_uncompressed()[..] != *root.pub65() { return Err(if encrypted { "wrong_password" } else { "corrupt" }) }
    // Collect stored KEYDATA entries.
    let mut ents: Vec<Addr> = vec![];
    let mut p = ENTRIES;
    while p < d.len() {
        let t = d[p]; p += 1;
        let len = |o: usize| -> Result<usize, &'static str> { d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as usize).ok_or("corrupt") };
        match t {
            0 => { let b = d.get(p + 20..p + 20 + ADDR).ok_or("corrupt")?; ents.push(Addr { b }); p += 20 + ADDR; }
            1 => p += 22 + len(p + 20)?,
            2 => p += 34 + len(p + 32)?,
            4 => p += 2 + len(p)?,
            _ => return Err("corrupt"),
        }
    }
    ents.sort_by_key(|a| a.index());
    let (mut pubk, mut cc) = (PublicKey::from_secret_key(&secp, &sk), root.chaincode().to_vec());
    let mut out = vec![]; let mut idx = -1i64;
    for a in ents.iter().filter(|a| a.index() >= 0) {
        while idx < a.index() {
            let mut m = h256(&pubk.serialize_uncompressed());
            for k in 0..32 { m[k] ^= cc[k]; }
            sk = sk.mul_tweak(&Scalar::from_be_bytes(m).map_err(|_| "corrupt")?).map_err(|_| "corrupt")?;
            pubk = PublicKey::from_secret_key(&secp, &sk); idx += 1;
            if idx == a.index() { cc = a.chaincode().to_vec(); }
        }
        if pubk.serialize_uncompressed()[..] != *a.pub65() { return Err("corrupt") }
        // An entry's own encrypted key, when present, must agree with the chained one.
        if a.has_priv() && plain(a)[..] != sk.secret_bytes()[..] { return Err("corrupt") }
        let w = bitcoin::PrivateKey { compressed: false, network: bitcoin::NetworkKind::Main, inner: sk };
        out.push((a.index(), Zeroizing::new(w.to_wif())));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    // btcrecover public test wallet (gurnec/btcrecover, scripts/fetch-fixtures.sh); skipped when absent.
    #[test] fn btcrecover_armory_fixture() {
        let Ok(d) = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/external/armory-wallet.wallet")) else { return };
        let k = super::open(&d, "btcr-test-password").unwrap();
        assert_eq!(k.len(), 100);
        assert_eq!(super::open(&d, "wrong").err(), Some("wrong_password"));
    }
}
