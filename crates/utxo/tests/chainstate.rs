//! chainstate reader: per-tx ('c') record decoding, log-only LevelDB dirs built here (obfuscation,
//! deletion shadowing, last-write-wins), and refusals (CRC flip, mid-flush 'H' key). Tables are
//! measured against real nodes in scripts/e2e.d/chainstate-real.sh.
use blocktools_utxo::chainstate::{per_tx, Chainstate, Opts};
use blocktools_utxo::{compress_amount, write_varint};
use std::path::Path;

fn crc32c(d: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in d { c ^= u32::from(b); for _ in 0..8 { c = if c & 1 != 0 { 0x82f6_3b78 ^ (c >> 1) } else { c >> 1 } } }
    !c
}
fn mask(c: u32) -> u32 { c.rotate_right(15).wrapping_add(0xa282_ead8) }
fn record(payload: &[u8]) -> Vec<u8> {
    let mut t = vec![1u8]; t.extend(payload);
    let mut o = mask(crc32c(&t)).to_le_bytes().to_vec(); o.extend((payload.len() as u16).to_le_bytes()); o.extend(t); o
}
fn lv(b: &[u8], o: &mut Vec<u8>) { let mut n = b.len(); while n >= 0x80 { o.push((n as u8) | 0x80); n >>= 7 } o.push(n as u8); o.extend(b) }
enum Op<'a> { Put(&'a [u8], Vec<u8>), Del(&'a [u8]) }
fn batch(seq: u64, ops: &[Op]) -> Vec<u8> {
    let mut o = seq.to_le_bytes().to_vec(); o.extend((ops.len() as u32).to_le_bytes());
    for op in ops { match op { Op::Put(k, v) => { o.push(1); lv(k, &mut o); lv(v, &mut o) } Op::Del(k) => { o.push(0); lv(k, &mut o) } } }
    o
}
fn mkdb(dir: &Path, batches: &[Vec<u8>]) {
    std::fs::create_dir_all(dir).unwrap();
    // MANIFEST: comparator name, log number 3, next file 4, last seq 0
    let mut e = vec![1u8]; lv(b"leveldb.BytewiseComparator", &mut e); e.extend([2, 3, 3, 4, 4, 0]);
    std::fs::write(dir.join("MANIFEST-000002"), record(&e)).unwrap();
    std::fs::write(dir.join("CURRENT"), "MANIFEST-000002\n").unwrap();
    std::fs::write(dir.join("000003.log"), batches.iter().flat_map(|b| record(b)).collect::<Vec<u8>>()).unwrap();
    std::fs::write(dir.join("000001.log"), record(&batch(1, &[Op::Put(b"Czzz-stale-log", vec![1])]))).unwrap(); // older than log number: ignored
}
const XOR: [u8; 8] = [0x5a, 0x11, 0x00, 0xff, 0x23, 0x42, 0x99, 0x01];
fn obf_val() -> Vec<u8> { let mut v = vec![8u8]; v.extend(XOR); v }
fn x(mut v: Vec<u8>) -> Vec<u8> { for (i, b) in v.iter_mut().enumerate() { *b ^= XOR[i % 8] } v }
fn coin(height: u64, cb: bool, value: u64, h160: [u8; 20]) -> Vec<u8> {
    let mut o = Vec::new(); write_varint(height * 2 + u64::from(cb), &mut o); write_varint(compress_amount(value), &mut o); o.push(0); o.extend(h160); o
}
fn ckey(txid: u8, vout: u64) -> Vec<u8> { let mut k = vec![b'C']; k.extend([txid; 32]); write_varint(vout, &mut k); k }
fn tmp(n: &str) -> std::path::PathBuf { let d = std::env::temp_dir().join(format!("bt-cs-{}-{n}", std::process::id())); let _ = std::fs::remove_dir_all(&d); d }
fn all(dir: &Path) -> std::io::Result<Vec<(u8, u32, u64, Vec<u8>)>> {
    let mut cs = Chainstate::open(dir)?; let mut v = Vec::new();
    while let Some(c) = cs.next_coin()? { v.push((c.txid[0], c.vout, c.value, c.script)) }
    Ok(v)
}

#[test]
fn per_tx_record_with_mask_bytes() {
    // vout0 spent, vout1 unspent, vouts 2..9: only vout 9 unspent (mask byte 0x80 for vouts 2..9)
    let mut v = Vec::new(); write_varint(1, &mut v); // version
    write_varint(8 * 1 + 4 + 1, &mut v); // 1 mask byte, vout1 unspent, coinbase
    v.push(0x80);
    for (val, h) in [(5_000_000_000u64, 0x11u8), (1234, 0x22)] { write_varint(compress_amount(val), &mut v); v.push(0); v.extend([h; 20]) }
    write_varint(77, &mut v);
    let c = per_tx([9; 32], &v).unwrap();
    assert_eq!(c.iter().map(|c| (c.vout, c.value, c.height, c.coinbase)).collect::<Vec<_>>(), vec![(1, 5_000_000_000, 77, true), (9, 1234, 77, true)]);
    assert_eq!(c[1].script, [&[0x76, 0xa9, 0x14][..], &[0x22; 20], &[0x88, 0xac]].concat());
    let mut t = v.clone(); t.push(0); assert!(per_tx([9; 32], &t).is_err(), "trailing byte refused");
    assert!(per_tx([9; 32], &v[..v.len() - 1]).is_err(), "truncated refused");
}

#[test]
fn log_only_db_obfuscated_last_write_wins_and_deletions() {
    let d = tmp("ok");
    mkdb(&d, &[
        batch(10, &[Op::Put(b"\x0e\x00obfuscate_key", obf_val()), Op::Put(&ckey(1, 0), x(coin(5, false, 100, [1; 20]))), Op::Put(&ckey(2, 300), x(coin(6, true, 200, [2; 20])))]),
        batch(13, &[Op::Del(&ckey(1, 0)), Op::Put(&ckey(3, 1), x(coin(7, false, 300, [3; 20]))), Op::Put(b"B", x(vec![0xab; 32]))]),
        batch(16, &[Op::Put(&ckey(3, 1), x(coin(7, false, 333, [3; 20])))]),
    ]);
    let got = all(&d).unwrap();
    assert_eq!(got.iter().map(|g| (g.0, g.1, g.2)).collect::<Vec<_>>(), vec![(2, 300, 200), (3, 1, 333)]);
    let mut cs = Chainstate::open(&d).unwrap(); while cs.next_coin().unwrap().is_some() {}
    assert!(cs.stats.obfuscated); assert_eq!(cs.stats.best_block.as_deref(), Some(&"ab".repeat(32)[..])); assert_eq!(cs.stats.total_value, 533);
    assert_eq!(cs.db().live.logs.len(), 1, "log older than the manifest's log number is not live");
}

#[test]
fn refusals() {
    let d = tmp("crc");
    mkdb(&d, &[batch(1, &[Op::Put(&ckey(1, 0), coin(5, false, 100, [1; 20]))]), batch(2, &[Op::Put(&ckey(2, 0), coin(5, false, 100, [1; 20]))])]);
    let p = d.join("000003.log"); let mut b = std::fs::read(&p).unwrap(); b[12] ^= 1; std::fs::write(&p, b).unwrap();
    assert!(all(&d).is_err(), "CRC flip in a non-final log record refused");
    let d = tmp("h");
    mkdb(&d, &[batch(1, &[Op::Put(b"H", vec![1]), Op::Put(&ckey(1, 0), coin(5, false, 100, [1; 20]))])]);
    assert!(all(&d).unwrap_err().to_string().contains("mid_flush"));
    let d = tmp("nocurrent"); std::fs::create_dir_all(&d).unwrap();
    assert!(Chainstate::open(&d).err().unwrap().to_string().contains("CURRENT"));
}

fn all_with(dir: &Path, o: Opts) -> std::io::Result<usize> {
    let mut cs = Chainstate::open_with(dir, o)?; let mut n = 0;
    while cs.next_coin()?.is_some() { n += 1 }
    Ok(n)
}

#[test]
fn discrimination_wrong_key_or_era_fails_loudly() {
    let d = tmp("disc");
    let k: Vec<Vec<u8>> = (0..50u8).map(|i| ckey(i, u64::from(i))).collect();
    let mut ops = vec![Op::Put(b"\x0e\x00obfuscate_key", obf_val())];
    for (i, kk) in k.iter().enumerate() { ops.push(Op::Put(kk, x(coin(100 + i as u64, i % 3 == 0, 1000 * i as u64 + 1, [i as u8; 20])))) }
    mkdb(&d, &[batch(1, &ops)]);
    assert_eq!(all_with(&d, Opts::default()).unwrap(), 50, "detected key and era");
    assert_eq!(all_with(&d, Opts { era: Some(b'C'), xor: None, hash_serialized: false }).unwrap(), 50);
    let e = all_with(&d, Opts { era: Some(b'c'), xor: None, hash_serialized: false }).unwrap_err().to_string();
    assert!(e.contains("era_mismatch"), "{e}");
    let e = all_with(&d, Opts { era: None, xor: Some(vec![0; 8]), hash_serialized: false }).unwrap_err().to_string();
    assert!(e.contains("wrong obfuscation key"), "no key applied to an obfuscated chainstate: {e}");
    let mut wrong = XOR.to_vec(); wrong[3] ^= 0x10;
    let e = all_with(&d, Opts { era: None, xor: Some(wrong), hash_serialized: false }).unwrap_err().to_string();
    assert!(e.contains("wrong obfuscation key"), "one wrong key byte: {e}");
    // mixed layouts in one directory
    let d = tmp("mixed");
    let mut v = Vec::new(); write_varint(1, &mut v); write_varint(2, &mut v); write_varint(compress_amount(5), &mut v); v.push(0); v.extend([7; 20]); write_varint(9, &mut v);
    let mut ck = vec![b'c']; ck.extend([0xee; 32]);
    mkdb(&d, &[batch(1, &[Op::Put(&ckey(1, 0), coin(5, false, 100, [1; 20])), Op::Put(&ck, v)])]);
    assert!(all_with(&d, Opts::default()).unwrap_err().to_string().contains("layout_mixed"));
}
