//! fd regression (issue #7 follow-up): a real Dogecoin chainstate has ~7,400 tables, above the
//! default `ulimit -n 1024`. Builds a dir with 200 level-1 tables + 3 overlapping level-0 tables
//! and runs the tool under `ulimit -n 64`: every coin, newest version wins, no EMFILE.
use blocktools_utxo::{compress_amount, write_varint};
use std::path::Path;

fn crc32c(d: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in d { c ^= u32::from(b); for _ in 0..8 { c = if c & 1 != 0 { 0x82f6_3b78 ^ (c >> 1) } else { c >> 1 } } }
    !c
}
fn mask(c: u32) -> u32 { c.rotate_right(15).wrapping_add(0xa282_ead8) }
fn uv(mut n: u64, o: &mut Vec<u8>) { while n >= 0x80 { o.push((n as u8) | 0x80); n >>= 7 } o.push(n as u8) }
fn lv(b: &[u8], o: &mut Vec<u8>) { uv(b.len() as u64, o); o.extend(b) }
fn record(payload: &[u8]) -> Vec<u8> {
    let mut t = vec![1u8]; t.extend(payload);
    let mut o = mask(crc32c(&t)).to_le_bytes().to_vec(); o.extend((payload.len() as u16).to_le_bytes()); o.extend(t); o
}
fn ikey(k: &[u8], seq: u64) -> Vec<u8> { let mut v = k.to_vec(); v.extend(((seq << 8) | 1).to_le_bytes()); v }
fn block(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut b = Vec::new();
    for (k, v) in entries { uv(0, &mut b); uv(k.len() as u64, &mut b); uv(v.len() as u64, &mut b); b.extend(k); b.extend(v) }
    b.extend(0u32.to_le_bytes()); b.extend(1u32.to_le_bytes()); b
}
fn put_block(f: &mut Vec<u8>, b: Vec<u8>) -> (u64, u64) {
    let (off, n) = (f.len() as u64, b.len() as u64);
    let mut t = b; t.push(0); let c = mask(crc32c(&t)); f.extend(t); f.extend(c.to_le_bytes()); (off, n)
}
/// One table file of sorted internal-key entries; returns its size.
fn table(path: &Path, entries: &[(Vec<u8>, Vec<u8>)]) -> u64 {
    let mut f = Vec::new();
    let (o, s) = put_block(&mut f, block(entries));
    let mut h = Vec::new(); uv(o, &mut h); uv(s, &mut h);
    let (mo, ms) = put_block(&mut f, block(&[]));
    let (io, is) = put_block(&mut f, block(&[(entries.last().unwrap().0.clone(), h)]));
    let mut ft = Vec::new(); uv(mo, &mut ft); uv(ms, &mut ft); uv(io, &mut ft); uv(is, &mut ft);
    ft.resize(40, 0); ft.extend(0xdb47_7524_8b80_fb57u64.to_le_bytes()); f.extend(ft);
    std::fs::write(path, &f).unwrap(); f.len() as u64
}
const XOR: [u8; 8] = [0x5a, 0x11, 0x00, 0xff, 0x23, 0x42, 0x99, 0x01];
fn x(mut v: Vec<u8>) -> Vec<u8> { for (i, b) in v.iter_mut().enumerate() { *b ^= XOR[i % 8] } v }
fn coin(value: u64, h: u8) -> Vec<u8> { let mut o = Vec::new(); write_varint(2, &mut o); write_varint(compress_amount(value), &mut o); o.push(0); o.extend([h; 20]); x(o) }
fn ckey(i: u32) -> Vec<u8> { let mut k = vec![b'C']; k.extend([0u8; 28]); k.extend(i.to_be_bytes()); write_varint(0, &mut k); k }

#[test]
fn more_tables_than_fd_limit() {
    let d = std::env::temp_dir().join(format!("bt-cs-many-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d); std::fs::create_dir_all(&d).unwrap();
    let mut edits = Vec::new();
    let mut add = |lv: u64, n: u64, size: u64, lo: &[u8], hi: &[u8]| { let mut e = vec![7u8]; uv(lv, &mut e); uv(n, &mut e); uv(size, &mut e); lv_(lo, &mut e); lv_(hi, &mut e); edits.push(e) };
    fn lv_(b: &[u8], o: &mut Vec<u8>) { lv(b, o) }
    // level 1: tables 10..210, coin i (value 1000+i) in table 10+i, written in reverse file order
    for i in (0..200u32).rev() {
        let e = vec![(ikey(&ckey(i), 100 + u64::from(i)), coin(1000 + u64::from(i), 1))];
        let n = 10 + u64::from(i); let sz = table(&d.join(format!("{n:06}.ldb")), &e);
        add(1, n, sz, &e[0].0, &e[0].0);
    }
    // level 0: three overlapping newer tables overwrite coins 0, 100, 199 with value 7
    for (j, i) in [0u32, 100, 199].into_iter().enumerate() {
        let e = vec![(ikey(&ckey(i), 1000 + j as u64), coin(7, 2))];
        let n = 300 + j as u64; let sz = table(&d.join(format!("{n:06}.ldb")), &e);
        add(0, n, sz, &e[0].0, &e[0].0);
    }
    let mut m = vec![1u8]; lv(b"leveldb.BytewiseComparator", &mut m); m.extend([2, 3, 3]); uv(400, &mut m); m.extend([4]); uv(2000, &mut m);
    let mut man = record(&m); for e in &edits { man.extend(record(e)) }
    std::fs::write(d.join("MANIFEST-000002"), man).unwrap();
    std::fs::write(d.join("CURRENT"), "MANIFEST-000002\n").unwrap();
    let mut b = 3000u64.to_le_bytes().to_vec(); b.extend(2u32.to_le_bytes());
    let mut ov = vec![8u8]; ov.extend(XOR);
    b.push(1); lv(b"\x0e\x00obfuscate_key", &mut b); lv(&ov, &mut b);
    b.push(1); lv(b"B", &mut b); lv(&x(vec![0xab; 32]), &mut b);
    std::fs::write(d.join("000003.log"), record(&b)).unwrap();

    let out = std::process::Command::new("sh").arg("-c").arg("ulimit -n 64 && exec \"$0\" --chain btc --census \"$1\"")
        .arg(env!("CARGO_BIN_EXE_chainstate-dump")).arg(&d).output().unwrap();
    let so = String::from_utf8_lossy(&out.stdout); let se = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "rc {:?}\nstdout {so}\nstderr {se}", out.status.code());
    let total: u64 = (0..200u64).map(|i| if [0, 100, 199].contains(&i) { 7 } else { 1000 + i }).sum();
    assert!(so.contains("\"coins\":200"), "{so}");
    assert!(so.contains(&format!("\"total\":\"{total}\"")), "{so}");
    let _ = std::fs::remove_dir_all(&d);
}
