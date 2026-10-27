//! Measurement fixture: a Core-25-format dumptxoutset of N random coins (p2wpkh/p2pkh/p2tr/p2sh mix),
//! plus `queries` lines of never-funded scripts. Random programs, no keys.
//!   cargo run --release -p blocktools-utxo --example synth-dump -- N OUT.dat [QUERIES OUT.txt]
use blocktools_utxo::*;
use std::io::Write;
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let n: u64 = a[1].parse().unwrap();
    let mut r = 0x9e37_79b9_7f4a_7c15u64;
    let mut rnd = move || { r ^= r << 13; r ^= r >> 7; r ^= r << 17; r };
    let prog = |rnd: &mut dyn FnMut() -> u64, len: usize| { let mut p = vec![0u8; len]; for c in p.chunks_mut(8) { c.copy_from_slice(&rnd().to_le_bytes()[..c.len()]) } p };
    let mut f = std::io::BufWriter::new(std::fs::File::create(&a[2]).unwrap());
    f.write_all(&[0u8; 32]).unwrap(); f.write_all(&n.to_le_bytes()).unwrap();
    for i in 0..n {
        let s = match i % 4 { 0 | 1 => [&[0x00, 0x14][..], &prog(&mut rnd, 20)].concat(), 2 => [&[0x76, 0xa9, 0x14][..], &prog(&mut rnd, 20), &[0x88, 0xac]].concat(), _ => [&[0x51, 0x20][..], &prog(&mut rnd, 32)].concat() };
        let c = Coin { txid: { let mut t = [0u8; 32]; t[..8].copy_from_slice(&i.to_le_bytes()); t }, vout: 0, height: 1, coinbase: false, value: 1 + rnd() % 100_000_000, script: s };
        let d = write_dump(25, [0; 4], [0; 32], std::slice::from_ref(&c));
        f.write_all(&d[40..]).unwrap();
    }
    if let (Some(q), Some(out)) = (a.get(3), a.get(4)) {
        let mut o = std::io::BufWriter::new(std::fs::File::create(out).unwrap());
        for _ in 0..q.parse::<u64>().unwrap() { let p = prog(&mut rnd, 20); writeln!(o, "0014{}", p.iter().map(|b| format!("{b:02x}")).collect::<String>()).unwrap() }
    }
}
