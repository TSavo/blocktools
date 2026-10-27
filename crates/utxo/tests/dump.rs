//! blocktools-utxo: Core's compressor vectors, both snapshot formats, refusals, bloom properties.
use blocktools_utxo::*;
fn coin(t: u8, vout: u32, value: u64, script: Vec<u8>) -> Coin { Coin { txid: [t; 32], vout, height: 7, coinbase: false, value, script } }
fn p2wpkh(b: u8) -> Vec<u8> { [&[0x00, 0x14][..], &[b; 20]].concat() }
fn p2pkh(b: u8) -> Vec<u8> { [&[0x76, 0xa9, 0x14][..], &[b; 20], &[0x88, 0xac]].concat() }

#[test]
fn core_compress_amount_vectors() {
    // src/test/compress_tests.cpp
    for (n, c) in [(0u64, 0u64), (1, 1), (1_000_000, 7), (100_000_000, 9), (5_000_000_000, 50), (2_100_000_000_000_000, 0x1406f40)] {
        assert_eq!(compress_amount(n), c, "{n}"); assert_eq!(decompress_amount(c), n, "{c}");
    }
    for n in (0..200_000u64).chain([12345, 50_012_345, u32::MAX as u64]) { assert_eq!(decompress_amount(compress_amount(n)), n) }
}
#[test]
fn varint_round_trip_and_core_bytes() {
    // serialize.h VARINT table
    for (n, b) in [(0u64, &[0x00][..]), (127, &[0x7f]), (128, &[0x80, 0x00]), (255, &[0x80, 0x7f]), (256, &[0x81, 0x00]),
                   (16383, &[0xfe, 0x7f]), (16384, &[0xff, 0x00]), (16511, &[0xff, 0x7f]), (65535, &[0x82, 0xfe, 0x7f])] {
        let mut v = Vec::new(); write_varint(n, &mut v); assert_eq!(v, b, "{n}");
    }
    for n in [0u64, 1, 127, 128, 255, 16511, 16512, 1 << 40, u64::MAX] {
        let mut v = Vec::new(); write_varint(n, &mut v); assert_eq!(read_varint(&mut v.as_slice()).unwrap(), n);
    }
}
fn sample() -> Vec<Coin> {
    vec![coin(1, 0, 1000, p2wpkh(1)), coin(1, 1, 2500, p2pkh(2)), coin(2, 0, 7, p2wpkh(1)), coin(3, 5, 99, vec![0x6a, 0x01, 0x02])]
}
#[test]
fn both_formats_ingest_and_sum() {
    for (fmt, magic, net) in [(25, [0; 4], None), (28, [0xf9, 0xbe, 0xb4, 0xd9], Some("btc")), (28, [0xfa, 0xbf, 0xb5, 0xda], Some("btc-regtest"))] {
        let d = write_dump(fmt, magic, [9; 32], &sample());
        let s = UtxoSet::ingest(d.as_slice(), 12).unwrap();
        assert_eq!((s.coins, s.scripts(), s.header.network()), (4, 3, net));
        assert_eq!(s.query_script(&p2wpkh(1)), Answer::Funded { value: 1007, outputs: 2 });
        assert_eq!(s.query_script(&p2pkh(2)), Answer::Funded { value: 2500, outputs: 1 });
        assert_eq!(s.query_script(&[0x6a, 0x01, 0x02]), Answer::Funded { value: 99, outputs: 1 });
        assert!(!matches!(s.query_script(&p2wpkh(3)), Answer::Funded { .. }));
        assert!(!matches!(s.query_script(&p2pkh(1)), Answer::Funded { .. }), "same 20 bytes, other template");
    }
}
#[test]
fn truncated_trailing_and_bad_version_refused() {
    let d = write_dump(25, [0; 4], [9; 32], &sample());
    for cut in [10, 40, d.len() - 1] { assert!(UtxoSet::ingest(&d[..cut], 12).is_err(), "cut {cut}") }
    let mut t = d.clone(); t.push(0); assert!(UtxoSet::ingest(t.as_slice(), 12).is_err());
    let mut v = write_dump(28, [0; 4], [9; 32], &sample()); v[5] = 3; assert!(UtxoSet::ingest(v.as_slice(), 12).is_err());
}
#[test]
fn compressed_p2pk_decodes_to_the_full_script() {
    let x = [0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98];
    let enc = [&[0x02][..], &x].concat();
    assert_eq!(read_script(&mut enc.as_slice()).unwrap(), [&[0x21, 0x02][..], &x, &[0xac]].concat());
    let enc = [&[0x04][..], &x].concat(); // uncompressed P2PK of G (even y)
    let s = read_script(&mut enc.as_slice()).unwrap();
    assert_eq!((s.len(), s[0], s[1], &s[2..34], s[66]), (67, 0x41, 0x04, &x[..], 0xac));
}
/// Property: the bloom filter never says no to a member, its false-positive rate on non-members is near
/// the design rate, and the exact set turns every false positive into "not funded".
#[test]
fn bloom_no_false_negatives_fpr_near_design_exact_set_eliminates() {
    let mut r = 0x1234_5678_9abc_def0u64;
    let mut rnd = || { r ^= r << 13; r ^= r >> 7; r ^= r << 17; r };
    let mut prog = |rnd: &mut dyn FnMut() -> u64| { let mut p = [0u8; 20]; for c in p.chunks_mut(8) { c.copy_from_slice(&rnd().to_le_bytes()[..c.len()]) } [&[0x00, 0x14][..], &p].concat() };
    let coins: Vec<Coin> = (0..50_000u32).map(|i| { let mut c = coin(0, i, 1, prog(&mut rnd)); c.txid[..4].copy_from_slice(&i.to_le_bytes()); c }).collect();
    let s = UtxoSet::ingest(write_dump(25, [0; 4], [0; 32], &coins).as_slice(), 12).unwrap();
    for c in &coins { assert!(matches!(s.query_script(&c.script), Answer::Funded { .. })) }
    let (mut fp, n) = (0u32, 200_000u32);
    for _ in 0..n {
        let q = prog(&mut rnd);
        match s.query_script(&q) { Answer::BloomFalsePositive => fp += 1, Answer::Funded { .. } => panic!("random script funded"), Answer::Absent => {} }
        assert!(s.exact_script(&q).is_none());
    }
    let rate = f64::from(fp) / f64::from(n);
    assert!(rate < 0.006 && rate > 0.0005, "fpr {rate}"); // design (1-e^(-8/12))^8 = 0.31%
}
