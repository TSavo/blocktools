//! The LevelDB port against bytes written by the reference implementation: a real Snappy-compressed
//! LevelDB (fixtures/leveldb/snappy-plyvel.hex.txt: table + log + MANIFEST from the C++ leveldb that
//! plyvel bundles) and a Snappy vector from an independent encoder. Expected sets are recomputed here
//! from the generator's recipe (fixture header). Corruptions must fail loudly.
use blocktools_utxo::leveldb::{snappy_decompress, Db};
use std::collections::BTreeMap;

fn root() -> std::path::PathBuf { std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..") }
fn hex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }
fn unpack(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("bt-ldb-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d); std::fs::create_dir_all(&d).unwrap();
    for l in std::fs::read_to_string(root().join("fixtures/leveldb/snappy-plyvel.hex.txt")).unwrap().lines() {
        if let Some(r) = l.strip_prefix("FILE ") { let (n, h) = r.split_once(' ').unwrap(); std::fs::write(d.join(n), hex(h)).unwrap() }
    }
    d
}
fn expected() -> BTreeMap<Vec<u8>, Vec<u8>> {
    let mut m = BTreeMap::new();
    for i in 0..3000 { if i % 7 != 0 { m.insert(format!("k{i:06}").into_bytes(), format!("value-{i}-").repeat(8).into_bytes()); } }
    for i in 3000..3010 { m.insert(format!("k{i:06}").into_bytes(), format!("late{i}").into_bytes()); }
    m.remove(&b"k000001"[..]);
    m
}
fn read(d: &std::path::Path) -> std::io::Result<(BTreeMap<Vec<u8>, Vec<u8>>, u64)> {
    let mut db = Db::open(d)?; let mut m = BTreeMap::new(); let mut last: Option<Vec<u8>> = None;
    while let Some((k, v)) = db.next_live()? {
        assert!(last.as_ref().is_none_or(|l| *l < k), "keys ascend in bytewise comparator order, each once");
        last = Some(k.clone()); m.insert(k, v);
    }
    Ok((m, db.snappy_blocks()))
}

#[test]
fn snappy_vector_from_independent_encoder() {
    let t = std::fs::read_to_string(root().join("fixtures/leveldb/snappy-vector.hex.txt")).unwrap();
    let get = |p: &str| hex(t.lines().find_map(|l| l.strip_prefix(p)).unwrap());
    let (raw, sz) = (get("RAW "), get("SZ "));
    assert_eq!(snappy_decompress(&sz).unwrap(), raw);
    assert!(snappy_decompress(&sz[..sz.len() - 1]).is_err(), "truncated");
    let mut long = sz.clone(); long[0] ^= 1; assert!(snappy_decompress(&long).is_err(), "declared length mismatch");
    assert!(snappy_decompress(&[4, 0b0000_0001 | (0 << 2), 1]).is_err(), "copy before any output (offset past start)");
}

#[test]
fn reference_written_snappy_leveldb_reads_exactly() {
    let d = unpack("ok");
    let (got, snappy) = read(&d).unwrap();
    assert!(snappy > 0, "the fixture's table blocks are Snappy-compressed");
    assert_eq!(got, expected());
}

#[test]
fn corrupt_table_block_fails_crc() {
    let d = unpack("crc");
    let t = std::fs::read_dir(&d).unwrap().map(|e| e.unwrap().path()).find(|p| p.extension().is_some_and(|x| x == "ldb")).unwrap();
    let mut b = std::fs::read(&t).unwrap(); b[100] ^= 0x40; std::fs::write(&t, b).unwrap();
    assert!(read(&d).unwrap_err().to_string().contains("crc"));
}

#[test]
fn live_set_comes_from_manifest_not_a_glob() {
    let d = unpack("glob");
    std::fs::write(d.join("000999.ldb"), b"not a table, not in the MANIFEST").unwrap();
    assert_eq!(read(&d).unwrap().0, expected(), "a stray .ldb outside the MANIFEST's live set is ignored");
    std::fs::remove_file(std::fs::read_dir(&d).unwrap().map(|e| e.unwrap().path()).find(|p| p.extension().is_some_and(|x| x == "ldb") && !p.ends_with("000999.ldb")).unwrap()).unwrap();
    assert!(read(&d).is_err(), "a live table named by the MANIFEST but missing is an error");
}
