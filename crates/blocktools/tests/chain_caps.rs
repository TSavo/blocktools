//! docs/CHAINS.md "What each row can do": the detect column is measured here. For every row
//! whose test-phrase address scripts/chain-caps.py filled in, address::detect on that address
//! must give what the cell says: "yes" (only this chain), "yes, 1 of N" (this chain among N
//! candidates), or "no". scripts/chain-caps.py --check measures the other columns.
use blocktools::address::detect;
#[test]
fn detect_column_matches_address_detect() {
    let doc = include_str!("../../../docs/CHAINS.md");
    let t = doc.split("<!-- chain-caps:begin -->").nth(1).and_then(|s| s.split("<!-- chain-caps:end -->").next()).expect("chain-caps table");
    let (mut n, mut bad) = (0, Vec::new());
    for l in t.lines() {
        let f: Vec<&str> = l.trim().trim_matches('|').split('|').map(str::trim).collect();
        if f.len() != 6 || f[0] == "chain" || f[0] == "---" || f[1] != "yes" { continue }
        let addr = f[4].trim_matches('`');
        let c = detect(addr);
        let want = if !c.iter().any(|(k, _)| *k == f[0]) { "no".to_string() } else if c.len() == 1 { "yes".into() } else { format!("yes, 1 of {}", c.len()) };
        if want != f[2] { bad.push(format!("{}: doc says {:?}, address::detect gives {:?}", f[0], f[2], want)) }
        n += 1;
    }
    assert!(n > 50, "only {n} rows checked");
    assert!(bad.is_empty(), "detect column wrong:\n{}", bad.join("\n"));
}
