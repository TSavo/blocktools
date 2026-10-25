//! Every chain quirk in docs/CHAINS.md has an independent known-answer test that exists.
const DOC: &str = include_str!("../../../docs/CHAINS.md");

fn rows() -> Vec<Vec<String>> {
    let s = DOC.split("<!-- quirks:begin -->").nth(1).expect("quirks table missing").split("<!-- quirks:end -->").next().unwrap();
    s.lines().filter(|l| l.starts_with('|')).skip(2)
        .map(|l| l.trim_matches('|').split('|').map(|c| c.trim().to_string()).collect()).collect()
}
fn test_src(file: &str) -> Option<String> {
    std::fs::read_to_string(format!("{}/tests/{file}", env!("CARGO_MANIFEST_DIR"))).ok()
}

#[test] fn every_quirk_has_an_existing_independent_kat() {
    let r = rows();
    assert!(r.len() >= 10, "quirk table too short");
    for row in &r {
        assert_eq!(row.len(), 4, "bad row {row:?}");
        let (q, kat, src) = (&row[0], &row[2], &row[3]);
        assert!(!q.is_empty() && !row[1].is_empty(), "row {row:?}");
        assert!(src.len() > 10 && !src.to_lowercase().contains("our own"), "{q}: needs an independent source");
        let (file, f) = kat.split_once("::").unwrap_or_else(|| panic!("{q}: KAT must be file::fn, got {kat:?}"));
        let body = test_src(file).unwrap_or_else(|| panic!("{q}: no test file {file}"));
        assert!(body.contains(&format!("fn {f}(")), "{q}: {file} has no fn {f}");
        let pos = body.find(&format!("fn {f}(")).unwrap();
        assert!(body[..pos].trim_end().ends_with("#[test]"), "{q}: {f} is not a #[test]");
    }
}

#[test] fn every_quirky_chain_in_code_has_a_row() {
    let r = rows();
    let has = |chain: &str| r.iter().any(|row| row[1].split_whitespace().any(|c| c == chain));
    for id in ["ppc", "nvc", "clam", "rdd", "blk", "zec", "grs", "qrk"] {
        if ["ppc", "nvc", "clam", "rdd"].contains(&id) { assert!(blocktools_tx::pos::layout(id).is_some()) }
        assert!(has(id), "chain {id} has a quirk in code but no row in docs/CHAINS.md quirks table");
    }
    // Any chain pos::layout accepts must be listed (catches a new nTime chain added without a vector).
    for id in blocktools_core::chains::CHAINS.iter().map(|c| c.name) {
        if blocktools_tx::pos::layout(id).is_some() { assert!(has(id), "nTime chain {id} has no quirk row") }
    }
}
