//! DESIGN §3: an agent-facing line is at most 512 bytes. Grow a valid line one allowlisted
//! warning at a time across the boundary: every output of <= 512 bytes passes, every longer one is dropped.
use blocktools_schema::{redact_output_line, STATUSES, TX_WARNINGS};
use serde_json::{json, Map, Value};

#[test]
fn line_cap_is_512_bytes() {
    let w = "nonstandard_output";
    assert!(TX_WARNINGS.contains(&w));
    let (mut kept, mut dropped, mut max_kept) = (0, 0, 0);
    for k in 0..=32 {
        let mut m = Map::new();
        m.insert("status".into(), json!(STATUSES[0]));
        m.insert("warnings".into(), Value::Array(vec![json!(w); k]));
        let want = serde_json::to_string(&Value::Object(m)).unwrap();
        let got = redact_output_line(&want);
        if want.len() <= 512 { assert_eq!(got.as_deref(), Some(want.as_str()), "len {}", want.len()); kept += 1; max_kept = max_kept.max(want.len()); }
        else { assert_eq!(got, None, "len {} must be dropped", want.len()); dropped += 1; }
    }
    assert!(kept > 0 && dropped > 0, "boundary not crossed");
    assert!(max_kept > 490, "largest kept line {max_kept} is not near 512");
}
