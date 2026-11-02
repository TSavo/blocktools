//! spruceid/siwe test vectors (commit 911f6f2c73ef24deac73fec2f6b84930721d2fb4, test/*.json, MIT/Apache-2.0).
//! Provenance: docs/PROVENANCE-siwe.md.
use serde_json::Value;
use siwe::*;

fn load(f: &str) -> serde_json::Map<String, Value> {
    serde_json::from_str::<Value>(&std::fs::read_to_string(format!("{}/tests/data/{f}", env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap().as_object().unwrap().clone()
}
/// spruce's fields use null for absent; ours omit them.
fn strip_nulls(v: &Value) -> Value {
    Value::Object(v.as_object().unwrap().iter().filter(|(_, x)| !x.is_null()).map(|(k, x)| (k.clone(), x.clone())).collect())
}

#[test]
fn parsing_positive_all() {
    let d = load("parsing_positive.json");
    assert_eq!(d.len(), 19);
    for (name, t) in &d {
        let m = Siwe::parse(t["message"].as_str().unwrap()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(m.to_json(), strip_nulls(&t["fields"]), "{name}");
        assert_eq!(m.render(), t["message"].as_str().unwrap(), "{name}");
        // build from the published fields gives the same text
        assert_eq!(Siwe::from_json(&t["fields"]).unwrap().render(), t["message"].as_str().unwrap(), "{name}");
    }
}

#[test]
fn parsing_negative_all() {
    let d = load("parsing_negative.json");
    assert_eq!(d.len(), 29);
    for (name, t) in &d { assert!(Siwe::parse(t.as_str().unwrap()).is_err(), "{name} parsed"); }
}

#[test]
fn negative_objects_all() {
    let d = load("parsing_negative_objects.json");
    assert_eq!(d.len(), 18);
    for (name, t) in &d {
        let r = Siwe::from_json(t).map_err(|e| e).and_then(|m| m.validate().map_err(String::from));
        assert!(r.is_err(), "{name} built");
    }
}

#[test]
fn message_objects() {
    let d = load("message_objects.json");
    assert_eq!(d.len(), 13);
    for (name, t) in &d {
        let r = Siwe::from_json(&t["msg"]).and_then(|m| m.validate().map(|_| m).map_err(String::from));
        assert_eq!(r.is_ok(), t["error"] == "none", "{name}: {r:?}");
        if let Ok(m) = r { assert_eq!(Siwe::parse(&m.render()).unwrap(), m, "{name}") }
    }
}

#[test]
fn valid_specification() {
    let d = load("valid_specification.json");
    assert_eq!(d.len(), 9);
    for (name, t) in &d {
        let m = Siwe::parse(t["msg"].as_str().unwrap()).unwrap_or_else(|e| panic!("{name}: {e}"));
        let it = &t["items"];
        assert_eq!(m.statement.as_deref(), it["statement"].as_str(), "{name}");
        assert_eq!(m.request_id.as_deref(), it["requestId"].as_str(), "{name}");
        let r: Option<Vec<String>> = it["resources"].as_array().map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect());
        assert_eq!(m.resources, r, "{name}");
    }
}

#[test]
fn uris() {
    let ok = load("valid_uris.json");
    let bad = load("invalid_uris.json");
    assert_eq!((ok.len(), bad.len()), (36, 17));
    for (name, t) in &ok { Siwe::parse(t["msg"].as_str().unwrap()).unwrap_or_else(|e| panic!("{name}: {e}")); }
    for (name, t) in &bad { assert_eq!(Siwe::parse(t.as_str().unwrap()), Err("bad_uri"), "{name}") }
}

#[test]
fn verification_fields_render_and_parse() {
    // The text these signatures were made over: build from the fields, parse back (signature checked in e2e by msg-verify).
    for f in ["verification_positive.json", "verification_negative.json"] {
        for (name, t) in &load(f) {
            let mut o = t.as_object().unwrap().clone();
            o.remove("signature");
            let Ok(m) = Siwe::from_json(&Value::Object(o)) else { continue };
            if m.validate().is_ok() { assert_eq!(Siwe::parse(&m.render()).unwrap(), m, "{f} {name}") }
        }
    }
}

#[test]
fn non_canonical_and_time() {
    let base = load("parsing_positive.json")["couple of optional fields"]["message"].as_str().unwrap().to_string();
    for bad in [format!("{base}\n"), base.replace('\n', "\r\n"), base.replace("Version: 1", "Version:  1"), base.replace("Chain ID: 1", "Chain ID: 01"), format!(" {base}")] {
        assert!(Siwe::parse(&bad).is_err(), "{bad:?}");
    }
    assert_eq!(rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(rfc3339_ms("2021-09-30T16:25:24-02:00"), rfc3339_ms("2021-09-30T18:25:24Z"));
    assert_eq!(rfc3339_ms("2000-02-29T00:00:00.5Z"), Some(951782400500));
    for b in ["2001-02-29T00:00:00Z", "2022-13-17T12:45:13.610Z", "2023-03-17T25:45:13.610Z", "2023-03-17t12:45:13Z", "2023-03-17T12:45:13", "2023-03-17T12:45:13.Z"] {
        assert_eq!(rfc3339_ms(b), None, "{b}");
    }
}
