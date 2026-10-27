//! --metadata/--sources against a real solc 0.8.26 build (recipes/fixtures/evm-sol, see PROVENANCE.md there).
use std::io::Write;
use std::process::{Command, Stdio};
fn fx(p: &str) -> String { format!("{}/../../recipes/fixtures/evm-sol/{p}", env!("CARGO_MANIFEST_DIR")) }
fn run(args: &[&str], stdin: &str) -> (i32, serde_json::Value, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_bytecode-inspect")).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    // A tool that refuses before reading stdin closes it: EPIPE here is expected, the exit code and stderr are asserted.
    if let Err(e) = c.stdin.take().unwrap().write_all(stdin.as_bytes()) { assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}"); }
    let o = c.wait_with_output().unwrap();
    let out = String::from_utf8_lossy(&o.stdout).to_string();
    (o.status.code().unwrap(), serde_json::from_str(out.trim()).unwrap_or(serde_json::Value::Null), String::from_utf8_lossy(&o.stderr).into())
}
fn code(n: &str) -> String { std::fs::read_to_string(fx(n)).unwrap() }

#[test]
fn runtime_and_creation_with_args_match() {
    let (c, o, e) = run(&["--metadata", &fx("Counter.metadata.json"), "--sources", &fx("")], &code("Counter.runtime.hex"));
    assert_eq!(c, 0, "{e}");
    assert_eq!(o["metadata_match"], true); assert_eq!(o["embedded_cid"], o["metadata_cid"]);
    assert_eq!(o["compiler_matches_trailer"], true);
    assert_eq!(o["sources"]["src/Lib.sol"]["status"], "match"); assert_eq!(o["sources"]["src/Lib.sol"]["ipfs_url_match"], true);
    assert_eq!(o["sources_missing"], 0);
    let with_args = format!("{}{:064x}", code("Counter.creation.hex").trim(), 42);
    let (c, o, _) = run(&["--metadata", &fx("Counter.metadata.json")], &with_args);
    assert_eq!(c, 0); assert_eq!(o["metadata_match"], true); assert_eq!(o["sources_missing"], 2);
}

#[test]
fn tampered_source_and_metadata_are_mismatches() {
    let d = std::env::temp_dir().join(format!("bi-meta-{}", std::process::id()));
    std::fs::create_dir_all(d.join("src")).unwrap();
    std::fs::copy(fx("src/Counter.sol"), d.join("src/Counter.sol")).unwrap();
    std::fs::write(d.join("src/Lib.sol"), code("src/Lib.sol").replace("x + 1", "x + 2")).unwrap();
    let (c, o, _) = run(&["--metadata", &fx("Counter.metadata.json"), "--sources", d.to_str().unwrap()], &code("Counter.runtime.hex"));
    assert_eq!(c, 1); assert_eq!(o["status"], "mismatch");
    assert_eq!(o["sources"]["src/Lib.sol"]["status"], "mismatch"); assert_eq!(o["sources"]["src/Counter.sol"]["status"], "match");
    let m = d.join("m.json");
    std::fs::write(&m, code("Counter.metadata.json").replacen("200", "201", 1)).unwrap();
    let (c, o, _) = run(&["--metadata", m.to_str().unwrap()], &code("Counter.runtime.hex"));
    assert_eq!(c, 1); assert_eq!(o["metadata_match"], false);
}

#[test]
fn no_trailer_and_bad_input() {
    let (c, o, _) = run(&["--metadata", &fx("Counter.metadata.json")], "0x6000");
    assert_eq!(c, 1); assert_eq!(o["status"], "no_metadata");
    let (c, _, e) = run(&["--sources", "/tmp"], "0x6000");
    assert_eq!(c, 2, "{e}");
}
