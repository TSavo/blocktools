//! redact: stdin raw JSON lines (may contain secrets) -> stdout public lines.
//! This is the only process whose stdout is connected to the agent.
use std::io::{self, BufRead, Read, Write};
fn main() {
    blocktools_io::help("redact: JSON lines in -> schema-checked, secrets replaced by [REDACTED], leak-checked lines out; also passes public derive --address-list lines (label<TAB>path<TAB>address) that pass the same leak check");
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    let (mut kept, mut dropped) = (0u64, 0u64);
    // Bounded line reads (64 KiB) so hostile input cannot exhaust memory.
    let mut r = stdin.lock();
    loop {
        let mut buf = Vec::new();
        let n = (&mut r).take(65536).read_until(b'\n', &mut buf).unwrap_or(0);
        if n == 0 { break; }
        if buf.last() != Some(&b'\n') && n == 65536 { // overlong: skip rest of line
            dropped += 1; let mut sink = Vec::new(); let _ = r.read_until(b'\n', &mut sink); continue;
        }
        match std::str::from_utf8(&buf).ok().and_then(|s| blocktools_schema::redact_output_line(s)) {
            Some(l) => { kept += 1; let _ = writeln!(out, "{l}"); }
            None => dropped += 1,
        }
    }
    let _ = writeln!(out, r#"{{"tool":"redact","status":"done","count":{kept},"index":{dropped}}}"#);
}
