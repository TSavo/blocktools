//! read-file: concatenate files to stdout (like cat), std only. Exists so the
//! shell-less reference image can feed files into a pipe.
//! Bounded: at most 64 MiB per file.
use std::io::{Read, Write};
fn main() {
    blocktools_io::help("read-file FILE: bounded file reader for pipelines inside the container");
    let mut out = std::io::stdout().lock();
    let mut rc = 0;
    for p in std::env::args().skip(1) {
        match std::fs::File::open(&p) {
            Ok(f) => { let mut buf = Vec::new(); if f.take(64 << 20).read_to_end(&mut buf).is_err() || out.write_all(&buf).is_err() { eprintln!("{{\"tool\":\"read-file\",\"status\":\"error\",\"error\":\"read_or_write_failed\"}}"); rc = rc.max(1); } }
            Err(_) => { eprintln!("{{\"tool\":\"read-file\",\"status\":\"bad_input\",\"error\":\"cannot_open\"}}"); rc = 2 }
        }
    }
    std::process::exit(rc);
}
