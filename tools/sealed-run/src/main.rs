//! sealed-run: the agent-facing boundary. Runs a pipeline of blocktools tools
//! WITHOUT a shell (no expansion, no injection), then:
//!   sealed-run agent '<pipeline>'  -> stdout = redacted public JSON lines only
//!   sealed-run human '<pipeline>'  -> raw output (keys!) to /dev/tty after a typed code
//!   sealed-run pin-tty             -> pin this terminal session; afterwards codes are accepted only from it
//!   sealed-run unpack /in|/secrets  -> (wrapper, via `docker exec -u 0`) unpack a tar from stdin into that
//!                                      tmpfs: files 0444 / dirs 0555 owned by root, so uid 10001 can read
//!                                      but never change them; the root dir is opened (0555) last
//!   sealed-run staged agent|human '<pipeline>' -> wait until /secrets is readable (staging done), then run
//! Pipeline grammar: `tool args... [< file] | tool args... | ...`
//! Tokens are whitespace-separated. Only tools that live next to sealed-run and are
//! on the allowlist can be run. Tool stderr is discarded.
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};


fn out(status: &str) -> ! { blocktools_io::outln!(r#"{{"tool":"sealed-run","status":"{status}"}}"#); std::process::exit(2) }

pub struct Stage { pub prog: String, pub args: Vec<String>, pub input: Option<String> }

pub fn parse(pipeline: &str) -> Result<Vec<Stage>, &'static str> {
    if pipeline.len() > 4096 { return Err("bad_input"); }
    let mut stages = Vec::new();
    for (i, seg) in pipeline.split('|').enumerate() {
        let toks: Vec<&str> = seg.split_whitespace().collect();
        let (prog, rest) = toks.split_first().ok_or("bad_input")?;
        if !blocktools_io::sealed_allowed(prog) { return Err("unsupported"); }
        let mut args = Vec::new();
        let mut input = None;
        let mut it = rest.iter();
        while let Some(t) = it.next() {
            if *t == "<" {
                if i != 0 || input.is_some() { return Err("bad_input"); }
                input = Some(it.next().ok_or("bad_input")?.to_string());
            } else if t.chars().any(|c| ";&$`(){}*?<>'\"\\!~#".contains(c)) {
                return Err("bad_input");
            } else { args.push(t.to_string()); }
        }
        stages.push(Stage { prog: prog.to_string(), args, input });
    }
    if stages.is_empty() || stages.len() > 16 { return Err("bad_input"); }
    Ok(stages)
}

fn spawn(stages: &[Stage], last_stdout: Stdio) -> Result<Vec<Child>, &'static str> {
    let dir = std::env::current_exe().map_err(|_| "error")?.parent().ok_or("error")?.to_path_buf();
    let mut children: Vec<Child> = Vec::new();
    let n = stages.len();
    let mut last_stdout = Some(last_stdout);
    for (i, s) in stages.iter().enumerate() {
        let stdin = if let Some(f) = &s.input {
            Stdio::from(std::fs::File::open(f).map_err(|_| "bad_input")?)
        } else if let Some(prev) = children.last_mut() {
            Stdio::from(prev.stdout.take().ok_or("error")?)
        } else { Stdio::inherit() };
        let stdout = if i + 1 == n { last_stdout.take().unwrap() } else { Stdio::piped() };
        let c = Command::new(dir.join(&s.prog)).args(&s.args)
            .env_clear().stdin(stdin).stdout(stdout).stderr(Stdio::null())
            .spawn().map_err(|_| "error")?;
        children.push(c);
    }
    Ok(children)
}

/// Tar entry path -> safe relative path; None for the archive root ("." / ""); Err for anything escaping.
pub fn safe_rel(name: &str) -> Result<Option<std::path::PathBuf>, &'static str> {
    if name.starts_with('/') || name.contains('\0') { return Err("bad_input"); }
    let mut p = std::path::PathBuf::new();
    for c in name.split('/') {
        match c { "" | "." => {}, ".." => return Err("bad_input"), c => p.push(c) }
    }
    Ok(if p.as_os_str().is_empty() { None } else { Some(p) })
}

fn octal(f: &[u8]) -> Result<u64, &'static str> {
    if f.first().is_some_and(|b| b & 0x80 != 0) { // GNU base-256
        return Ok(f[1..].iter().fold(0u64, |a, b| a.wrapping_shl(8) | *b as u64));
    }
    let t: String = f.iter().take_while(|b| **b != 0).map(|b| *b as char).collect();
    let t = t.trim();
    if t.is_empty() { return Ok(0) }
    u64::from_str_radix(t, 8).map_err(|_| "bad_input")
}

fn cstr(f: &[u8]) -> String { String::from_utf8_lossy(&f[..f.iter().position(|b| *b == 0).unwrap_or(f.len())]).into_owned() }

/// Unpack a ustar/GNU/pax tar stream into `dest`: regular files and directories only (links, devices
/// and fifos are refused), no absolute or `..` paths. Files are written 0444 and directories end 0555,
/// `dest` itself last, so a reader waiting for `dest` to open sees a complete tree.
pub fn unpack(r: &mut impl Read, dest: &std::path::Path) -> Result<u64, &'static str> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut dirs: Vec<std::path::PathBuf> = Vec::new();
    let (mut long, mut n) = (None::<String>, 0u64);
    let mut h = [0u8; 512];
    loop {
        if r.read_exact(&mut h).is_err() { return Err("bad_input") }
        if h.iter().all(|b| *b == 0) { break }
        let size = octal(&h[124..136])?;
        let pad = (512 - size % 512) % 512;
        let kind = h[156];
        let mut name = cstr(&h[0..100]);
        if &h[257..262] == b"ustar" { let pre = cstr(&h[345..500]); if !pre.is_empty() { name = format!("{pre}/{name}") } }
        if kind == b'L' || kind == b'x' || kind == b'g' {
            if size > 1 << 20 { return Err("bad_input") }
            let mut b = vec![0u8; (size + pad) as usize];
            r.read_exact(&mut b).map_err(|_| "bad_input")?;
            b.truncate(size as usize);
            if kind == b'L' { long = Some(cstr(&b)) }
            if kind == b'x' { // pax records "len key=value\n": only path matters
                for rec in String::from_utf8_lossy(&b).split('\n') {
                    if let Some(v) = rec.split_once(' ').and_then(|(_, kv)| kv.strip_prefix("path=")) { long = Some(v.to_string()) }
                }
            }
            continue;
        }
        if let Some(l) = long.take() { name = l }
        let rel = safe_rel(&name)?;
        match kind {
            b'0' | 0 | b'7' => {
                let rel = rel.ok_or("bad_input")?;
                let path = dest.join(&rel);
                let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o444).open(&path).map_err(|_| "error")?;
                let mut take = (&mut *r).take(size);
                if std::io::copy(&mut take, &mut f).map_err(|_| "error")? != size { return Err("bad_input") }
                let mut p = vec![0u8; pad as usize];
                r.read_exact(&mut p).map_err(|_| "bad_input")?;
                n += 1;
            }
            b'5' => {
                if size != 0 { return Err("bad_input") }
                if let Some(rel) = rel {
                    let path = dest.join(&rel);
                    std::fs::create_dir(&path).map_err(|_| "error")?;
                    dirs.push(path); n += 1;
                }
            }
            _ => return Err("bad_input"),
        }
    }
    // deepest first, then dest: once 0555 nothing (not even root without CAP_DAC_OVERRIDE) adds to it
    dirs.sort_by_key(|d| std::cmp::Reverse(d.components().count()));
    for d in dirs.iter().map(|d| d.as_path()).chain([dest]) {
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o555)).map_err(|_| "error")?;
    }
    Ok(n)
}

fn random_code() -> String {
    let mut b = [0u8; 3];
    let ok = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).is_ok();
    if !ok { out("error"); }
    format!("{:03}-{:03}-{:03}", b[0], b[1], b[2])
}

fn main() {
    blocktools_io::help("sealed-run agent|human '<pipeline>': run an allowlisted tool pipeline; agent mode prints only redacted output");
    let mut a: Vec<String> = std::env::args().collect();
    if a.len() == 3 && a[1] == "unpack" {
        if a[2] != "/in" && a[2] != "/secrets" && std::env::var_os("BLOCKTOOLS_UNPACK_ANYWHERE").is_none() { out("bad_input") }
        match unpack(&mut std::io::stdin().lock(), std::path::Path::new(&a[2])) {
            Ok(n) => { blocktools_io::outln!(r#"{{"tool":"sealed-run","status":"unpacked","count":{n}}}"#); return }
            Err(e) => out(e),
        }
    }
    if a.get(1).map(String::as_str) == Some("staged") {
        // the wrapper streams ./in then ./secrets in (`unpack`); /secrets opens last. Give up after 120 s.
        let mut ok = false;
        for _ in 0..1200 { if std::fs::read_dir("/secrets").is_ok() { ok = true; break } std::thread::sleep(std::time::Duration::from_millis(100)) }
        if !ok { out("error") }
        a.remove(1);
    }
    if a.len() == 2 && a[1] == "pin-tty" {
        // Human-only: pin this terminal session (partial mitigation against agent-spawned ptys; SECURITY.md).
        let p = blocktools_tty::pin_paths().into_iter().last().unwrap_or_else(|| out("error")); // $BLOCKTOOLS_TTY_PIN if set, else ~/.config/blocktools/tty-pin
        match blocktools_tty::pin_here(&p) { Ok(()) => { blocktools_io::outln!(r#"{{"tool":"sealed-run","status":"pinned"}}"#); return } Err(e) => out(e) }
    }
    let (mode, pipeline) = match (a.get(1), a.get(2), a.len()) { (Some(m), Some(p), 3) => (m.clone(), p.clone()), _ => out("bad_input") };
    let stages = parse(&pipeline).unwrap_or_else(|e| out(e));
    match mode.as_str() {
        "agent" => {
            let mut ch = spawn(&stages, Stdio::piped()).unwrap_or_else(|e| out(e));
            let stdout = ch.last_mut().unwrap().stdout.take().unwrap();
            let mut o = std::io::stdout().lock();
            let (mut kept, mut dropped) = (0u64, 0u64);
            let mut r = BufReader::new(stdout);
            loop {
                let mut buf = Vec::new();
                let n = (&mut r).take(65536).read_until(b'\n', &mut buf).unwrap_or(0);
                if n == 0 { break; }
                match std::str::from_utf8(&buf).ok().and_then(|s| blocktools_schema::redact_output_line(s)) {
                    Some(l) => { kept += 1; let _ = writeln!(o, "{l}"); }
                    None => dropped += 1,
                }
            }
            for mut c in ch { let _ = c.wait(); }
            let _ = writeln!(o, r#"{{"tool":"redact","status":"done","count":{kept},"index":{dropped}}}"#);
        }
        "human" => {
            if let Err(e) = blocktools_tty::pin_check() { out(e) }
            let mut tty = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").unwrap_or_else(|_| out("bad_input"));
            let code = random_code();
            let _ = write!(tty, "This will print PRIVATE KEYS to this terminal.\nType the code {code} to continue: ");
            let mut ans = String::new();
            let _ = BufReader::new(tty.try_clone().unwrap()).take(64).read_line(&mut ans);
            if ans.trim() != code { let _ = writeln!(tty, "aborted"); out("error"); }
            let ch = spawn(&stages, Stdio::from(tty)).unwrap_or_else(|e| out(e));
            for mut c in ch { let _ = c.wait(); }
            blocktools_io::outln!(r#"{{"tool":"sealed-run","status":"done"}}"#);
        }
        _ => out("bad_input"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn parses() {
        let s = parse("seed-repair < /in/seed.txt | seed-to-master | derive --count 5").unwrap();
        assert_eq!(s.len(), 3); assert_eq!(s[0].input.as_deref(), Some("/in/seed.txt")); assert_eq!(s[2].args, vec!["--count", "5"]);
    }
    #[test] fn paths() {
        assert_eq!(safe_rel("./").unwrap(), None);
        assert_eq!(safe_rel("./a/b.txt").unwrap().unwrap(), std::path::PathBuf::from("a/b.txt"));
        for p in ["/etc/x", "../x", "a/../../x", "a/.."] { assert!(safe_rel(p).is_err(), "{p}") }
    }
    fn hdr(name: &str, kind: u8, size: usize) -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[124..135].copy_from_slice(format!("{size:011o}").as_bytes());
        h[156] = kind; h[257..262].copy_from_slice(b"ustar");
        h
    }
    #[test] fn unpacks_and_refuses() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("sr-unpack-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d); std::fs::create_dir(&d).unwrap();
        let mut t = hdr("./", b'5', 0);
        t.extend(hdr("./sub/", b'5', 0));
        t.extend(hdr("./sub/n.txt", b'0', 3)); let mut b = b"hi\n".to_vec(); b.resize(512, 0); t.extend(b);
        t.extend(vec![0u8; 1024]);
        assert_eq!(unpack(&mut &t[..], &d).unwrap(), 2);
        assert_eq!(std::fs::read(d.join("sub/n.txt")).unwrap(), b"hi\n");
        assert_eq!(std::fs::metadata(d.join("sub/n.txt")).unwrap().permissions().mode() & 0o777, 0o444);
        assert_eq!(std::fs::metadata(&d).unwrap().permissions().mode() & 0o777, 0o555);
        for (name, kind) in [("../x", b'0'), ("/x", b'0'), ("./l", b'2'), ("./h", b'1')] {
            let e = std::env::temp_dir().join(format!("sr-unpack-{}-{}", std::process::id(), kind));
            let _ = std::fs::remove_dir_all(&e); std::fs::create_dir(&e).unwrap();
            let mut t = hdr(name, kind, 0); t.extend(vec![0u8; 1024]);
            assert!(unpack(&mut &t[..], &e).is_err(), "{name}");
            let _ = std::fs::remove_dir_all(&e);
        }
        assert!(unpack(&mut &hdr("./x", b'0', 9)[..], &d).is_err(), "truncated");
        for p in [d.join("sub"), d.clone()] { std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap() }
        let _ = std::fs::remove_dir_all(&d);
    }
    #[test] fn rejects() {
        for p in ["sh -c id", "derive | bash", "seed-repair | derive < /x", "", "derive ; rm -rf /", "wget http://x"] {
            assert!(parse(p).is_err(), "{p}");
        }
    }
}
