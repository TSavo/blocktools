//! kr-run: the agent-facing boundary. Runs a pipeline of keyrescue tools
//! WITHOUT a shell (no expansion, no injection), then:
//!   kr-run agent '<pipeline>'  -> stdout = redacted public JSON lines only
//!   kr-run human '<pipeline>'  -> raw output (keys!) to /dev/tty after a typed code
//! Pipeline grammar: `tool args... [< file] | tool args... | ...`
//! Tokens are whitespace-separated. Only tools that live next to kr-run and are
//! on the allowlist can be run. Tool stderr is discarded.
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};

const ALLOWED: &[&str] = &[
    "seed-repair", "seed-to-master", "derive", "keystore-open", "kr-cat", "kr-redact",
    "dat-read", "electrum-read", "multibit-read", "armory-read",
    "tx-decode", "tx-build", "tx-verify", "tx-sign", "tx-build-sweep", "key-to-addresses", "classify",
];

fn out(status: &str) -> ! { kr_io::outln!(r#"{{"tool":"kr-run","status":"{status}"}}"#); std::process::exit(2) }

pub struct Stage { pub prog: String, pub args: Vec<String>, pub input: Option<String> }

pub fn parse(pipeline: &str) -> Result<Vec<Stage>, &'static str> {
    if pipeline.len() > 4096 { return Err("bad_input"); }
    let mut stages = Vec::new();
    for (i, seg) in pipeline.split('|').enumerate() {
        let toks: Vec<&str> = seg.split_whitespace().collect();
        let (prog, rest) = toks.split_first().ok_or("bad_input")?;
        if !ALLOWED.contains(prog) { return Err("unsupported"); }
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

fn random_code() -> String {
    let mut b = [0u8; 3];
    let ok = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).is_ok();
    if !ok { out("error"); }
    format!("{:03}-{:03}-{:03}", b[0], b[1], b[2])
}

fn main() {
    kr_io::help("kr-run agent|human '<pipeline>': run an allowlisted tool pipeline; agent mode prints only redacted output");
    let a: Vec<String> = std::env::args().collect();
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
                match std::str::from_utf8(&buf).ok().and_then(|s| kr_schema::redact_line(s.trim_end())) {
                    Some(l) => { kept += 1; let _ = writeln!(o, "{l}"); }
                    None => dropped += 1,
                }
            }
            for mut c in ch { let _ = c.wait(); }
            let _ = writeln!(o, r#"{{"tool":"kr-redact","status":"done","count":{kept},"index":{dropped}}}"#);
        }
        "human" => {
            let mut tty = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").unwrap_or_else(|_| out("bad_input"));
            let code = random_code();
            let _ = write!(tty, "This will print PRIVATE KEYS to this terminal.\nType the code {code} to continue: ");
            let mut ans = String::new();
            let _ = BufReader::new(tty.try_clone().unwrap()).take(64).read_line(&mut ans);
            if ans.trim() != code { let _ = writeln!(tty, "aborted"); out("error"); }
            let ch = spawn(&stages, Stdio::from(tty)).unwrap_or_else(|e| out(e));
            for mut c in ch { let _ = c.wait(); }
            kr_io::outln!(r#"{{"tool":"kr-run","status":"done"}}"#);
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
    #[test] fn rejects() {
        for p in ["sh -c id", "derive | bash", "seed-repair | derive < /x", "", "derive ; rm -rf /", "wget http://x"] {
            assert!(parse(p).is_err(), "{p}");
        }
    }
}
