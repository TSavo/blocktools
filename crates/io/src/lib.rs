//! blocktools-io: stdout for pipe tools. If the reader went away (EPIPE, e.g. `| head`),
//! exit quietly with status 0 instead of panicking. std only.
use std::io::Write;
pub fn emit(line: &str) {
    let mut o = std::io::stdout().lock();
    if writeln!(o, "{line}").and_then(|_| o.flush()).is_err() { std::process::exit(0) }
}
/// D1-14 exit rule (docs/EXIT-CODES.md): 0 = ok/done/checksum_ok/valid; 2 = bad_input/unsupported (change
/// the input or arguments); 1 = every other status (refused, failed, aborted, wrong_password, error, ...).
pub fn exit_code(status: &str) -> i32 {
    match status { "ok" | "done" | "checksum_ok" | "valid" => 0, "bad_input" | "unsupported" => 2, _ => 1 }
}
/// `outln!(...)`: like `println!`, but EPIPE-safe.
#[macro_export]
macro_rules! outln { ($($t:tt)*) => { $crate::emit(&format!($($t)*)) } }

const HEAD: &str = "DANGEROUS: use at your own risk. Code that handles keys and signs transactions should always be read and audited by you before you trust it with real funds. Used incorrectly, it can destroy your money.
Used incorrectly (wrong address, huge fee, lost keys, wrong chain) you lose funds; verify every transaction.";
const TAIL: &str = "Unit tests are evidence, not a substitute for your own review. See docs/SECURITY.md.";

/// The sealed-run allowlist (crates/io/sealed-tools.txt): what sealed-run runs, what the sealed image ships.
pub const SEALED_TOOLS_TXT: &str = include_str!("../sealed-tools.txt");
/// Host-side tools and their class (crates/io/host-tools.txt).
pub const HOST_TOOLS_TXT: &str = include_str!("../host-tools.txt");
fn lines(t: &'static str) -> impl Iterator<Item = &'static str> {
    t.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'))
}
/// True when `tool` is on the sealed-run allowlist.
pub fn sealed_allowed(tool: &str) -> bool { lines(SEALED_TOOLS_TXT).any(|l| l == tool) }
fn host_class(tool: &str) -> Option<&'static str> {
    lines(HOST_TOOLS_TXT).find_map(|l| l.split_once(' ').filter(|(n, _)| *n == tool).map(|(_, c)| c.trim()))
}

/// The --help banner for `tool`, derived from the allowlist so it cannot drift from what sealed-run does.
pub fn banner(tool: &str) -> String {
    let mid = if tool == "sealed-run" {
        "This is the sealed boundary: ./blocktools run starts it inside the sealed, offline container.".to_string()
    } else if sealed_allowed(tool) {
        "It may open hostile wallet files and handle secrets: run it sealed and offline (./blocktools run; sealed-run allows it).".to_string()
    } else {
        match host_class(tool) {
            Some("public") => "Host-side network tool: it needs the network by design, so it is not in the sealed image and sealed-run refuses it. Run it on the host and give it public data only (addresses, public keys, signed transactions).".to_string(),
            Some("offline") => "Host-side offline tool: it opens no network connection and reads public chain data; it is not in the sealed image and sealed-run refuses it. It never prints a key; anything it prints from your own input (a matching phrase) is yours to keep private, so send stdout to a private file.".to_string(),
            Some("local-rpc") => "Host-side tool that needs a network connection to a local wallet RPC: it is not in the sealed image and sealed-run refuses it. It sends secrets only to a loopback RPC; run it on an offline host.".to_string(),
            _ => format!("UNCLASSIFIED: {tool} is in neither crates/io/sealed-tools.txt nor crates/io/host-tools.txt."),
        }
    };
    format!("{HEAD}\n{mid}\n{TAIL}")
}

/// If argv contains --help / -h: print this tool's banner + `usage` and exit 0. The tool name is the
/// executable's file name.
pub fn help(usage: &str) {
    if std::env::args().skip(1).any(|a| a == "--help" || a == "-h") {
        let tool = std::env::current_exe().ok().and_then(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
            .unwrap_or_default();
        help_with(&banner(&tool), usage)
    }
}
fn help_with(banner: &str, usage: &str) {
    if std::env::args().skip(1).any(|a| a == "--help" || a == "-h") {
        let mut o = std::io::stdout().lock();
        let _ = writeln!(o, "{banner}\n\n{usage}");
        std::process::exit(0)
    }
}

/// Remaining argv after dropping `--chain` and its value. A leading non-flag (the program
/// name, as returned by `args_or_exit`) is also dropped so it is not forwarded as a positional.
pub fn args_without_chain(args: &[String]) -> Vec<String> {
    let mut i = if args.first().map(|s| !s.starts_with('-')).unwrap_or(false) { 1 } else { 0 };
    let mut out = Vec::new();
    while i < args.len() {
        if args[i] == "--chain" {
            i += 1;
            if i < args.len() { i += 1; }
            continue;
        }
        out.push(args[i].clone());
        i += 1;
    }
    out
}

/// Run `tool` from the same directory as this executable. stdin/stdout/stderr are inherited.
pub fn sibling_exit<S: AsRef<std::ffi::OsStr>>(tool: &str, args: &[S]) -> Result<i32, &'static str> {
    let dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())).ok_or("delegate_missing")?;
    match std::process::Command::new(dir.join(tool)).args(args).status() {
        Ok(st) => Ok(st.code().unwrap_or(1)),
        Err(_) => Err("delegate_missing"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strips_chain_and_argv0() {
        let a = vec!["/bin/tx-build".into(), "--chain".into(), "sol".into(), "--plan".into(), "p.json".into()];
        assert_eq!(args_without_chain(&a), vec!["--plan".to_string(), "p.json".to_string()]);
        let b = vec!["--chain".into(), "xrp".into(), "--account".into(), "rX".into()];
        assert_eq!(args_without_chain(&b), vec!["--account".to_string(), "rX".to_string()]);
    }
}
