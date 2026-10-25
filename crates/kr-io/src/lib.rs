//! kr-io: stdout for pipe tools. If the reader went away (EPIPE, e.g. `| head`),
//! exit quietly with status 0 instead of panicking. std only.
use std::io::Write;
pub fn emit(line: &str) {
    let mut o = std::io::stdout().lock();
    if writeln!(o, "{line}").and_then(|_| o.flush()).is_err() { std::process::exit(0) }
}
/// `outln!(...)`: like `println!`, but EPIPE-safe.
#[macro_export]
macro_rules! outln { ($($t:tt)*) => { $crate::emit(&format!($($t)*)) } }

/// Shown at the top of every tool's --help and in README/DESIGN/docs/SECURITY.md.
pub const WARNING: &str = "DANGEROUS: use at your own risk; this code needs an independent security audit before use with real funds or keys.
It opens hostile wallet files and extracts secrets. Run it only sealed and offline (./keyrescue run).
Used incorrectly these tools can DESTROY FUNDS: signing to a wrong address, paying a huge fee,
losing keys, or sending to an address on the wrong chain. You are responsible for verifying every transaction.
Unit tests are the main evidence of correctness; they are not a substitute for an audit. See docs/SECURITY.md.";

/// If argv contains --help / -h: print WARNING + `usage` and exit 0.
pub fn help(usage: &str) {
    if std::env::args().skip(1).any(|a| a == "--help" || a == "-h") {
        let mut o = std::io::stdout().lock();
        let _ = writeln!(o, "{WARNING}\n\n{usage}");
        std::process::exit(0)
    }
}
