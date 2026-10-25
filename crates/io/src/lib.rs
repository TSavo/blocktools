//! blocktools-io: stdout for pipe tools. If the reader went away (EPIPE, e.g. `| head`),
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
pub const WARNING: &str = "DANGEROUS: use at your own risk. Code that handles keys and signs transactions should always be read and audited by you before you trust it with real funds. Used incorrectly, it can destroy your money.
Used incorrectly (wrong address, huge fee, lost keys, wrong chain) you lose funds; verify every transaction.
It opens hostile wallet files and extracts secrets: run it only sealed and offline (./blocktools run).
Unit tests are evidence, not a substitute for your own review. See docs/SECURITY.md.";

/// If argv contains --help / -h: print WARNING + `usage` and exit 0.
pub fn help(usage: &str) {
    if std::env::args().skip(1).any(|a| a == "--help" || a == "-h") {
        let mut o = std::io::stdout().lock();
        let _ = writeln!(o, "{WARNING}\n\n{usage}");
        std::process::exit(0)
    }
}
