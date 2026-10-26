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

/// Shown at the top of every tool's --help and in README/DESIGN/docs/SECURITY.md.
pub const WARNING: &str = "DANGEROUS: use at your own risk. Code that handles keys and signs transactions should always be read and audited by you before you trust it with real funds. Used incorrectly, it can destroy your money.
Used incorrectly (wrong address, huge fee, lost keys, wrong chain) you lose funds; verify every transaction.
It opens hostile wallet files and extracts secrets: run it only sealed and offline (./blocktools run).
Unit tests are evidence, not a substitute for your own review. See docs/SECURITY.md.";

/// The --help banner of the host-side network tools (rpc, utxo-fetch, tx-broadcast, xmr-wallet). They are
/// not in the sealed image and `sealed-run` refuses them (`unsupported`), so they must not tell the user to
/// run them sealed.
pub const HOST_WARNING: &str = "DANGEROUS: use at your own risk. Code that handles keys and signs transactions should always be read and audited by you before you trust it with real funds. Used incorrectly, it can destroy your money.
Used incorrectly (wrong address, huge fee, lost keys, wrong chain) you lose funds; verify every transaction.
This is a host-side network tool: it cannot run sealed (it is not in the sealed image and sealed-run refuses it). Run it on the host; feed it public data only, unless the usage below says otherwise.
Unit tests are evidence, not a substitute for your own review. See docs/SECURITY.md.";

/// If argv contains --help / -h: print WARNING + `usage` and exit 0.
pub fn help(usage: &str) { help_with(WARNING, usage) }
/// `help` for the host-side network tools: HOST_WARNING instead of WARNING.
pub fn help_host(usage: &str) { help_with(HOST_WARNING, usage) }
fn help_with(banner: &str, usage: &str) {
    if std::env::args().skip(1).any(|a| a == "--help" || a == "-h") {
        let mut o = std::io::stdout().lock();
        let _ = writeln!(o, "{banner}\n\n{usage}");
        std::process::exit(0)
    }
}
