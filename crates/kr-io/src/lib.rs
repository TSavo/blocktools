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
