//! Human interaction on /dev/tty only (never stdin/stdout, which carry the pipe).
//! `libc` is used solely for tcgetattr/tcsetattr to switch terminal echo off.
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use zeroize::Zeroizing;

pub fn open() -> Option<File> { OpenOptions::new().read(true).write(true).open("/dev/tty").ok() }

/// Restores the saved terminal mode on drop (also on early return).
struct EchoOff { fd: i32, saved: libc::termios }
impl EchoOff {
    fn new(f: &File) -> Option<EchoOff> {
        let fd = f.as_raw_fd();
        // SAFETY: termios is plain data; fd is an open tty for the life of the guard.
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut t) != 0 { return None }
            let saved = t;
            t.c_lflag &= !(libc::ECHO | libc::ECHONL);
            t.c_lflag |= libc::ICANON;
            if libc::tcsetattr(fd, libc::TCSANOW, &t) != 0 { return None }
            Some(EchoOff { fd, saved })
        }
    }
}
impl Drop for EchoOff { fn drop(&mut self) { unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved); } } }

/// Read one line (max 1024 bytes) from the terminal with echo off. None if no tty
/// or echo cannot be disabled (we refuse rather than echo a secret).
pub fn read_secret(prompt: &str) -> Option<Zeroizing<String>> {
    let mut tty = open()?;
    let _g = EchoOff::new(&tty)?;
    let _ = tty.write_all(prompt.as_bytes());
    let mut s = Zeroizing::new(Vec::new());
    let mut b = [0u8; 1];
    while tty.read(&mut b).ok()? == 1 && b[0] != b'\n' && s.len() < 1024 { if b[0] != b'\r' { s.push(b[0]) } }
    let _ = tty.write_all(b"\n");
    String::from_utf8(s.to_vec()).ok().map(Zeroizing::new)
}

/// Random 6-character confirmation code from /dev/urandom (no ambiguous chars).
pub fn code() -> Option<String> {
    const A: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let mut r = [0u8; 6];
    File::open("/dev/urandom").ok()?.read_exact(&mut r).ok()?;
    Some(r.iter().map(|b| A[*b as usize % A.len()] as char).collect())
}

/// Show `summary` on the terminal and require the human to type a fresh code.
/// Returns false on any mismatch / no terminal. Never reads from stdin.
pub fn confirm(summary: &str) -> bool {
    let (Some(mut tty), Some(c)) = (open(), code()) else { return false };
    if let Err(e) = pin_check() { let _ = writeln!(tty, "refused: {e} (see SECURITY.md, terminal pinning)"); return false }
    let _ = write!(tty, "{summary}\nType the code {c} to confirm (anything else aborts): ");
    let mut ans = Vec::new();
    let mut b = [0u8; 1];
    while tty.read(&mut b).unwrap_or(0) == 1 && b[0] != b'\n' && ans.len() < 64 { ans.push(b[0]) }
    let ok = String::from_utf8_lossy(&ans).trim() == c;
    if !ok { let _ = writeln!(tty, "aborted"); }
    ok
}

// ---- Terminal pinning (partial mitigation, see SECURITY.md) ----
// A process that owns a pty (e.g. an agent running Python's pty.fork) can read the code and type it:
// /dev/tty alone does not prove a human. Pinning records the human's terminal session (session id +
// controlling-tty device) once; while a pin exists, confirm() refuses from any other session, so a
// freshly spawned pty does not pass. Limits: anyone who can write or delete the pin file (same Unix
// user) or inject into the pinned terminal itself (TIOCSTI, ptrace, tmux/screen send-keys) defeats it.

/// (session id, controlling tty device number) of this process. Linux only (reads /proc); None elsewhere.
pub fn session() -> Option<(i64, u64)> {
    // SAFETY: getsid(0) has no memory effects.
    let sid = unsafe { libc::getsid(0) } as i64;
    let st = std::fs::read_to_string("/proc/self/stat").ok()?;
    let f: Vec<&str> = st.rsplit_once(')')?.1.split_whitespace().collect();
    let tty: u64 = f.get(4)?.parse().ok()?; // field 7 tty_nr (fields after comm: state ppid pgrp session tty_nr)
    if sid <= 0 || tty == 0 { return None }
    Some((sid, tty))
}
/// Pin files: the account's home from the password database (not $HOME, which a caller controls)
/// and, additionally, $BLOCKTOOLS_TTY_PIN. An env var can add a pin but never remove one.
pub fn pin_paths() -> Vec<std::path::PathBuf> {
    let mut v = vec![];
    // SAFETY: getpwuid returns a pointer into static storage or null; copied out immediately.
    unsafe {
        let pw = libc::getpwuid(libc::getuid());
        if !pw.is_null() && !(*pw).pw_dir.is_null() {
            let d = std::ffi::CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned();
            v.push(std::path::Path::new(&d).join(".config/blocktools/tty-pin"));
        }
    }
    if let Some(e) = std::env::var_os("BLOCKTOOLS_TTY_PIN") { v.push(e.into()) }
    v
}
pub fn pin_matches(pin: &str, cur: Option<(i64, u64)>) -> bool {
    let mut it = pin.split_whitespace().map(|x| x.parse::<i64>());
    match (it.next(), it.next(), cur) { (Some(Ok(s)), Some(Ok(t)), Some((cs, ct))) => s == cs && t as u64 == ct, _ => false }
}
/// Ok when no pin exists, or every existing pin names this session. Fails closed on unreadable pins.
pub fn pin_check() -> Result<(), &'static str> {
    for p in pin_paths() {
        if !p.exists() { continue }
        let s = std::fs::read_to_string(&p).map_err(|_| "tty_pin_unreadable")?;
        if !pin_matches(&s, session()) { return Err("tty_session_not_pinned") }
    }
    Ok(())
}
/// Record this terminal session as the only one confirm() accepts (after a typed code). Mode 0600.
pub fn pin_here(path: &std::path::Path) -> Result<(), &'static str> {
    let (sid, tty) = session().ok_or("no_controlling_tty_session")?;
    if !confirm(&format!("Pin this terminal (session {sid}, tty {tty}) as the only one that may confirm?")) { return Err("aborted") }
    if let Some(d) = path.parent() { std::fs::create_dir_all(d).map_err(|_| "io")? }
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path).map_err(|_| "io")?;
    writeln!(f, "{sid} {tty}").map_err(|_| "io")
}

#[cfg(test)]
mod tests {
    #[test] fn pin_compare() {
        use super::pin_matches as m;
        assert!(m("100 34816\n", Some((100, 34816)))); assert!(!m("100 34816", Some((101, 34816))));
        assert!(!m("100 34816", Some((100, 34817)))); assert!(!m("100 34816", None)); assert!(!m("junk", Some((1, 1))));
    }
    #[test] fn code_shape() { let c = super::code().unwrap(); assert_eq!(c.len(), 6); assert!(c.chars().all(|x| x.is_ascii_alphanumeric())); assert_ne!(c, super::code().unwrap()); }
}
