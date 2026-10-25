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
    let _ = write!(tty, "{summary}\nType the code {c} to confirm (anything else aborts): ");
    let mut ans = Vec::new();
    let mut b = [0u8; 1];
    while tty.read(&mut b).unwrap_or(0) == 1 && b[0] != b'\n' && ans.len() < 64 { ans.push(b[0]) }
    let ok = String::from_utf8_lossy(&ans).trim() == c;
    if !ok { let _ = writeln!(tty, "aborted"); }
    ok
}

#[cfg(test)]
mod tests {
    #[test] fn code_shape() { let c = super::code().unwrap(); assert_eq!(c.len(), 6); assert!(c.chars().all(|x| x.is_ascii_alphanumeric())); assert_ne!(c, super::code().unwrap()); }
}
