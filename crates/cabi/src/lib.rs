//! C ABI for blocktools (secrets-off). Mirrors the wasm public surface at a small fixed
//! entry set: version, chain table, common signing envelope. No private keys, no I/O.
//!
//! Header: `crates/cabi/include/blocktools.h`.
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

fn to_c(s: String) -> *mut c_char {
    CString::new(s.replace('\0', "")).map(|c| c.into_raw()).unwrap_or(std::ptr::null_mut())
}

/// Library version (static). Do not free.
#[no_mangle]
pub extern "C" fn bt_version() -> *const c_char {
    static V: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    V.as_ptr() as *const c_char
}

/// JSON chain registry array. Caller frees with [`bt_free`].
#[no_mangle]
pub extern "C" fn bt_chain_table() -> *mut c_char {
    to_c(blocktools_core::chains::table_json())
}

/// Run a `blocktools.sign/v1` envelope JSON request. Caller frees with [`bt_free`].
#[no_mangle]
pub unsafe extern "C" fn bt_envelope(json_utf8: *const c_char) -> *mut c_char {
    if json_utf8.is_null() {
        return to_c(r#"{"envelope":"blocktools.sign/v1","status":"error","error":"null_input"}"#.into());
    }
    let s = match CStr::from_ptr(json_utf8).to_str() {
        Ok(s) => s,
        Err(_) => return to_c(r#"{"envelope":"blocktools.sign/v1","status":"error","error":"bad_utf8"}"#.into()),
    };
    to_c(blocktools::envelope::run(s))
}

/// Free a string from [`bt_chain_table`] or [`bt_envelope`].
#[no_mangle]
pub unsafe extern "C" fn bt_free(p: *mut c_char) {
    if p.is_null() { return }
    drop(CString::from_raw(p));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn version_nonempty() {
        let v = unsafe { CStr::from_ptr(bt_version()) }.to_str().unwrap();
        assert!(v.starts_with('0') || v.chars().next().unwrap().is_ascii_digit(), "{v}");
    }

    #[test]
    fn chain_table_roundtrip() {
        let p = bt_chain_table();
        assert!(!p.is_null());
        let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap();
        assert!(s.starts_with('[') && s.contains("\"name\":\"btc\""));
        unsafe { bt_free(p) };
    }

    #[test]
    fn envelope_chain_table_op() {
        let req = std::ffi::CString::new(r#"{"op":"chain_table","chain":"_"}"#).unwrap();
        let p = unsafe { bt_envelope(req.as_ptr()) };
        let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap();
        assert!(s.contains("\"status\":\"ok\""));
        unsafe { bt_free(p) };
    }
}
