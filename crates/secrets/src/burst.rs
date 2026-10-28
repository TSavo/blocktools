//! Burst / Signum account from a secret passphrase — what blocktools was missing (not BIP39 /
//! secp256k1). passphrase -> SHA-256 private key -> Curve25519 base multiplication (clamped, as
//! libsodium/NXT) -> public key; the numeric account id is the first 8 bytes (little-endian) of
//! SHA-256(public key), and the "S-…" address is the NXT/Burst Reed-Solomon of that id.
use bitcoin::hashes::{sha256, Hash};
use curve25519_dalek::constants::X25519_BASEPOINT;
use zeroize::Zeroizing;

// NXT / Burst Reed-Solomon over GF(2^5).
const GEXP: [u8; 32] = [
    1, 2, 4, 8, 16, 5, 10, 20, 13, 26, 17, 7, 14, 28, 29, 31, 27, 19, 3, 6, 12, 24, 21, 15, 30, 25,
    23, 11, 22, 9, 18, 1,
];
const GLOG: [u8; 32] = [
    0, 0, 1, 18, 2, 5, 19, 11, 3, 29, 6, 27, 20, 8, 12, 23, 4, 10, 30, 17, 7, 22, 28, 26, 21, 25, 9,
    16, 13, 14, 24, 15,
];
const CWMAP: [usize; 17] = [3, 2, 1, 0, 7, 6, 5, 4, 13, 14, 15, 16, 12, 8, 9, 10, 11];
const ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

fn gmult(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        GEXP[(GLOG[a as usize] as usize + GLOG[b as usize] as usize) % 31]
    }
}

/// NXT/Burst Reed-Solomon encode of a numeric account id -> "XXXX-XXXX-XXXX-XXXXX" (no "S-").
pub fn reed_solomon(id: u64) -> String {
    let s = id.to_string();
    let mut d = [0u8; 20]; // a u64 is at most 20 decimal digits
    for (i, c) in s.bytes().enumerate() {
        d[i] = c - b'0';
    }
    let mut length = s.len();
    let mut codeword = [0u8; 17];
    let mut cw_len = 0usize;
    loop {
        // one base-10 -> base-32 reduction pass
        let mut new_len = 0usize;
        let mut digit32 = 0u32;
        for i in 0..length {
            digit32 = digit32 * 10 + d[i] as u32;
            if digit32 >= 32 {
                d[new_len] = (digit32 >> 5) as u8;
                digit32 &= 31;
                new_len += 1;
            } else if new_len > 0 {
                d[new_len] = 0;
                new_len += 1;
            }
        }
        length = new_len;
        codeword[cw_len] = digit32 as u8;
        cw_len += 1;
        if length == 0 {
            break;
        }
    }
    let mut p = [0u8; 4];
    for i in (0..13).rev() {
        let fb = codeword[i] ^ p[3];
        p[3] = p[2] ^ gmult(30, fb);
        p[2] = p[1] ^ gmult(6, fb);
        p[1] = p[0] ^ gmult(9, fb);
        p[0] = gmult(17, fb);
    }
    codeword[13..17].copy_from_slice(&p);
    let mut out = String::with_capacity(20);
    for i in 0..17 {
        out.push(ALPHABET[codeword[CWMAP[i]] as usize] as char);
        if i & 3 == 3 && i < 13 {
            out.push('-');
        }
    }
    out
}

/// (numeric account id, "S-…" Reed-Solomon address) from a Burst/Signum secret passphrase.
pub fn account_from_passphrase(passphrase: &str) -> (u64, String) {
    let sk = Zeroizing::new(sha256::Hash::hash(passphrase.as_bytes()).to_byte_array());
    // X25519 base multiplication with clamping (table-free ladder) == libsodium crypto_scalarmult_base.
    let pubkey = X25519_BASEPOINT.mul_clamped(*sk).to_bytes();
    let h = sha256::Hash::hash(&pubkey).to_byte_array();
    let id = u64::from_le_bytes(h[..8].try_into().unwrap());
    (id, format!("S-{}", reed_solomon(id)))
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Independently validated (python pynacl + NXT Reed-Solomon, live Signum API accountRS).
    #[test]
    fn burst_vector() {
        let (id, addr) = account_from_passphrase(
            "paint boat burst card course daddy money stair invite inside huge duck",
        );
        assert_eq!(id, 11817502445436113882);
        assert_eq!(addr, "S-H6YU-VM2A-MDZ5-CM32A");
    }
    #[test]
    fn rs_vector() {
        assert_eq!(reed_solomon(11817502445436113882), "H6YU-VM2A-MDZ5-CM32A");
    }
}
