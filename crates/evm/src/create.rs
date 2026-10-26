//! Contract addresses. CREATE: keccak256(rlp([sender, nonce]))[12..] (Yellow Paper eq. 85).
//! CREATE2: keccak256(0xff ++ sender ++ salt ++ keccak256(init_code))[12..] (EIP-1014).
use crate::keccak;

fn rlp_bytes(b: &[u8], out: &mut Vec<u8>) {
    if b.len() == 1 && b[0] < 0x80 { out.push(b[0]); } else { out.push(0x80 + b.len() as u8); out.extend_from_slice(b); }
}

/// CREATE address for `sender` at account `nonce`.
pub fn create(sender: &[u8; 20], nonce: u64) -> [u8; 20] {
    let nb = nonce.to_be_bytes();
    let first = nb.iter().position(|&x| x != 0).unwrap_or(8);
    let mut body = vec![];
    rlp_bytes(sender, &mut body);
    rlp_bytes(&nb[first..], &mut body); // nonce 0 -> empty string 0x80
    let mut enc = vec![0xc0 + body.len() as u8];
    enc.extend(body);
    keccak(&enc)[12..].try_into().unwrap()
}

/// CREATE2 address from `sender`, 32-byte `salt` and keccak256(init_code).
pub fn create2(sender: &[u8; 20], salt: &[u8; 32], init_code_hash: &[u8; 32]) -> [u8; 20] {
    let mut b = Vec::with_capacity(85);
    b.push(0xff); b.extend_from_slice(sender); b.extend_from_slice(salt); b.extend_from_slice(init_code_hash);
    keccak(&b)[12..].try_into().unwrap()
}
