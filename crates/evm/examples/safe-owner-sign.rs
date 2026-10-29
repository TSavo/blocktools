//! E2E/fixture helper (NOT a shipped tool): sign a 32-byte Safe tx hash with a raw test key, the way a
//! Safe EOA owner would, and print {sig, owner}. Blind-hash signing is deliberately not a blocktools
//! tool (see msg-sign's refusal); this fixture exists only to drive scripts/e2e.d/evm-safe.sh offline.
//!   cargo run -p blocktools-evm --example safe-owner-sign -- <safe_tx_hash_hex> <key_hex>
use blocktools_evm::keccak;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let hash = blocktools_evm::unhex(&a[0]).expect("hash hex");
    let h: [u8; 32] = hash.as_slice().try_into().expect("hash must be 32 bytes");
    let kb = blocktools_evm::unhex(&a[1]).expect("key hex");
    let sk = SecretKey::from_slice(&kb).expect("32-byte key");
    let secp = Secp256k1::new();
    let (id, rs) = secp.sign_ecdsa_recoverable(&Message::from_digest(h), &sk).serialize_compact();
    let mut sig = rs.to_vec();
    sig.push(27 + id.to_i32() as u8); // Safe EOA owner signature: v in {27,28}
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let kh = keccak(&pk.serialize_uncompressed()[1..]);
    let mut owner = [0u8; 20];
    owner.copy_from_slice(&kh[12..]);
    println!("{}", serde_json::json!({"sig": blocktools_evm::hex(&sig), "owner": blocktools_evm::checksum_address(&owner)}));
}
