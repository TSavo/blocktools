//! Chain-specific EIP-7702 authorization for an EOA. This signature authorizes
//! delegation, independently of any payment the account subsequently executes.
use crate::rlp::{encode, uint, Rlp};
use sha3::{Digest, Keccak256};
use std::num::NonZeroU64;

pub struct Authorization {
    pub chain_id: NonZeroU64,
    pub delegate: [u8; 20],
    pub nonce: u64,
}

impl Authorization {
    pub fn digest(&self) -> Result<[u8; 32], &'static str> {
        if self.nonce == u64::MAX {
            return Err("authorization nonce cannot be incremented");
        }
        let fields = Rlp::L(vec![
            uint(self.chain_id.get().into()),
            Rlp::B(self.delegate.to_vec()),
            uint(self.nonce.into()),
        ]);
        Ok(Keccak256::new()
            .chain_update([0x05])
            .chain_update(encode(&fields))
            .finalize()
            .into())
    }

    #[cfg(feature = "secrets")]
    pub fn sign(&self, key: &secp256k1::SecretKey) -> Result<(u8, [u8; 64]), &'static str> {
        let message = secp256k1::Message::from_digest(self.digest()?);
        let signature = secp256k1::Secp256k1::new().sign_ecdsa_recoverable(&message, key);
        let (id, compact) = signature.serialize_compact();
        let parity = id.to_i32() as u8;
        if parity > 1 {
            return Err("signature recovery id cannot be encoded as y parity");
        }
        Ok((parity, compact))
    }
}
