//! EntryPoint v0.8 EIP-712 signing for Simple7702Account.
//! Supports existing accounts and the EIP-7702 initCode marker without initializer calls.
use sha3::{Digest, Keccak256};
use std::num::NonZeroU64;

const ENTRY_POINT: [u8; 20] = [
    0x43, 0x37, 0x08, 0x4d, 0x9e, 0x25, 0x5f, 0xf0, 0x70, 0x24, 0x61, 0xcf, 0x88, 0x95, 0xce, 0x9e,
    0x3b, 0x5f, 0xf1, 0x08,
];
type Word = [u8; 32];
fn hash(data: impl AsRef<[u8]>) -> Word {
    Keccak256::digest(data).into()
}
fn word(data: &[u8]) -> Word {
    let mut out = [0; 32];
    out[32 - data.len()..].copy_from_slice(data);
    out
}
fn pair(high: u128, low: u128) -> Word {
    let mut out = [0; 32];
    out[..16].copy_from_slice(&high.to_be_bytes());
    out[16..].copy_from_slice(&low.to_be_bytes());
    out
}
pub struct UserOperation<'a> {
    pub chain_id: NonZeroU64,
    pub sender: [u8; 20],
    pub nonce: Word,
    /// Some(delegate) commits to the delegate substituted for the 7702 marker by EntryPoint.
    pub marker_delegate: Option<[u8; 20]>,
    pub call_data: &'a [u8],
    pub verification_gas: u128,
    pub call_gas: u128,
    pub pre_verification_gas: Word,
    pub priority_fee: u128,
    pub max_fee: u128,
    pub paymaster_and_data: &'a [u8],
}
impl UserOperation<'_> {
    pub fn digest(&self) -> Word {
        let domain = hash([
            hash(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            hash(b"ERC4337"), hash(b"1"), word(&self.chain_id.get().to_be_bytes()), word(&ENTRY_POINT),
        ].concat());
        let body = hash([
            hash(b"PackedUserOperation(address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData)"),
            word(&self.sender), self.nonce, hash(self.marker_delegate.as_ref().map_or(&[][..], |d| d.as_slice())),
            hash(self.call_data), pair(self.verification_gas,self.call_gas),self.pre_verification_gas,
            pair(self.priority_fee,self.max_fee),hash(self.paymaster_and_data),
        ].concat());
        hash([&[0x19, 0x01][..], &domain, &body].concat())
    }
    #[cfg(feature = "secrets")]
    pub fn sign(&self, key: &secp256k1::SecretKey) -> Result<[u8; 65], &'static str> {
        let secp = secp256k1::Secp256k1::signing_only();
        let pubkey = key.public_key(&secp).serialize_uncompressed();
        if hash(&pubkey[1..])[12..] != self.sender {
            return Err("address_does_not_match_key");
        }
        let (id, rs) = secp
            .sign_ecdsa_recoverable(&secp256k1::Message::from_digest(self.digest()), key)
            .serialize_compact();
        if id.to_i32() > 1 {
            return Err("unrepresentable recovery id");
        }
        let mut signature = [0; 65];
        signature[..64].copy_from_slice(&rs);
        signature[64] = 27 + id.to_i32() as u8;
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_base_sepolia_entry_point_get_user_op_hash() {
        let op = UserOperation {
            chain_id: 84532u64.try_into().unwrap(),
            sender: blocktools_core::hex_dec("18ee1d19ab2030e5dd6f52c6be152ffea0d08c0d")
                .unwrap()
                .try_into()
                .unwrap(),
            nonce: word(&[1]),
            marker_delegate: None,
            call_data: &[0x12, 0x34],
            verification_gas: 100000,
            call_gas: 50000,
            pre_verification_gas: word(&30000u64.to_be_bytes()),
            priority_fee: 1000,
            max_fee: 2000,
            paymaster_and_data: &[],
        };
        assert_eq!(
            blocktools_core::hex_enc(op.digest()),
            "abcf3b4ba27fdd1415a657bdf2287fd5861ec97d2bc6935fda13193fc2d8307a"
        );
        #[cfg(feature = "secrets")]
        {
            // Public fixture: getUserOpHash with the 7702 marker and a delegate
            // designator. Simple7702Account.isValidSignature returned 0x1626ba7e.
            let key = secp256k1::SecretKey::from_slice(&[1; 32]).unwrap();
            assert_eq!(op.sign(&key), Err("address_does_not_match_key"));
            let mut paymaster =
                blocktools_core::hex_dec("888888888888ec68a58ab8094cc1ad20ba3d2402").unwrap();
            paymaster.extend(pair(100000, 100000));
            paymaster.push(3);
            let marked = UserOperation {
                sender: blocktools_core::validate::eth(
                    "0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1",
                )
                .unwrap(),
                marker_delegate: Some(
                    blocktools_core::validate::eth("0x4Cd241E8d1510e30b2076397afc7508Ae59C66c9")
                        .unwrap(),
                ),
                paymaster_and_data: &paymaster,
                ..op
            };
            assert_eq!(
                blocktools_core::hex_enc(marked.digest()),
                "1ed81c4f1f5fff078cdc353c67732a0362ed1e4ce5005a6cdb43616bc1266f94"
            );
            assert_eq!(blocktools_core::hex_enc(marked.sign(&key).unwrap()),"302f9159d5987680933b56019340d483d5ad02ac7f20d74021d3b587a0077b0b2388e782c5690c9c391c5877f4edadabdf7751dfee5c2dd90e4cded0f6e091181c");
        }
    }
}
