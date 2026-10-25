//! Cosmos SDK (cosmoshub): one bank MsgSend, SIGN_MODE_DIRECT. Unsigned form = SignDoc bytes (body, auth_info, chain_id,
//! account_number); signed form = TxRaw. Signature: secp256k1 ECDSA over sha256(SignDoc), RFC6979, low-S, 64-byte r||s.
use crate::pb;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, ecdsa::Signature};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Send { pub from: String, pub to: String, pub denom: String, pub amount: u128, pub memo: String,
    pub pubkey: [u8; 33], pub sequence: u64, pub fee: u128, pub gas: u64, pub chain_id: String, pub account_number: u64 }

const MSG_SEND: &str = "/cosmos.bank.v1beta1.MsgSend";
const PUBKEY: &str = "/cosmos.crypto.secp256k1.PubKey";
fn coin(denom: &str, amt: u128) -> Vec<u8> { let mut c = vec![]; pb::bytes(&mut c, 1, denom.as_bytes()); pb::bytes(&mut c, 2, amt.to_string().as_bytes()); c }

impl Send {
    pub fn body(&self) -> Vec<u8> {
        let mut m = vec![]; pb::bytes(&mut m, 1, self.from.as_bytes()); pb::bytes(&mut m, 2, self.to.as_bytes()); pb::bytes(&mut m, 3, &coin(&self.denom, self.amount));
        let mut any = vec![]; pb::bytes(&mut any, 1, MSG_SEND.as_bytes()); pb::bytes(&mut any, 2, &m);
        let mut b = vec![]; pb::bytes(&mut b, 1, &any); if !self.memo.is_empty() { pb::bytes(&mut b, 2, self.memo.as_bytes()) } b
    }
    pub fn auth_info(&self) -> Vec<u8> {
        let mut k = vec![]; pb::bytes(&mut k, 1, &self.pubkey);
        let mut any = vec![]; pb::bytes(&mut any, 1, PUBKEY.as_bytes()); pb::bytes(&mut any, 2, &k);
        let mut single = vec![]; pb::uint(&mut single, 1, 1);
        let mut mode = vec![]; pb::bytes(&mut mode, 1, &single);
        let mut si = vec![]; pb::bytes(&mut si, 1, &any); pb::bytes(&mut si, 2, &mode); pb::uint(&mut si, 3, self.sequence);
        let mut fee = vec![]; pb::bytes(&mut fee, 1, &coin(&self.denom, self.fee)); pb::uint(&mut fee, 2, self.gas);
        let mut a = vec![]; pb::bytes(&mut a, 1, &si); pb::bytes(&mut a, 2, &fee); a
    }
    pub fn sign_doc(&self) -> Vec<u8> {
        let mut d = vec![]; pb::bytes(&mut d, 1, &self.body()); pb::bytes(&mut d, 2, &self.auth_info()); pb::bytes(&mut d, 3, self.chain_id.as_bytes()); pb::uint(&mut d, 4, self.account_number); d
    }
    pub fn tx_raw(&self, sig: &[u8; 64]) -> Vec<u8> { let mut t = vec![]; pb::bytes(&mut t, 1, &self.body()); pb::bytes(&mut t, 2, &self.auth_info()); pb::bytes(&mut t, 3, sig); t }
    fn digest(&self) -> Message { Message::from_digest(Sha256::digest(self.sign_doc()).into()) }
    pub fn sign(&self, sk: &[u8; 32]) -> Result<[u8; 64], &'static str> {
        let s = Secp256k1::new(); let k = SecretKey::from_slice(sk).map_err(|_| "bad_secret_key")?;
        if PublicKey::from_secret_key(&s, &k).serialize() != self.pubkey { return Err("key_does_not_match_pubkey") }
        Ok(s.sign_ecdsa(&self.digest(), &k).serialize_compact())
    }
    pub fn verify(&self, sig: &[u8; 64]) -> bool {
        let (Ok(pk), Ok(sg)) = (PublicKey::from_slice(&self.pubkey), Signature::from_compact(sig)) else { return false };
        let mut n = sg; n.normalize_s(); n == sg && Secp256k1::verification_only().verify_ecdsa(&self.digest(), &sg, &pk).is_ok()
    }
    pub fn decode_sign_doc(b: &[u8]) -> Result<Send, String> {
        let d = pb::fields(b)?;
        let body = pb::one(&d, 1).ok_or("no body")?; let auth = pb::one(&d, 2).ok_or("no auth_info")?;
        let chain_id = String::from_utf8(pb::one(&d, 3).ok_or("no chain_id")?.to_vec()).map_err(|_| "bad chain_id")?;
        let s = Self::decode_parts(body, auth, chain_id, pb::num(&d, 4))?;
        if s.sign_doc() != b { return Err("not canonical (re-encoding differs)".into()) }
        Ok(s)
    }
    /// TxRaw + the chain_id / account_number it was signed for -> (tx, signature).
    pub fn decode_tx_raw(b: &[u8], chain_id: &str, account_number: u64) -> Result<(Send, [u8; 64]), String> {
        let t = pb::fields(b)?;
        if pb::count(&t, 3) != 1 { return Err("exactly one signature expected".into()) }
        let s = Self::decode_parts(pb::one(&t, 1).ok_or("no body")?, pb::one(&t, 2).ok_or("no auth_info")?, chain_id.into(), account_number)?;
        let sig: [u8; 64] = pb::one(&t, 3).unwrap().try_into().map_err(|_| "signature must be 64 bytes")?;
        if s.tx_raw(&sig) != b { return Err("not canonical (re-encoding differs)".into()) }
        Ok((s, sig))
    }
    fn decode_parts(body: &[u8], auth: &[u8], chain_id: String, account_number: u64) -> Result<Send, String> {
        let s = |b: &[u8]| String::from_utf8(b.to_vec()).map_err(|_| "bad utf8".to_string());
        let bf = pb::fields(body)?;
        if pb::count(&bf, 1) != 1 { return Err("exactly one message expected".into()) }
        let any = pb::fields(pb::one(&bf, 1).unwrap())?;
        if pb::one(&any, 1) != Some(MSG_SEND.as_bytes()) { return Err("only MsgSend is supported".into()) }
        let m = pb::fields(pb::one(&any, 2).ok_or("no msg")?)?;
        if pb::count(&m, 3) != 1 { return Err("exactly one coin expected".into()) }
        let c = pb::fields(pb::one(&m, 3).unwrap())?;
        let denom = s(pb::one(&c, 1).ok_or("no denom")?)?;
        let amount: u128 = s(pb::one(&c, 2).ok_or("no amount")?)?.parse().map_err(|_| "bad amount")?;
        let af = pb::fields(auth)?;
        if pb::count(&af, 1) != 1 { return Err("exactly one signer expected".into()) }
        let si = pb::fields(pb::one(&af, 1).unwrap())?;
        let pany = pb::fields(pb::one(&si, 1).ok_or("no pubkey")?)?;
        if pb::one(&pany, 1) != Some(PUBKEY.as_bytes()) { return Err("only secp256k1 pubkeys are supported".into()) }
        let pubkey: [u8; 33] = pb::one(&pb::fields(pb::one(&pany, 2).ok_or("no key")?)?, 1).ok_or("no key")?.try_into().map_err(|_| "bad pubkey")?;
        let fee = pb::fields(pb::one(&af, 2).ok_or("no fee")?)?;
        if pb::count(&fee, 1) != 1 { return Err("exactly one fee coin expected".into()) }
        let fc = pb::fields(pb::one(&fee, 1).unwrap())?;
        if s(pb::one(&fc, 1).ok_or("no fee denom")?)? != denom { return Err("fee denom differs from amount denom".into()) }
        let fee_amt: u128 = s(pb::one(&fc, 2).ok_or("no fee amount")?)?.parse().map_err(|_| "bad fee")?;
        let t = Send { from: s(pb::one(&m, 1).ok_or("no from")?)?, to: s(pb::one(&m, 2).ok_or("no to")?)?, denom, amount,
            memo: pb::one(&bf, 2).map(s).transpose()?.unwrap_or_default(), pubkey, sequence: pb::num(&si, 3), fee: fee_amt, gas: pb::num(&fee, 2), chain_id, account_number };
        if t.body() != body || t.auth_info() != auth { return Err("unsupported fields present (timeout, granter, extension options, ...)".into()) }
        if address(&t.pubkey) != t.from { return Err("from address does not match signer pubkey".into()) }
        Ok(t)
    }
    pub fn txid(raw: &[u8]) -> String { Sha256::digest(raw).iter().map(|b| format!("{b:02X}")).collect() }
}
pub fn address(pubkey: &[u8; 33]) -> String {
    use bitcoin::hashes::{hash160, Hash};
    blocktools_core::chains::cosmos_address("cosmos", &hash160::Hash::hash(pubkey).to_byte_array())
}
pub fn pubkey_of(sk: &[u8; 32]) -> Result<[u8; 33], &'static str> { Ok(PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(sk).map_err(|_| "bad_secret_key")?).serialize()) }
