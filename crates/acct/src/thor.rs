//! THORChain `MsgDeposit` (chain_id `thorchain-1`): SIGN_MODE_DIRECT, `/cosmos.crypto.secp256k1.PubKey`,
//! secp256k1 ECDSA over sha256(SignDoc). THORChain-native actions ride in the deposit `memo`: swaps
//! (`=:ASSET:DEST:LIM`), liquidity, and THORName `~:name:chain:addr[:owner:preferred]` register/update.
//! Address = thor1 = bech32("thor", hash160(compressed pubkey)). The protocol native fee (RfRune) is
//! deducted by the chain, so the tx carries a gas limit but no fee coin. Unsigned form = SignDoc bytes;
//! signed form = TxRaw. Golden KATs: the real mainnet `swapchan` THORName register/alias txs
//! (crates/acct/tests/thorchain.rs), accepted by thorchain-1 on 2026-10-27.
use crate::pb;
use bitcoin::hashes::{hash160, Hash};
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

pub const CHAIN_ID: &str = "thorchain-1";
const MSG_DEPOSIT: &str = "/types.MsgDeposit";
const PUBKEY: &str = "/cosmos.crypto.secp256k1.PubKey";

/// One `MsgDeposit` of a single coin, SIGN_MODE_DIRECT. For RUNE the asset is THOR/RUNE/RUNE.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deposit {
    pub asset_chain: String, pub asset_symbol: String, pub asset_ticker: String,
    pub amount: u128, pub memo: String, pub pubkey: [u8; 33],
    pub sequence: u64, pub gas: u64, pub chain_id: String, pub account_number: u64,
}

impl Deposit {
    pub fn signer20(&self) -> [u8; 20] { hash160::Hash::hash(&self.pubkey).to_byte_array() }
    pub fn thor_address(&self) -> String { blocktools_core::chains::cosmos_address("thor", &self.signer20()) }
    fn asset(&self) -> Vec<u8> { let mut a = vec![]; pb::bytes(&mut a, 1, self.asset_chain.as_bytes()); pb::bytes(&mut a, 2, self.asset_symbol.as_bytes()); pb::bytes(&mut a, 3, self.asset_ticker.as_bytes()); a }
    // common.Coin { Asset asset = 1; string amount = 2; } — decimals (3) is omitted for native RUNE, matching mainnet.
    fn coin(&self) -> Vec<u8> { let mut c = vec![]; pb::bytes(&mut c, 1, &self.asset()); pb::bytes(&mut c, 2, self.amount.to_string().as_bytes()); c }
    // TxBody { Any{ /types.MsgDeposit { Coin coins=1; string memo=2; bytes signer=3 } } }. No TxBody.memo.
    pub fn body(&self) -> Vec<u8> {
        let mut m = vec![]; pb::bytes(&mut m, 1, &self.coin()); pb::bytes(&mut m, 2, self.memo.as_bytes()); pb::bytes(&mut m, 3, &self.signer20());
        let mut any = vec![]; pb::bytes(&mut any, 1, MSG_DEPOSIT.as_bytes()); pb::bytes(&mut any, 2, &m);
        let mut b = vec![]; pb::bytes(&mut b, 1, &any); b
    }
    // AuthInfo { SignerInfo{ pubkey Any; ModeInfo single=SIGN_MODE_DIRECT; uint64 sequence }; Fee{ uint64 gas_limit } }. No fee coin.
    pub fn auth_info(&self) -> Vec<u8> {
        let mut k = vec![]; pb::bytes(&mut k, 1, &self.pubkey);
        let mut any = vec![]; pb::bytes(&mut any, 1, PUBKEY.as_bytes()); pb::bytes(&mut any, 2, &k);
        let mut single = vec![]; pb::uint(&mut single, 1, 1);
        let mut mode = vec![]; pb::bytes(&mut mode, 1, &single);
        let mut si = vec![]; pb::bytes(&mut si, 1, &any); pb::bytes(&mut si, 2, &mode); pb::uint(&mut si, 3, self.sequence);
        let mut fee = vec![]; pb::uint(&mut fee, 2, self.gas);
        let mut a = vec![]; pb::bytes(&mut a, 1, &si); pb::bytes(&mut a, 2, &fee); a
    }
    pub fn sign_doc(&self) -> Vec<u8> { let mut d = vec![]; pb::bytes(&mut d, 1, &self.body()); pb::bytes(&mut d, 2, &self.auth_info()); pb::bytes(&mut d, 3, self.chain_id.as_bytes()); pb::uint(&mut d, 4, self.account_number); d }
    pub fn tx_raw(&self, sig: &[u8; 64]) -> Vec<u8> { let mut t = vec![]; pb::bytes(&mut t, 1, &self.body()); pb::bytes(&mut t, 2, &self.auth_info()); pb::bytes(&mut t, 3, sig); t }
    fn digest(&self) -> Message { Message::from_digest(Sha256::digest(&self.sign_doc()).into()) }
    pub fn sign(&self, sk: &[u8; 32]) -> Result<[u8; 64], &'static str> {
        let s = Secp256k1::new(); let k = SecretKey::from_slice(sk).map_err(|_| "bad_secret_key")?;
        if PublicKey::from_secret_key(&s, &k).serialize() != self.pubkey { return Err("key_does_not_match_pubkey") }
        Ok(s.sign_ecdsa(&self.digest(), &k).serialize_compact())
    }
    pub fn verify(&self, sig: &[u8; 64]) -> bool {
        let (Ok(pk), Ok(sg)) = (PublicKey::from_slice(&self.pubkey), Signature::from_compact(sig)) else { return false };
        let mut n = sg; n.normalize_s(); n == sg && Secp256k1::verification_only().verify_ecdsa(&self.digest(), &sg, &pk).is_ok()
    }
    pub fn txid(raw: &[u8]) -> String { Sha256::digest(raw).iter().map(|b| format!("{b:02X}")).collect() }

    pub fn decode_sign_doc(b: &[u8]) -> Result<Deposit, String> {
        let d = pb::fields(b)?;
        let body = pb::one(&d, 1).ok_or("no body")?; let auth = pb::one(&d, 2).ok_or("no auth_info")?;
        let chain_id = String::from_utf8(pb::one(&d, 3).ok_or("no chain_id")?.to_vec()).map_err(|_| "bad chain_id")?;
        let t = Self::decode_parts(body, auth, chain_id, pb::num(&d, 4))?;
        if t.sign_doc() != b { return Err("not canonical (re-encoding differs)".into()) }
        Ok(t)
    }
    /// TxRaw + the chain_id / account_number it was signed for -> (deposit, signature).
    pub fn decode_tx_raw(b: &[u8], chain_id: &str, account_number: u64) -> Result<(Deposit, [u8; 64]), String> {
        let t = pb::fields(b)?;
        if pb::count(&t, 3) != 1 { return Err("exactly one signature expected".into()) }
        let d = Self::decode_parts(pb::one(&t, 1).ok_or("no body")?, pb::one(&t, 2).ok_or("no auth_info")?, chain_id.into(), account_number)?;
        let sig: [u8; 64] = pb::one(&t, 3).unwrap().try_into().map_err(|_| "signature must be 64 bytes")?;
        if d.tx_raw(&sig) != b { return Err("not canonical (re-encoding differs)".into()) }
        Ok((d, sig))
    }
    fn decode_parts(body: &[u8], auth: &[u8], chain_id: String, account_number: u64) -> Result<Deposit, String> {
        let s = |b: &[u8]| String::from_utf8(b.to_vec()).map_err(|_| "bad utf8".to_string());
        let bf = pb::fields(body)?;
        if pb::count(&bf, 1) != 1 { return Err("exactly one message expected".into()) }
        let any = pb::fields(pb::one(&bf, 1).unwrap())?;
        if pb::one(&any, 1) != Some(MSG_DEPOSIT.as_bytes()) { return Err("only MsgDeposit is supported".into()) }
        let m = pb::fields(pb::one(&any, 2).ok_or("no msg")?)?;
        if pb::count(&m, 1) != 1 { return Err("exactly one coin expected".into()) }
        let c = pb::fields(pb::one(&m, 1).unwrap())?;
        let asset = pb::fields(pb::one(&c, 1).ok_or("no asset")?)?;
        let amount: u128 = s(pb::one(&c, 2).ok_or("no amount")?)?.parse().map_err(|_| "bad amount")?;
        let signer = pb::one(&m, 3).ok_or("no signer")?;
        let af = pb::fields(auth)?;
        if pb::count(&af, 1) != 1 { return Err("exactly one signer expected".into()) }
        let si = pb::fields(pb::one(&af, 1).unwrap())?;
        let pany = pb::fields(pb::one(&si, 1).ok_or("no pubkey")?)?;
        if pb::one(&pany, 1) != Some(PUBKEY.as_bytes()) { return Err("pubkey type must be /cosmos.crypto.secp256k1.PubKey".into()) }
        let kb = pb::one(&pb::fields(pb::one(&pany, 2).ok_or("no key")?)?, 1).ok_or("no key")?;
        let pubkey: [u8; 33] = PublicKey::from_slice(kb).map_err(|_| "bad pubkey")?.serialize();
        let fee = pb::fields(pb::one(&af, 2).ok_or("no fee")?)?;
        if pb::count(&fee, 1) != 0 { return Err("THORChain deposit carries no fee coin".into()) }
        let t = Deposit {
            asset_chain: s(pb::one(&asset, 1).ok_or("no asset chain")?)?, asset_symbol: s(pb::one(&asset, 2).ok_or("no asset symbol")?)?, asset_ticker: s(pb::one(&asset, 3).ok_or("no asset ticker")?)?,
            amount, memo: pb::one(&m, 2).map(s).transpose()?.unwrap_or_default(), pubkey,
            sequence: pb::num(&si, 3), gas: pb::num(&fee, 2), chain_id, account_number };
        if t.body() != body || t.auth_info() != auth { return Err("unsupported fields present (TxBody memo, timeout, extra coins, fee coin, ...)".into()) }
        if t.signer20().as_slice() != signer { return Err("signer does not match pubkey".into()) }
        Ok(t)
    }
}
