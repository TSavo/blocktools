//! Generator, NOT part of the blocktools build. Copied into wallet-core adf80f8 as
//! rust/tw_tests/tests/bt_gen_ethermint.rs by .github/workflows/twc-vectors.yml and run with
//! `cargo test -p tw_tests --test bt_gen_ethermint -- --nocapture`. Prints TWC's own MsgSend output for fixed inputs.
//! Key: Trust Wallet Core public test vector (NativeInjective SignerTests.cpp), never a real key.
use tw_any_coin::ffi::tw_any_signer::tw_any_signer_sign;
use tw_coin_registry::coin_type::CoinType;
use tw_encoding::hex::{DecodeHex, ToHex};
use tw_memory::test_utils::tw_data_helper::TWDataHelper;
use tw_proto::Cosmos::Proto::{self, mod_Message::OneOfmessage_oneof as MessageEnum};
use tw_proto::{deserialize, serialize};

const KEY: &str = "9ee18daf8e463877aaf497282abc216852420101430482a28e246c179e2c5ef1"; // public test vector

fn gen(name: &str, coin: CoinType, from: &str, to: &str, denom: &str, chain_id: &str, signer: Option<Proto::SignerInfo>, hasher: Proto::TxHasher) {
    let input = Proto::SigningInput {
        signing_mode: Proto::SigningMode::Protobuf, account_number: 1234, chain_id: chain_id.into(), sequence: 5,
        fee: Some(Proto::Fee { gas: 200000, amounts: vec![Proto::Amount { denom: denom.into(), amount: "4000000000000000".into() }] }),
        private_key: KEY.decode_hex().unwrap().into(),
        messages: vec![Proto::Message { message_oneof: MessageEnum::send_coins_message(Proto::mod_Message::Send {
            from_address: from.into(), to_address: to.into(),
            amounts: vec![Proto::Amount { denom: denom.into(), amount: "1000000000000000000".into() }], ..Default::default() }) }],
        tx_hasher: hasher, signer_info: signer, ..Default::default()
    };
    let d = TWDataHelper::create(serialize(&input).unwrap());
    let o = TWDataHelper::wrap(unsafe { tw_any_signer_sign(d.ptr(), coin as u32) }).to_vec().expect("null");
    let o: Proto::SigningOutput = deserialize(&o).unwrap();
    println!("BTVEC {name} coin={} err={:?} msg={} sig={} serialized={}", coin as u32, o.error, o.error_message, o.signature.to_hex(), o.serialized);
}

#[test]
fn bt_gen_ethermint() {
    // Addresses of KEY under each hrp are computed in-job by TWC itself (printed below) and used as from; to = from of the other key.
    let evmos_from = addr(CoinType::NativeEvmos); let canto_from = addr(CoinType::NativeCanto);
    gen("evmos_default", CoinType::NativeEvmos, &evmos_from, &evmos_from, "aevmos", "evmos_9001-2", None, Proto::TxHasher::UseDefault);
    gen("canto_default", CoinType::NativeCanto, &canto_from, &canto_from, "acanto", "canto_7700-1", None, Proto::TxHasher::UseDefault);
    gen("canto_ethermint", CoinType::NativeCanto, &canto_from, &canto_from, "acanto", "canto_7700-1",
        Some(Proto::SignerInfo { public_key_type: Proto::SignerPublicKeyType::Secp256k1, json_type: "ethermint/PubKeyEthSecp256k1".into(),
            protobuf_type: "/ethermint.crypto.v1.ethsecp256k1.PubKey".into() }), Proto::TxHasher::Keccak256);
}
fn addr(coin: CoinType) -> String {
    let pk = tw_keypair::tw::PrivateKey::new(KEY.decode_hex().unwrap()).unwrap();
    let a = tw_any_coin::any_address::AnyAddress::with_public_key(coin, pk.get_public_key_by_type(tw_keypair::tw::PublicKeyType::Secp256k1Extended).unwrap(), tw_coin_entry::derivation::Derivation::Default, None).unwrap();
    println!("BTADDR {} {}", coin as u32, a.description()); a.description().to_string()
}
