//! Generator, NOT part of the blocktools build. Copied into wallet-core adf80f8 as
//! rust/tw_tests/tests/bt_gen_cosmos23.rs by .github/workflows/twc-vectors.yml and run with
//! `cargo test -p tw_tests --test bt_gen_cosmos23 -- --nocapture`. Prints TWC's own MsgSend (SIGN_MODE_DIRECT) output
//! for the address-only Cosmos hrps, fixed inputs, TWC defaults otherwise (no signer_info override, default hasher).
//! Key: Trust Wallet Core public test vector (tests/chains/Cosmos/SignerTests.cpp), never a real key.
use tw_any_coin::ffi::tw_any_signer::tw_any_signer_sign;
use tw_coin_registry::coin_type::CoinType;
use tw_encoding::hex::{DecodeHex, ToHex};
use tw_memory::test_utils::tw_data_helper::TWDataHelper;
use tw_proto::Cosmos::Proto::{self, mod_Message::OneOfmessage_oneof as MessageEnum};
use tw_proto::{deserialize, serialize};

const KEY: &str = "80e81ea269e66a0a05b11236df7919fb7fbeedba87452d667489d7403a02f005"; // public test vector

// (name, coin id, chain_id, base denom)
const ROWS: &[(&str, u32, &str, &str)] = &[
    ("stride", 40000118, "stride-1", "ustrd"), ("axelar", 50000118, "axelar-dojo-1", "uaxl"), ("crescent", 60000118, "crescent-1", "ucre"),
    ("kujira", 70000118, "kaiyo-1", "ukuji"), ("comdex", 80000118, "comdex-1", "ucmdx"), ("neutron", 90000118, "neutron-1", "untrn"),
    ("sommelier", 11000118, "sommelier-3", "usomm"), ("fetchai", 12000118, "fetchhub-4", "afet"), ("mars", 13000118, "mars-1", "umars"),
    ("umee", 14000118, "umee-1", "uumee"), ("noble", 18000118, "noble-1", "uusdc"), ("sei", 19000118, "pacific-1", "usei"),
    ("celestia", 21000118, "celestia", "utia"), ("coreum", 10000990, "coreum-mainnet-1", "ucore"), ("quasar", 15000118, "quasar-1", "uqsr"),
    ("persistence", 16000118, "core-1", "uxprt"), ("akash", 17000118, "akashnet-2", "uakt"), ("kava", 459, "kava_2222-10", "ukava"),
    ("bluzelle", 483, "bluzelle-9", "ubnt"), ("band", 494, "laozi-mainnet", "uband"), ("agoric", 564, "agoric-3", "ubld"),
    ("dydx", 22000118, "dydx-mainnet-1", "adydx"), ("thorchain", 931, "thorchain-1", "rune"),
];

#[test]
fn bt_gen_cosmos23() {
    for &(name, id, chain_id, denom) in ROWS {
        let coin = match CoinType::try_from(id) { Ok(c) => c, Err(_) => { println!("BTVEC {name} coin={id} err=no_coin_type"); continue } };
        let pk = tw_keypair::tw::PrivateKey::new(KEY.decode_hex().unwrap()).unwrap();
        let from = match tw_any_coin::any_address::AnyAddress::with_public_key(coin, pk.get_public_key_by_type(tw_keypair::tw::PublicKeyType::Secp256k1).unwrap(), tw_coin_entry::derivation::Derivation::Default, None) {
            Ok(a) => a.description().to_string(), Err(e) => { println!("BTVEC {name} coin={id} err=addr {e:?}"); continue } };
        println!("BTADDR {id} {from}");
        let input = Proto::SigningInput {
            signing_mode: Proto::SigningMode::Protobuf, account_number: 1037, chain_id: chain_id.into(), sequence: 8,
            fee: Some(Proto::Fee { gas: 200000, amounts: vec![Proto::Amount { denom: denom.into(), amount: "200".into() }] }),
            private_key: KEY.decode_hex().unwrap().into(),
            messages: vec![Proto::Message { message_oneof: MessageEnum::send_coins_message(Proto::mod_Message::Send {
                from_address: from.clone().into(), to_address: from.clone().into(),
                amounts: vec![Proto::Amount { denom: denom.into(), amount: "1000".into() }], ..Default::default() }) }],
            ..Default::default()
        };
        let d = TWDataHelper::create(serialize(&input).unwrap());
        let o = TWDataHelper::wrap(unsafe { tw_any_signer_sign(d.ptr(), id) }).to_vec();
        let Some(o) = o else { println!("BTVEC {name} coin={id} err=null_output"); continue };
        let o: Proto::SigningOutput = deserialize(&o).unwrap();
        println!("BTVEC {name} coin={id} chain_id={chain_id} denom={denom} from={from} err={:?} msg={} sig={} serialized={}", o.error, o.error_message, o.signature.to_hex(), o.serialized);
    }
}
