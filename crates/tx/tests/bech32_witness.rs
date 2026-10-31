//! Golden vectors for the keyless bech32 witness-program decode (`bech32_witness_program`) and for
//! the OP_RETURN payload field now emitted by the tx decoder (`Decoded::json_lines`). Public data only.
use blocktools_tx::{bech32_witness_program, decode};

#[test]
fn p2wpkh_bc1q() {
    // BIP173 P2WPKH example (segwit v0, bech32).
    let (ver, prog, words) = bech32_witness_program("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    assert_eq!(ver, 0);
    assert_eq!(blocktools_core::hex_enc(&prog), "751e76e8199196d454941c45d1b3a323f1433bd6");
    assert_eq!(
        blocktools_core::hex_enc(&words),
        "0e140f070d1a001912060b0d081504140311021d030c1d03040f1814060e1e16"
    );
    // `words` are the raw 5-bit data words after the version; regrouping 5->8 bits reproduces `program`.
    assert!(words.iter().all(|&w| w < 32));
}

#[test]
fn p2tr_bc1p() {
    // BIP350 P2TR example (taproot v1, bech32m).
    let (ver, prog, words) = bech32_witness_program("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0").unwrap();
    assert_eq!(ver, 1);
    assert_eq!(
        blocktools_core::hex_enc(&prog),
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );
    assert_eq!(
        blocktools_core::hex_enc(&words),
        "0f061f060c1f17191b121d1a18150d000c0a0a1c1d01180b001c0109171f061b0517070211160a191e0a001516051718021e0c00"
    );
    assert_eq!(words.len(), 52); // 32-byte program -> ceil(256/5) = 52 five-bit words
}

#[test]
fn rejects_non_bech32() {
    // A legacy base58 address is not a witness program.
    assert!(bech32_witness_program("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").is_err());
    assert!(bech32_witness_program("not-an-address").is_err());
    // Bad checksum (last char flipped).
    assert!(bech32_witness_program("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5").is_err());
}

#[test]
fn decode_tx_emits_op_return_payload() {
    // Minimal legacy tx: one input, one zero-value OP_RETURN output pushing 0xdeadbeef.
    //  version 01000000 | vin 01 | prevout 00..00 index 00000000 | scriptSig 00 | seq ffffffff
    //  vout 01 | value 0000000000000000 | spk 06 6a04deadbeef | locktime 00000000
    const RAW: &str = "010000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff010000000000000000066a04deadbeef00000000";
    let d = decode(RAW, "btc").unwrap();
    assert_eq!(d.outputs.len(), 1);
    assert_eq!(d.outputs[0].kind, "op_return");
    let lines = d.json_lines();
    let out = lines
        .iter()
        .find(|l| l["role"] == "output")
        .expect("an output line");
    assert_eq!(out["kind"], "op_return");
    assert_eq!(out["op_return"], "deadbeef");
}
