//! detect / convert / zec / sweep per tx format. Expected addresses come from
//! scripts/kat-chains.py (independent base58check, version bytes from each coin's source):
//! p2pkh of the secp256k1 generator G (pubkey of private key 1, a public test vector).
#[path = "../../tx/tests/common/mod.rs"]
mod common;
use blocktools::{address, chains, sweep::{build_unsigned_sweep, build_unsigned_sweep_at, build_unsigned_zec_sweep}, tx};
const KAT: &[(&str, &str)] = &[
    ("btc", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
    ("ltc", "LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ"),
    ("doge", "DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE"),
    ("qtum", "QXHFfTBKYXjaaTH1e7Rox8CcdNPGHVhM59"),
    ("ftc", "6pQiLg4eJbM2bP9CZemnccDzwB3kz2Ae1x"),
    ("nmc", "N7FdkoPbHSxKfrSVVbRu3NZtrLqc1oKpAR"),
    ("dash", "XmN7PQYWKn5MJFna5fRYgP6mxT2F7xpekE"),
    ("vtc", "Vkg6Ts44mskyD668xZkxFkjqovjXX9yUzZ"),
    ("dgb", "DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE"),
    ("via", "Vkg6Ts44mskyD668xZkxFkjqovjXX9yUzZ"),
    ("mona", "MJaRnao1s62a2zAKSkmG582KbLKianqb7v"),
    ("rvn", "RKxTdfmtxtfLDKZBgx6SvNkBtNu9jRYnLh"),
    ("xpm", "AST9CekEhDWuxHPynRmeyjg5biNFSijvb3"),
    ("trc", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
    ("mec", "MJaRnao1s62a2zAKSkmG582KbLKianqb7v"),
    ("aur", "AST9CekEhDWuxHPynRmeyjg5biNFSijvb3"),
    ("bch", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
    ("bsv", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
    ("btg", "GUXByHDZLvU4DnVH9imSFckt3HEQ5cFgE5"),
    ("ppc", "PKGSi8HTQzLx89rkZrRrVkPFjrcSC55NP9"),
    ("nvc", "4QP6S2Gv3WZmgnJgR8mshrbHA9W6hQiTxR"),
    ("clam", "xJyuT2j5dnLoBhHraFjzG2hmMDjnS3fefx"),
    ("blk", "BF8MAsLp7aSfb9g9qGSHwzDerit8nAZAJX"),
    ("rdd", "RjJ4cn5Bg58D2khGiNRmQW1yWtA6Py9kWa"),
    ("pot", "PKGSi8HTQzLx89rkZrRrVkPFjrcSC55NP9"),
    ("qrk", "QXHFfTBKYXjaaTH1e7Rox8CcdNPGHVhM59"),
    ("wdc", "WZMJS5eeCEgiqxNK1QRbE1HR4wFQwmCjJV"),
    ("anc", "AST9CekEhDWuxHPynRmeyjg5biNFSijvb3"),
    ("bcc", "8Rm8H7Fo9KCXs7hYfL74Z7K9TC5XnPGnWq"),
];
const ZEC_T1: &str = "t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs";
const ZEC_T3: &str = "t3VEtV2oBtHxjq7wKHJb3PHsqXHvMRgUmVw";
const BTC: &str = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";

#[test] fn convert_matches_independent_kats_for_every_verified_row() {
    let mut n = 0;
    for (c, want) in KAT {
        let row = chains::chain(c).unwrap();
        if row.verified { assert_eq!(address::convert(BTC, c).as_deref(), Ok(*want), "{c}"); n += 1;
                          assert_eq!(address::convert_from(c, want, "btc").as_deref(), Ok(BTC), "{c} back"); }
        else { assert_eq!(address::convert(BTC, c), Err("unknown_or_unverified_chain")) }
    }
    assert_eq!(n, 26);
}
#[test] fn detect_returns_every_candidate() {
    let names = |a: &str| { let mut v: Vec<_> = address::detect(a).into_iter().map(|x| x.0).collect(); v.sort(); v };
    let k = |c: &str| KAT.iter().find(|x| x.0 == c).unwrap().1;
    assert_eq!(names(k("doge")), ["dgb", "doge"]);          // version 30
    assert_eq!(names(k("vtc")), ["via", "vtc"]);            // version 71
    assert_eq!(names(BTC), ["bch", "bsv", "btc", "trc"]);   // version 0
    assert_eq!(names(k("mona")), ["ltc", "mec", "mona", "qtum"]); // 50: MONA/MEC p2pkh, LTC/QTUM p2sh
    assert_eq!(address::convert(k("mona"), "btc"), Err("ambiguous_address"));
    assert!(names(k("wdc")).is_empty());                    // unverified row: never a candidate
    assert_eq!(names(ZEC_T1), ["zec"]);
    assert_eq!(names("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), ["btc"]);
}
#[test] fn zec_transparent() {
    assert_eq!(address::validate("zec", ZEC_T1), Ok(address::AddrKind::P2pkh));
    assert_eq!(address::validate("zec", ZEC_T3), Ok(address::AddrKind::P2sh));
    assert!(address::validate("zec", BTC).is_err());
    assert_eq!(address::convert(BTC, "zec").as_deref(), Ok(ZEC_T1));
    assert_eq!(address::convert(ZEC_T1, "btc").as_deref(), Ok(BTC));
    assert_eq!(address::convert("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "zec"), Err("no_equivalent"));
    assert_eq!(address::convert("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "dash"), Err("no_equivalent"));
}
#[test] fn params_rows() {
    let p = address::params_json();
    let r = |n: &str| p.as_array().unwrap().iter().find(|r| r["name"] == n).unwrap().clone();
    assert_eq!(r("ppc")["decimals"], 6); assert_eq!(r("nvc")["decimals"], 6); assert_eq!(r("dash")["decimals"], 8); assert_eq!(r("qrk")["decimals"], 5);
    assert_eq!(r("btg")["forkid"], 79); assert_eq!(r("bsv")["tx_format"], "forkid"); assert_eq!(r("ppc")["tx_format"], "pos-ntime");
    assert_eq!(r("zec")["p2pkh"], serde_json::json!([0x1c, 0xb8])); assert_eq!(r("dash")["sweep_build"], true); assert_eq!(r("rdd")["sweep_build"], true); assert_eq!(r("pot")["sweep_build"], false);
}
fn utxo(c: &str) -> String {
    let a = address::convert(BTC, c).unwrap();
    common::line(chains::chain(c).unwrap(), 0, 100000, &a) // legacy inputs carry prev_tx (amount proof)
}
#[test] fn sweep_builds_legacy_and_forkid_and_decodes_back() {
    for c in ["dash", "dgb", "rvn", "vtc", "via", "qtum", "bsv", "mona", "btc", "doge"] {
        let to = KAT.iter().find(|x| x.0 == c).unwrap().1;
        let r = build_unsigned_sweep(c, &utxo(c), to, 10).unwrap_or_else(|e| panic!("{c}: {e}"));
        assert_eq!(r["fee"], "1930", "{c}"); assert_eq!(r["amount"], "98070", "{c}");
        let d = tx::decode(r["unsigned_tx"].as_str().unwrap(), c).unwrap();
        assert_eq!(d.outputs.len(), 1); assert_eq!(d.outputs[0].address.as_deref(), Some(to), "{c}");
        assert_eq!(d.outputs[0].amount, Some(98070));
        let d = tx::decode(r["psbt"].as_str().unwrap(), c).unwrap();
        assert_eq!(d.fee, Some(1930), "{c} psbt fee");
    }
}
#[test] fn grs_sweep_builds_and_decodes() {
    let to = "Fob4maNwBGVRPmMcRLS6qtTJfKeySAMsWq";
    let r = build_unsigned_sweep("grs", &utxo("grs"), to, 10).unwrap();
    assert_eq!(r["amount"], "98070");
    let d = tx::decode(r["unsigned_tx"].as_str().unwrap(), "grs").unwrap();
    assert_eq!(d.outputs[0].address.as_deref(), Some(to));
    let d = tx::decode(r["psbt"].as_str().unwrap(), "grs").unwrap();
    assert_eq!(d.fee, Some(1930));
}
#[test] fn pos_ntime_sweep_builds_and_decodes() {
    for (c, layout_end) in [("ppc", false), ("nvc", false), ("clam", false), ("rdd", true)] {
        let to = KAT.iter().find(|x| x.0 == c).map(|x| x.1).unwrap_or_else(|| panic!("{c} KAT"));
        let r = build_unsigned_sweep_at(c, &utxo(c), to, 10, 1792800000).unwrap();
        assert_eq!(r["tx_format"], "pos-ntime"); assert!(r.get("psbt").is_none());
        let raw = blocktools_core::hex_dec(r["unsigned_tx"].as_str().unwrap()).unwrap();
        let t = if layout_end { &raw[raw.len() - 4..] } else { &raw[4..8] };
        assert_eq!(u32::from_le_bytes(t.try_into().unwrap()), 1792800000, "{c} nTime position");
        let d = tx::decode(&r.to_string(), c).unwrap();
        assert_eq!(d.outputs[0].address.as_deref(), Some(to));
        assert_eq!(d.fee.map(|f| f.to_string()), r["fee"].as_str().map(String::from));
        assert_eq!(build_unsigned_sweep_at(c, &utxo(c), to, 10, 0).unwrap_err(), "pos_ntime_needs_time");
    }
    assert_eq!(address::tx_format("blk"), ("legacy", true));
}
#[test] fn zec_sweep_builds_and_decodes() {
    let u = format!(r#"{{"txid":"{}","vout":1,"amount":1000000,"address":"{ZEC_T1}"}}"#, "cc".repeat(32));
    let r = build_unsigned_sweep("zec", &u, ZEC_T1, 1).unwrap();
    assert_eq!(r["tx_format"], "zcash-v5"); assert!(r.get("psbt").is_none());
    assert_eq!(r["fee"], "10000"); // ZIP-317 minimum: 5000 * max(2, 1 action)
    let d = tx::decode(&r.to_string(), "zec").unwrap();
    assert_eq!(d.outputs[0].address.as_deref(), Some(ZEC_T1)); assert_eq!(d.fee, Some(10000));
    let r2 = build_unsigned_zec_sweep(&u, ZEC_T1, 1, 0xc2d6d0b4, 100).unwrap(); // other branch id, expiry set
    assert_eq!(r2["branch_id"], "c2d6d0b4"); assert_eq!(r2["expiry_height"], 100); assert_ne!(r2["unsigned_tx"], r["unsigned_tx"]);
    assert_eq!(address::tx_format("zec"), ("zcash-v5", true));
}
#[test] fn sweep_refuses_unsupported_formats() {
    for (c, why) in [("pot", "unsupported_tx_format:pos-ntime"), ("wdc", "unsupported_tx_format:legacy"),
                     ("eth", "unsupported_tx_format:evm")] {
        assert_eq!(build_unsigned_sweep(c, "", BTC, 10).unwrap_err(), why, "{c}");
    }
    // qrk: Bitcoin-legacy since 2026-10-25 (tx/tests/qrk.rs), 5 decimals.
    assert_eq!(address::tx_format("qrk"), ("legacy", true));
    let q = "QXHFfTBKYXjaaTH1e7Rox8CcdNPGHVhM59";
    let r = build_unsigned_sweep("qrk", &common::line(chains::chain("qrk").unwrap(), 0, 10000000, q), q, 10).unwrap();
    assert_eq!(r["tx_format"], "legacy");
    assert!(build_unsigned_sweep("dash", &utxo("btc"), BTC, 10).is_err()); // utxo address not a DASH address
}

/// BCH/BSV/BTG are NOT exempt from the prev_tx proof (decided 2026-10-25): their fork-id sighash commits
/// to the amount, but the builder, tx-decode/tx-verify and tx-sign all key on script type, so a plain
/// P2PKH line is refused like any legacy input. Same function backs the CLI and wasm buildUnsignedSweep.
#[test] fn forkid_needs_prev_tx() {
    for (c, a) in [("bch", BTC), ("bsv", BTC), ("btg", "GUXByHDZLvU4DnVH9imSFckt3HEQ5cFgE5")] {
        let plain = format!("{{\"txid\":\"{}\",\"vout\":0,\"amount\":100000,\"address\":\"{a}\"}}\n", "ab".repeat(32));
        assert!(build_unsigned_sweep(c, &plain, a, 10).unwrap_err().contains("legacy_input_needs_prev_tx"), "{c}");
        assert!(build_unsigned_sweep(c, &common::line(chains::chain(c).unwrap(), 0, 100000, a), a, 10).is_ok(), "{c}");
    }
}

#[test] fn table_params_no_drift() {
    // chainTable.buildable / coin_type / hrp must match chainParams.sweep_build / slip44 / hrp.
    let table: Vec<serde_json::Value> = serde_json::from_str(&chains::table_json()).unwrap();
    let params = address::params_json().as_array().unwrap().clone();
    for c in chains::CHAINS {
        let t = table.iter().find(|r| r["name"] == c.name).unwrap_or_else(|| panic!("table missing {}", c.name));
        let p = params.iter().find(|r| r["name"] == c.name).unwrap_or_else(|| panic!("params missing {}", c.name));
        assert_eq!(t["buildable"], p["sweep_build"], "{} buildable vs sweep_build", c.name);
        assert_eq!(t["coin_type"], p["slip44"], "{} coin_type vs slip44", c.name);
        // hrp: table embeds it only for utxo/cosmos encodings; params always has the key.
        if let Some(h) = t.get("hrp") { assert_eq!(h, &p["hrp"], "{} hrp", c.name); }
        else { assert!(p["hrp"].is_null(), "{} params hrp should be null when table omits it", c.name); }
        // And both equal Chain::tx_format / slip44.
        assert_eq!(p["sweep_build"], c.tx_format().1, "{} vs Chain::tx_format", c.name);
        assert_eq!(p["slip44"], serde_json::json!(c.slip44()), "{} vs Chain::slip44", c.name);
    }
    let atom_t = table.iter().find(|r| r["name"] == "atom").unwrap();
    let atom_p = params.iter().find(|r| r["name"] == "atom").unwrap();
    assert_eq!(atom_t["hrp"], "cosmos", "chainTable atom hrp");
    assert_eq!(atom_p["hrp"], "cosmos", "chainParams atom hrp");
    for name in ["wdc", "anc", "bcc"] {
        let trow = table.iter().find(|r| r["name"] == name).unwrap();
        let prow = params.iter().find(|r| r["name"] == name).unwrap();
        assert!(trow["coin_type"].is_null(), "{name} chainTable coin_type must be null (no SLIP-44)");
        assert!(prow["slip44"].is_null(), "{name} chainParams slip44 must be null (no SLIP-44)");
        assert_ne!(trow["coin_type"], 0, "{name} must not report coin_type 0");
    }
}
