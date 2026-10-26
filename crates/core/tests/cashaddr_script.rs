//! bch CashAddr destinations map to the same output script as their legacy form.
//! Vectors: bitcoincashorg spec/cashaddr.md legacy-conversion table and examples.
use blocktools_core::chains::{address_to_script, chain};
use blocktools_core::validate::{validate, AddrKind};

const PAIRS: [(&str, &str); 3] = [
    ("1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu", "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"),
    ("1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR", "bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy"),
    ("3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC", "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq"),
];

#[test]
fn cashaddr_same_script_as_legacy() {
    let c = chain("bch").unwrap();
    for (l, ca) in PAIRS {
        let s = address_to_script(c, l).unwrap();
        assert_eq!(address_to_script(c, ca).as_ref(), Some(&s), "{ca}");
        assert_eq!(address_to_script(c, ca.strip_prefix("bitcoincash:").unwrap()).as_ref(), Some(&s), "bare {ca}");
        assert_eq!(address_to_script(c, &ca.to_ascii_uppercase()).as_ref(), Some(&s), "upper {ca}");
        assert_eq!(validate("bch", ca).unwrap(), if l.starts_with('3') { AddrKind::P2sh } else { AddrKind::P2pkh });
    }
}

#[test]
fn cashaddr_refusals() {
    let c = chain("bch").unwrap();
    for bad in [
        "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6b", // checksum
        "bitcoincash:Qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", // mixed case
        "bchtest:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",     // prefix is under the checksum
        "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t",     // valid testnet (spec example)
    ] {
        assert!(address_to_script(c, bad).is_none(), "{bad}");
        assert!(validate("bch", bad).is_err(), "{bad}");
    }
    assert!(address_to_script(chain("btc").unwrap(), PAIRS[0].1).is_none());
    assert!(validate("bsv", PAIRS[0].1).is_err());
}
