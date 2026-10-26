//! finding:D1-1 (finding 1): a BCH CashAddr returned no candidates from address::detect (and so from detectAddress /
//! detectAddressInfo). Vector: CashAddr spec example, same hash as 1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu.
use blocktools::address::detect;
use blocktools_core::validate::AddrKind;
#[test]
fn cashaddr_detects_as_bch() {
    for a in ["bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", "BITCOINCASH:QPM2QSZNHKS23Z7629MMS6S4CWEF74VCWVY22GDX6A"] {
        assert_eq!(detect(a), vec![("bch", AddrKind::P2pkh)], "{a}");
    }
    assert!(detect("bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6b").is_empty(), "bad checksum must not detect");
}
