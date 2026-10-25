//! KATs for the `secrets` feature, through the facade (public test vectors only).
use blocktools::secrets::seed::{readings, Reading};

#[test]
fn bip39_abandon_about_root() {
    let rs = readings(&("abandon ".repeat(11) + "about"), "");
    let Reading::Master { scheme, xprv, .. } = &rs[0] else { panic!("no master") };
    assert_eq!(*scheme, "bip39");
    assert_eq!(xprv.as_str(), "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu");
}
