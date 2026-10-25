//! Cardano KAT: public BIP39 vector "abandon x11 about"; expected Shelley base addresses
//! (m/1852'/1815'/0'/0/{0,1} + stake 2/0) from bip_utils 2.x CardanoShelley, the first one also
//! published in pycardano / CIP-1852 docs examples. Secrets stay in-test.
#![cfg(feature = "cardano")]
use blocktools_core::chains;
const M: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test] fn icarus_base_addresses() {
    let m = chains::ada_icarus_master(M, "").unwrap();
    let r = chains::ada_rows(&m, 2);
    assert_eq!(r[0].address, "addr1qy8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mq4afdhv");
    assert_eq!(r[1].address, "addr1qyz85693g4fr8c55mfyxhae8j2u04pydxrgqr73vmwpx3a8927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mqu2c0f9");
    assert_eq!(r[0].path, "m/1852'/1815'/0'/0/0");
    let v = |a: &str| blocktools_core::validate::validate("ada", a).is_ok();
    assert!(v(&r[0].address) && v("stake1u8j40zgr2gy4788kl54h6x3gu0pukq5lfr8nflufpg5dzaskqlx2l") == false);
    assert!(!v("addr1qy8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mq4afdhw"));
    assert!(!v("addr_test1qy8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mq4afdhv"));
}
