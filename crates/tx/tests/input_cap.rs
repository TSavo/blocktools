//! DESIGN: transaction input is limited to 4 MiB (MAX_INPUT). One byte over is too_large;
//! exactly 4 MiB is parsed (and fails for a different reason, since it is not a transaction).
use blocktools_tx::{input_bytes, MAX_INPUT};
#[test]
fn input_cap_is_4_mib() {
    assert_eq!(MAX_INPUT, 4 << 20);
    assert_eq!(input_bytes(&"0".repeat(MAX_INPUT + 1)), Err("too_large"));
    assert_ne!(input_bytes(&"0".repeat(MAX_INPUT)).err(), Some("too_large"));
}
