//! E2E/recipe fixture helper (not a user tool): prints one mock utxos.json line with a synthetic `prev_tx`
//! paying AMOUNT to ADDR, so offline examples exercise the legacy-input amount proof.
//!   cargo run --release -p blocktools-tx --example mock-utxo -- CHAIN VOUT AMOUNT ADDR
#[path = "../tests/common/mod.rs"]
#[allow(dead_code)]
mod common;
fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let c = blocktools_core::chains::chain(&a[0]).expect("chain");
    print!("{}", common::line(c, a[1].parse().unwrap(), a[2].parse().unwrap(), &a[3]));
}
