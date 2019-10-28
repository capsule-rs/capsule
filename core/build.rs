// https://github.com/rust-lang/rust/issues/56306
// must statically link dpdk to the final binary, otherwise rustc
// will decide to not link functions not explicitly called but
// must be included in the final binary.

use std::env;

fn main() {
    let rte_sdk = env::var("RTE_SDK").expect("No RTE_SDK found ~ DPDK installation directory.");

    println!("cargo:rustc-link-search=native={}/build/lib", rte_sdk);
    // need to statically link the mempool ring driver for `cargo test`
    println!("cargo:rustc-link-lib=static=rte_mempool_ring");
    println!("cargo:rerun-if-env-changed=RTE_SDK");
}
