// https://github.com/rust-lang/rust/issues/56306
// must statically link dpdk to the final binary, otherwise rustc
// will decide to not link functions not explicitly called but
// must be included in the final binary.

fn main() {
    // need to statically link the mempool ring driver for `cargo test`
    println!("cargo:rustc-link-search=native=/opt/dpdk/build/lib");
    println!("cargo:rustc-link-lib=static=rte_mempool_ring");
}
