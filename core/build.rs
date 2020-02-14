fn main() {
    // need to statically link the mempool ring driver for `cargo test`
    println!("cargo:rustc-link-lib=static=rte_mempool_ring");
}
