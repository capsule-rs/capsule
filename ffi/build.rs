use bindgen;
use cc;
use std::env;
use std::path::{Path, PathBuf};

fn bind(path: &Path) {
    cc::Build::new()
        .file("src/shim.c")
        .include("/opt/dpdk/build/include")
        .flag("-march=native")
        .compile("rte_shim");

    bindgen::Builder::default()
        .header("src/bindings.h")
        .generate_comments(true)
        .generate_inline_functions(true)
        .whitelist_type(r"(rte|eth|ether|pcap)_.*")
        .whitelist_function(r"(_rte|rte|eth|ether|numa|pcap)_.*")
        .whitelist_var(r"(RTE|DEV|ETH|ETHER|MEMPOOL|PKT|rte)_.*")
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_partialeq(true)
        .default_enum_style(bindgen::EnumVariation::ModuleConsts)
        .clang_arg("-fkeep-inline-functions")
        .clang_arg("-I/opt/dpdk/build/include")
        .rustfmt_bindings(true)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let rte_sdk = env::var("RTE_SDK").expect("No RTE_SDK found ~ DPDK installation directory.");

    // there's a problem statically linking to a linker script
    // see: https://github.com/rust-lang/rust/issues/40483
    println!("cargo:rustc-link-search=native={}/build/lib", rte_sdk);
    println!("cargo:rustc-link-lib=dylib=dpdk");
    println!("cargo:rustc-link-lib=dylib=numa");
    println!("cargo:rustc-link-lib=dylib=pcap");
    println!("cargo:rustc-link-lib=dylib=z");

    bind(&out_path);
}
