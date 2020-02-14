// current rust version tested: nightly-2019-10-28

// can be removed @ stable/newer versions
#![feature(result_map_or_else)]

use bindgen;
use cc;
#[cfg(feature = "build-kni")]
use libc;

#[cfg(feature = "build-kni")]
use std::{ffi::CStr, mem, os::raw::c_char, str::from_utf8_unchecked};

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(feature = "build-kni")]
#[inline]
fn to_str(bytes: &[c_char]) -> &str {
    unsafe { from_utf8_unchecked(CStr::from_ptr(bytes.as_ptr()).to_bytes()) }
}

fn nproc() -> usize {
    String::from_utf8(Command::new("nproc").output().unwrap().stdout)
        .unwrap()
        .trim()
        .parse::<usize>()
        .unwrap_or(1)
}

#[cfg(feature = "build-kni")]
#[inline]
fn uname() -> Result<libc::utsname, ()> {
    let mut uname = unsafe { mem::zeroed() };
    let res = unsafe { libc::uname(&mut uname) };
    if res < 0 {
        Err(())
    } else {
        Ok(uname)
    }
}

#[cfg(feature = "build-kni")]
fn is_kni_bound() -> bool {
    Command::new("sh")
        .arg("-c")
        .arg("lsmod | grep rte_kni")
        .output()
        .expect("Could not retrieve `lsmod`'s output!")
        .status
        .success()
}

#[cfg(feature = "build-kni")]
fn set_dpdk_kni(config: &str) {
    let sed_kni_librte = Command::new("sed")
        .arg("-i")
        .arg("-e")
        .arg("/^CONFIG_RTE_LIBRTE_KNI/d")
        .arg("-e")
        .arg("$ a CONFIG_RTE_LIBRTE_KNI=y")
        .arg(format!("../dpdk/config/defconfig_{}", config))
        .spawn()
        .expect("Failed to run `sed`!")
        .wait_with_output()
        .expect("Could not retrieve `sed`'s output")
        .status
        .success();

    let sed_kni = Command::new("sed")
        .arg("-i")
        .arg("-e")
        .arg("/^CONFIG_RTE_KNI_KMOD/d")
        .arg("-e")
        .arg("$ a CONFIG_RTE_KNI_KMOD=y")
        .arg(format!("../dpdk/config/defconfig_{}", config))
        .spawn()
        .expect("Failed to run `sed`!")
        .wait_with_output()
        .expect("Could not retrieve `sed`'s output")
        .status
        .success();

    if !(sed_kni_librte && sed_kni) {
        panic!("Configuration of kni was not successful!")
    }
}

#[cfg(feature = "build-pcap")]
fn set_dpdk_pcap(config: &str) {
    let sed_pcap_librte = Command::new("sed")
        .arg("-i")
        .arg("-e")
        .arg("/^CONFIG_RTE_LIBRTE_PMD_PCAP/d")
        .arg("-e")
        .arg("$ a CONFIG_RTE_LIBRTE_PMD_PCAP=y")
        .arg(format!("../dpdk/config/defconfig_{}", config))
        .spawn()
        .expect("Failed to run `sed`!")
        .wait_with_output()
        .expect("Could not retrieve `sed`'s output")
        .status
        .success();

    let sed_pcap = Command::new("sed")
        .arg("-i")
        .arg("-e")
        .arg("/^CONFIG_RTE_LIBRTE_PDUMP/d")
        .arg("-e")
        .arg("$ a CONFIG_RTE_LIBRTE_PDUMP=y")
        .arg(format!("../dpdk/config/defconfig_{}", config))
        .spawn()
        .expect("Failed to run `sed`!")
        .wait_with_output()
        .expect("Could not retrieve `sed`'s output")
        .status
        .success();

    if !(sed_pcap_librte && sed_pcap) {
        panic!("Configuration for pcap(s) was not successful!")
    }
}

/// in order to re-run this (i.e. for new module compilation), you could:
/// 1. cargo clean
/// 2. e.g. cargo build/run --features nb2/build-kni
fn build_dpdk(rte_sdk: &str) {
    let cflags =
        env::var("CFLAGS").unwrap_or_default() + " -g3 -Wno-error=maybe-uninitialized -fPIC";
    let config = env::var("DPDK_CONFIG").unwrap_or("x86_64-native-linuxapp-gcc".to_string());

    #[cfg(feature = "build-kni")]
    set_dpdk_kni(&config);

    #[cfg(feature = "build-pcap")]
    set_dpdk_pcap(&config);

    Command::new("make")
        .current_dir(Path::new("../dpdk"))
        .arg("config")
        .arg(format!("T={}", config))
        .arg(&format!("EXTRA_CFLAGS={}", cflags))
        .status()
        .expect("Couldn't configure dpdk for compilation!");

    Command::new("make")
        .current_dir(Path::new("../dpdk"))
        .args(&["-j", &format!("{}", nproc())])
        .arg("install")
        .arg(format!("T={}", config))
        .arg(&format!("DESTDIR={}/build", rte_sdk))
        .arg(&format!("EXTRA_CFLAGS={}", cflags))
        .status()
        .expect("Couldn't install dpdk!");
}

fn setup_dpdk() {
    let driver = env::var("DPDK_DRIVER").unwrap_or("uio_pci_generic".to_string());
    let devices_env = env::var("DPDK_DEVICES");

    // Note: no `lsmod` check here as uio_pci_generic is auto-loaded on some
    // systems, but not yet bound.
    if let Ok(devices) = devices_env {
        Command::new("python")
            .arg("../dpdk/usertools/dpdk-devbind.py")
            .arg("--force")
            .arg("-b")
            .arg(driver)
            .args(devices.split_whitespace())
            .status()
            .expect("Couldn't devbind driver to devices!");
    } else {
        println!(
            "Please make sure to run `dpdk-devbind` and bind devices to a DPDK-compatible driver"
        );
    }
}

fn make_dpdk(rte_sdk: &str) {
    build_dpdk(&rte_sdk);
    setup_dpdk();

    #[cfg(feature = "build-kni")]
    setup_kni(&rte_sdk);
}

#[cfg(feature = "build-kni")]
fn setup_kni(rte_sdk: &str) {
    if !is_kni_bound() {
        let insmod = Command::new("sudo")
            .arg("insmod")
            .arg(format!(
                "{}/build/lib/modules/{}/extra/dpdk/rte_kni.ko",
                rte_sdk,
                to_str(
                    &uname()
                        .expect("Can't find kernel version via `uname`")
                        .release
                )
            ))
            .output()
            .expect("Could not retrieve `insmod`'s output!")
            .status
            .success();

        if !insmod {
            panic!("Kmod module not inserted")
        }
    }
}

fn bind(path: &Path, rte_sdk: &str) {
    cc::Build::new()
        .file("src/shim.c")
        .include(format!("{}/build/include", rte_sdk))
        .include(format!("{}/build/include/dpdk", rte_sdk))
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
        .clang_arg("-finline-functions")
        .clang_arg(format!("-I/{}/build/include", rte_sdk))
        .clang_arg(format!("-I/{}/build/include/dpdk", rte_sdk))
        .rustfmt_bindings(true)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let rte_sdk = env::var("RTE_SDK").map_or_else(
        |_| {
            let dpdk_path = format!(
                "{}/dpdk",
                env::var("HOME").expect("Expecting a $HOME directory!")
            );

            make_dpdk(&dpdk_path);
            dpdk_path
        },
        |dpdk_path| {
            let dpdk_path_lib = PathBuf::from(&format!("{}/build/lib", dpdk_path));
            if !dpdk_path_lib.exists() || !dpdk_path_lib.join("libdpdk.a").exists() {
                make_dpdk(&dpdk_path);
            }
            dpdk_path
        },
    );

    // there's a problem statically linking to a linker script
    // see: https://github.com/rust-lang/rust/issues/40483
    println!("cargo:rustc-env=RTE_SDK={}", rte_sdk);
    println!("cargo:rustc-link-search=native={}/build/lib", rte_sdk);
    println!("cargo:rustc-link-lib=dylib=dpdk");
    println!("cargo:rustc-link-lib=dylib=numa");
    println!("cargo:rustc-link-lib=dylib=pcap");
    println!("cargo:rustc-link-lib=dylib=z");

    // re-run build.rs upon any of these changes
    println!("cargo:rerun-if-env-changed=RTE_SDK");
    println!("cargo:rerun-if-changed={}", rte_sdk);
    println!("cargo:rerun-if-env-changed=DPDK_CONFIG");
    println!("cargo:rerun-if-changed=../dpdk/config");
    println!("cargo:rerun-if-env-changed=DPDK_DEVICES");
    println!("cargo:rerun-if-changed=build.rs");

    bind(&out_path, &rte_sdk);
}
