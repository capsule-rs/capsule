/*
* Copyright 2019 Comcast Cable Communications Management, LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* SPDX-License-Identifier: Apache-2.0
*/

#[cfg(not(feature = "rustdoc"))]
use std::env;
#[cfg(not(feature = "rustdoc"))]
use std::path::{Path, PathBuf};

#[cfg(not(feature = "rustdoc"))]
const RTE_CORE_LIBS: &[&str] = &[
    "rte_acl",
    "rte_bbdev",
    "rte_bitratestats",
    "rte_bpf",
    "rte_bus_dpaa",
    "rte_bus_fslmc",
    "rte_bus_ifpga",
    "rte_bus_pci",
    "rte_bus_vdev",
    "rte_bus_vmbus",
    "rte_cfgfile",
    "rte_cmdline",
    "rte_common_cpt",
    "rte_common_dpaax",
    "rte_common_octeontx",
    "rte_common_octeontx2",
    "rte_compressdev",
    "rte_cryptodev",
    "rte_distributor",
    "rte_eal",
    "rte_efd",
    "rte_ethdev",
    "rte_eventdev",
    "rte_fib",
    "rte_flow_classify",
    "rte_gro",
    "rte_gso",
    "rte_hash",
    "rte_ip_frag",
    "rte_ipsec",
    "rte_jobstats",
    "rte_kni",
    "rte_kvargs",
    "rte_latencystats",
    "rte_lpm",
    "rte_mbuf",
    "rte_member",
    "rte_mempool",
    "rte_mempool_bucket",
    "rte_mempool_dpaa",
    "rte_mempool_dpaa2",
    "rte_mempool_octeontx",
    "rte_mempool_octeontx2",
    "rte_mempool_ring",
    "rte_mempool_stack",
    "rte_meter",
    "rte_metrics",
    "rte_net",
    "rte_pci",
    "rte_pdump",
    "rte_pipeline",
    "rte_port",
    "rte_power",
    "rte_rawdev",
    "rte_rawdev_dpaa2_cmdif",
    "rte_rawdev_dpaa2_qdma",
    // "rte_rawdev_ioat",
    "rte_rawdev_ntb",
    "rte_rawdev_octeontx2_dma",
    "rte_rawdev_skeleton",
    "rte_rcu",
    "rte_reorder",
    "rte_rib",
    "rte_ring",
    "rte_sched",
    "rte_security",
    "rte_stack",
    "rte_table",
    "rte_timer",
    "rte_vhost",
];

#[cfg(not(feature = "rustdoc"))]
static RTE_PMD_LIBS: &[&str] = &[
    "rte_pmd_af_packet",
    "rte_pmd_ark",
    "rte_pmd_atlantic",
    "rte_pmd_avp",
    "rte_pmd_axgbe",
    "rte_pmd_bbdev_fpga_lte_fec",
    "rte_pmd_bbdev_null",
    "rte_pmd_bbdev_turbo_sw",
    "rte_pmd_bnxt",
    "rte_pmd_bond",
    "rte_pmd_caam_jr",
    "rte_pmd_crypto_scheduler",
    "rte_pmd_cxgbe",
    "rte_pmd_dpaa",
    "rte_pmd_dpaa2",
    "rte_pmd_dpaa2_event",
    "rte_pmd_dpaa2_sec",
    "rte_pmd_dpaa_event",
    "rte_pmd_dpaa_sec",
    "rte_pmd_dsw_event",
    "rte_pmd_e1000",
    "rte_pmd_ena",
    "rte_pmd_enetc",
    "rte_pmd_enic",
    "rte_pmd_failsafe",
    "rte_pmd_fm10k",
    "rte_pmd_hinic",
    "rte_pmd_hns3",
    "rte_pmd_i40e",
    "rte_pmd_iavf",
    "rte_pmd_ice",
    "rte_pmd_ifc",
    "rte_pmd_ixgbe",
    "rte_pmd_kni",
    "rte_pmd_liquidio",
    "rte_pmd_memif",
    "rte_pmd_netvsc",
    "rte_pmd_nfp",
    "rte_pmd_nitrox",
    "rte_pmd_null",
    "rte_pmd_null_crypto",
    "rte_pmd_octeontx",
    "rte_pmd_octeontx2",
    "rte_pmd_octeontx2_crypto",
    "rte_pmd_octeontx2_event",
    "rte_pmd_octeontx_compress",
    "rte_pmd_octeontx_crypto",
    "rte_pmd_octeontx_event",
    "rte_pmd_opdl_event",
    "rte_pmd_pcap",
    "rte_pmd_pfe",
    "rte_pmd_qat",
    "rte_pmd_qede",
    "rte_pmd_ring",
    // "rte_pmd_sfc",
    "rte_pmd_skeleton_event",
    "rte_pmd_softnic",
    "rte_pmd_sw_event",
    "rte_pmd_tap",
    "rte_pmd_thunderx",
    "rte_pmd_vdev_netvsc",
    "rte_pmd_vhost",
    "rte_pmd_virtio",
    "rte_pmd_virtio_crypto",
    "rte_pmd_vmxnet3",
];

#[cfg(not(feature = "rustdoc"))]
const RTE_DEPS_LIBS: &[&str] = &["numa", "pcap"];
#[cfg(not(feature = "rustdoc"))]
fn march_flag() -> &'static str {
    let target = std::env::var("TARGET").unwrap();
    if target.starts_with("x86_64") {
        "-march=corei7-avx"
    } else if target.starts_with("aarch") {
        "-march=armv8-a"
    } else {
        "-march=native"
    }
}
#[cfg(not(feature = "rustdoc"))]
fn bind(path: &Path) {
    cc::Build::new()
        .file("src/shim.c")
        .flag(march_flag())
        .compile("rte_shim");

    bindgen::Builder::default()
        .header("src/bindings.h")
        .generate_comments(true)
        .generate_inline_functions(true)
        // treat as opaque as per issue w/ combining align/packed:
        // https://github.com/rust-lang/rust-bindgen/issues/1538
        .opaque_type(r"rte_arp_ipv4|rte_arp_hdr")
        .whitelist_type(r"(rte|eth|pcap)_.*")
        .whitelist_function(r"(_rte|rte|eth|numa|pcap)_.*")
        .whitelist_var(r"(RTE|DEV|ETH|MEMPOOL|PKT|rte)_.*")
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_partialeq(true)
        .default_enum_style(bindgen::EnumVariation::ModuleConsts)
        .clang_arg("-finline-functions")
        .clang_arg(march_flag())
        .rustfmt_bindings(true)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

#[cfg(not(feature = "rustdoc"))]
fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    bind(&out_path);

    RTE_CORE_LIBS
        .iter()
        .chain(RTE_PMD_LIBS)
        .chain(RTE_DEPS_LIBS)
        .for_each(|lib| println!("cargo:rustc-link-lib=dylib={}", lib));

    // re-run build.rs upon changes
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/");
}

// Skip the build script on docs.rs
#[cfg(feature = "rustdoc")]
fn main() {}
