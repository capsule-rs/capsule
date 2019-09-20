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

extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-search=native=/opt/dpdk/build/lib");
    println!("cargo:rustc-link-lib=static=dpdk");
    println!("cargo:rustc-link-lib=dylib=numa");
    println!("cargo:rustc-link-lib=dylib=pcap");
    println!("cargo:rustc-link-lib=dylib=z");

    let bindings = bindgen::Builder::default()
        .header("src/dpdk/rte.h")
        .generate_comments(true)
        .generate_inline_functions(true)
        .whitelist_type(r"(rte|cmdline|ether|eth|arp|vlan|vxlan)_.*")
        .whitelist_function(r"(_rte|rte|cmdline|lcore|ether|eth|arp|is)_.*")
        .whitelist_var(
            r"(RTE|CMDLINE|ETHER|ARP|VXLAN|BONDING|LCORE|MEMPOOL|ARP|PKT|EXT_ATTACHED|IND_ATTACHED|lcore|rte|cmdline|per_lcore)_.*",
        )
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_partialeq(true)
        .default_enum_style(bindgen::EnumVariation::ModuleConsts)
        .clang_arg("-fkeep-inline-functions")
        .clang_arg("-I/opt/dpdk/build/include")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
