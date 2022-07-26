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

#![warn(
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    unreachable_pub
)]
#![deny(broken_intra_doc_links)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/capsule/0.1.5")]

//! A framework for network function development. Written in Rust, inspired by
//! [NetBricks] and built on Intel's [Data Plane Development Kit].
//!
//! The goal of Capsule is to offer an ergonomic framework for network function
//! development that traditionally has high barriers of entry for developers.
//! We've created a tool to efficiently manipulate network packets while being
//! type-safe, memory-safe, and thread-safe. Building on DPDK and Rust, Capsule
//! offers:
//!
//! * a fast packet processor that uses minimum number of CPU cycles.
//! * a rich packet type system that guarantees memory-safety and thread-safety.
//! * a declarative programming model that emphasizes simplicity.
//! * an extensible and testable framework that is easy to develop and maintain.
//!
//! ## Getting started
//!
//! The easiest way to start developing Capsule applications is to use the
//! `Vagrant` [virtual machine] and the `Docker` [sandbox] provided by the
//! Capsule team. The sandbox is preconfigured with all the necessary tools and
//! libraries for Capsule development, including:
//!
//! * [DPDK 19.11]
//! * [Clang] and [LLVM]
//! * [Rust 1.50]
//! * [rr] 5.3
//!
//! For more information on getting started, please check out Capsule's
//! [README], as well as our [sandbox repo] for developer environments.
//!
//! ### Adding Capsule as a Cargo dependency
//!
//! ```toml
//! [dependencies]
//! capsule = "0.1"
//! ```
//!
//! ### Using features
//!
//! To enable test/bench features for example, you can include Capsule in your
//! Cargo dependencies with the `testils` feature flag:
//!
//! ```toml
//! [dev-dependencies]
//! capsule = { version = "0.1", features = ["testils"] }
//! ```
//!
//! Or, to enable the capturing of port traffic to `pcap` files
//! automatically per-port, per-core, you can run a Capsule application with the
//! `pcap-dump` feature flag turned on:
//!
//! ```shell
//! cargo run --features capsule/pcap-dump -- -f capsule-app.toml
//! ```
//!
//! ## Feature flags
//!
//! - `default`: None of the features are enabled.
//! - `pcap-dump`: Enables capturing port traffic to `pcap` files.
//! - `testils`: Enables utilities for unit testing and benchmarking.
//! - `full`: Enables all features.
//!
//! ### Examples
//!
//! - [kni]: Kernel NIC interface example.
//! - [nat64]: IPv6 to IPv4 NAT gateway example.
//! - [ping4d]: Ping4 daemon example.
//! - [pktdump]: Packet dump example.
//! - [skeleton]: Base skeleton example.
//! - [syn-flood]: TCP SYN flood example.
//!
//! [NetBricks]: https://www.usenix.org/system/files/conference/osdi16/osdi16-panda.pdf
//! [Data Plane Development Kit]: https://www.dpdk.org/
//! [virtual machine]: https://github.com/capsule-rs/sandbox/blob/master/Vagrantfile
//! [sandbox]: https://hub.docker.com/repository/docker/getcapsule/sandbox
//! [DPDK 19.11]: https://doc.dpdk.org/guides-19.11/rel_notes/release_19_11.html
//! [Clang]: https://clang.llvm.org/
//! [LLVM]: https://www.llvm.org/
//! [Rust 1.50]: https://blog.rust-lang.org/2021/02/11/Rust-1.50.0.html
//! [rr]: https://rr-project.org/
//! [README]: https://github.com/capsule-rs/capsule/blob/master/README.md
//! [sandbox repo]: https://github.com/capsule-rs/sandbox
//! [kni]: https://github.com/capsule-rs/capsule/tree/master/examples/kni
//! [nat64]: https://github.com/capsule-rs/capsule/tree/master/examples/nat64
//! [ping4d]: https://github.com/capsule-rs/capsule/tree/master/examples/ping4d
//! [pktdump]: https://github.com/capsule-rs/capsule/tree/master/examples/pktdump
//! [skeleton]: https://github.com/capsule-rs/capsule/tree/master/examples/skeleton
//! [syn-flood]: https://github.com/capsule-rs/capsule/tree/master/examples/syn-flood

// alias for the macros
extern crate self as capsule;

pub(crate) mod ffi;
mod macros;
pub mod net;
pub mod packets;
pub mod runtime;
#[cfg(any(test, feature = "testils"))]
#[cfg_attr(docsrs, doc(cfg(feature = "testils")))]
pub mod testils;

#[cfg(any(test, feature = "testils"))]
#[cfg_attr(docsrs, doc(cfg(feature = "testils")))]
pub use capsule_macros::{bench, test};
