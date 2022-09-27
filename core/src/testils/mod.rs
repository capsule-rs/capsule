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

//! Utilities for unit tests and benchmarks.

pub mod byte_arrays;
pub mod criterion;
mod packet;
pub mod proptest;
mod rvg;

pub use self::packet::*;
pub use self::rvg::*;

use crate::ffi::dpdk::{self, SocketId};
use crate::runtime::{Mempool, MEMPOOL};
use std::ops::DerefMut;
use std::ptr;
use std::sync::Once;
use std::thread;

static TEST_INIT: Once = Once::new();

/// Run once initialization of EAL for `cargo test`.
pub fn cargo_test_init() {
    TEST_INIT.call_once(|| {
        dpdk::eal_init(vec![
            "capsule_test",
            "--master-lcore",
            "127",
            "--lcores",
            // 2 logical worker cores, pins master core to physical core 0
            "0,1,127@0",
            // allows tests to run without hugepages
            "--no-huge",
            // allows tests to run without root privilege
            "--iova-mode=va",
            "--vdev",
            // a null device for RX and TX tests
            "net_null0",
            "--vdev",
            // a ring-based device that can be used with assertions
            "net_ring0",
            "--vdev",
            // a TAP device for supported device feature tests
            "net_tap0",
        ])
        .unwrap();
    });
}

/// A RAII guard that keeps the mempool in scope for the duration of the
/// test. It will unset the thread-bound mempool on drop.
#[derive(Debug)]
pub struct MempoolGuard {
    _inner: Mempool,
}

impl Drop for MempoolGuard {
    fn drop(&mut self) {
        MEMPOOL.with(|tls| tls.replace(ptr::null_mut()));
    }
}

/// Creates a new mempool for test that automatically cleans up after the
/// test completes.
pub fn new_mempool(capacity: usize, cache_size: usize) -> MempoolGuard {
    let name = format!("test-mp-{:?}", thread::current().id());
    let mut mempool = Mempool::new(name, capacity, cache_size, SocketId::ANY).unwrap();
    MEMPOOL.with(|tls| tls.set(mempool.ptr_mut().deref_mut()));
    MempoolGuard { _inner: mempool }
}
