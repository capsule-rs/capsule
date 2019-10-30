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

mod packet;
pub mod proptest;

pub mod byte_arrays {
    pub use crate::packets::icmp::v4::ICMPV4_PACKET;
    pub use crate::packets::icmp::v6::ICMPV6_PACKET;
    pub use crate::packets::ip::v6::{IPV6_PACKET, SRH_PACKET};
    pub use crate::packets::TCP_PACKET;
    pub use crate::packets::UDP_PACKET;
}

pub use self::packet::*;
pub use crate::dpdk::{Mempool, SocketId, MEMPOOL};

use crate::dpdk::eal_init;
use std::sync::Once;

static TEST_INIT: Once = Once::new();

/// Run once initialization of EAL for `cargo test`
pub fn cargo_test_init() {
    TEST_INIT.call_once(|| {
        eal_init(vec!["nb2_test".to_owned()]).unwrap();
    });
}
