pub mod criterion;
mod packet;
pub mod proptest;
mod strategy_valgen;

pub mod byte_arrays {
    pub use crate::packets::icmp::v4::ICMPV4_PACKET;
    pub use crate::packets::icmp::v6::ICMPV6_PACKET;
    pub use crate::packets::ip::v6::{IPV6_PACKET, SRH_PACKET};
    pub use crate::packets::TCP_PACKET;
    pub use crate::packets::UDP_PACKET;
}

pub use self::packet::*;
pub use self::strategy_valgen::*;
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
