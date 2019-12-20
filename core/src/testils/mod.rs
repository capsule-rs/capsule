pub mod criterion;
mod packet;
pub mod proptest;
mod rvg;

pub mod byte_arrays {
    pub use crate::packets::icmp::v4::ICMPV4_PACKET;
    pub use crate::packets::icmp::v6::ICMPV6_PACKET;
    pub use crate::packets::ip::v6::{IPV6_PACKET, SRH_PACKET};
    pub use crate::packets::TCP_PACKET;
    pub use crate::packets::UDP_PACKET;
}

pub use self::packet::*;
pub use self::rvg::*;

use crate::dpdk::{self, Mempool, SocketId, MEMPOOL};
use crate::metrics;
use std::ptr;
use std::sync::Once;

static TEST_INIT: Once = Once::new();

/// Run once initialization of EAL for `cargo test`.
pub fn cargo_test_init() {
    TEST_INIT.call_once(|| {
        dpdk::eal_init(vec!["nb2_test".to_owned(), "--no-huge".to_owned()]).unwrap();
        let _ = metrics::init();
    });
}

/// A handle that keeps the mempool in scope for the duration of the test. It
/// will unset the thread-bound mempool on drop.
pub struct MempoolGuard {
    #[allow(dead_code)]
    inner: Mempool,
}

impl Drop for MempoolGuard {
    fn drop(&mut self) {
        MEMPOOL.with(|tls| tls.replace(ptr::null_mut()));
    }
}

/// Creates a new mempool for test that automatically cleans up after the
/// test completes.
pub fn new_mempool(capacity: usize, cache_size: usize) -> MempoolGuard {
    let mut mempool = Mempool::new(capacity, cache_size, SocketId::ANY).unwrap();
    MEMPOOL.with(|tls| tls.set(mempool.raw_mut()));
    MempoolGuard { inner: mempool }
}
