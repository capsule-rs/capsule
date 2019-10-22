mod packet;
pub mod proptest;

pub use self::packet::*;

use crate::dpdk::eal_init;
use std::sync::Once;

static TEST_INIT: Once = Once::new();

/// Run once initialization of EAL for `cargo test`
pub fn cargo_test_init() {
    TEST_INIT.call_once(|| {
        eal_init(vec!["nb2_test".to_owned()]).unwrap();
    });
}
