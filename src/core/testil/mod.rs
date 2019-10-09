#![cfg(test)]

use crate::dpdk::eal_init;
use std::sync::Once;

static TEST_INIT: Once = Once::new();

/// Run once handle to initialize EAL for `cargo test`
pub fn cargo_test_init() {
    TEST_INIT.call_once(|| {
        eal_init(vec!["dpdk_test".to_owned()]).unwrap();
    });
}
