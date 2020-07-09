use crate::dpdk::SocketId;
use crate::ffi::{self, AsStr, ToCString, ToResult};
use std::ptr::NonNull;

const V4_MAX_DEPTH: u8 = 32;
const V6_MAX_DEPTH: u8 = 128;

struct LpmTable {
    name: String,
    table: NonNull<ffi::rte_lpm>,
}

struct LpmTableConfig {
    max_rules: u32,
    num_tables: u32,
    flags: u8,
    socket_id: u8,
}

impl LpmTable {
    #[inline]
    fn new_v4() {}
    fn new_v6() {}
}
