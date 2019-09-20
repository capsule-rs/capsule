use crate::dpdk::rte;
use failure::{format_err, Error};
use std::ffi::{CStr, CString};
use std::os::raw;

pub struct Mempool {
    pool: rte::rte_mempool,
}

impl Mempool {
    pub fn create(name: &str, size: usize, cache_size: usize) -> Result<Self, Error> {
        unsafe {
            let socket_id = rte::rte_socket_id();
            let ptr = rte::rte_pktmbuf_pool_create(
                CString::from_vec_unchecked(name.into()).as_ptr(),
                size as raw::c_uint,
                cache_size as raw::c_uint,
                0,
                rte::RTE_MBUF_DEFAULT_BUF_SIZE as u16,
                socket_id as raw::c_int,
            );

            if ptr.is_null() {
                Err(format_err!("Cannot create mbuf pool."))
            } else {
                Ok(Self { pool: *ptr })
            }
        }
    }

    pub fn name(&self) -> &str {
        unsafe {
            CStr::from_ptr(self.pool.name[..].as_ptr())
                .to_str()
                .unwrap_or("unknown")
        }
    }
}
