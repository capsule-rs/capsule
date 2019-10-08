use crate::dpdk::SocketId;
use crate::ffi::{self, AsStr, ToCString, ToResult};
use crate::Result;
use std::fmt;
use std::os::raw;
use std::ptr::NonNull;

pub struct Mempool {
    pool: NonNull<ffi::rte_mempool>,
}

impl Mempool {
    pub fn create(capacity: usize, cache_size: usize, socket_id: SocketId) -> Result<Self> {
        let name = format!("mempool{}", socket_id.0).to_cstring();
        let pool = unsafe {
            ffi::rte_pktmbuf_pool_create(
                name.as_ptr(),
                capacity as raw::c_uint,
                cache_size as raw::c_uint,
                0,
                ffi::RTE_MBUF_DEFAULT_BUF_SIZE as u16,
                socket_id.0 as raw::c_int,
            )
            .to_result()?
        };

        Ok(Self { pool })
    }

    pub fn pool(&self) -> &ffi::rte_mempool {
        unsafe { self.pool.as_ref() }
    }

    pub fn pool_mut(&mut self) -> &mut ffi::rte_mempool {
        unsafe { self.pool.as_mut() }
    }

    pub fn name(&self) -> &str {
        self.pool().name[..].as_str()
    }
}

impl fmt::Display for Mempool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pool = self.pool();
        write!(
            f,
            "{}: capacity={}, populated={}, cache_size={}, flags={:#x}, socket={}",
            self.name(),
            pool.size,
            pool.populated_size,
            pool.cache_size,
            pool.flags,
            pool.socket_id,
        )
    }
}

impl Drop for Mempool {
    fn drop(&mut self) {
        debug!("freeing {}.", self.name());

        unsafe {
            ffi::rte_mempool_free(self.pool_mut());
        }
    }
}
