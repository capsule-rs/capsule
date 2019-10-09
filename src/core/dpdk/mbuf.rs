use crate::dpdk::MEMPOOL;
use crate::ffi::{self, ToResult};
use crate::Result;
use std::convert::From;
use std::fmt;
use std::ptr::NonNull;

pub struct Mbuf {
    raw: NonNull<ffi::rte_mbuf>,
}

impl Mbuf {
    pub fn new() -> Result<Self> {
        let mempool = MEMPOOL.with(|tl| tl.get());
        let raw = unsafe { ffi::_rte_pktmbuf_alloc(mempool).to_result()? };
        Ok(raw.into())
    }

    fn raw(&self) -> &ffi::rte_mbuf {
        unsafe { self.raw.as_ref() }
    }

    fn raw_mut(&mut self) -> &mut ffi::rte_mbuf {
        unsafe { self.raw.as_mut() }
    }
}

impl From<NonNull<ffi::rte_mbuf>> for Mbuf {
    fn from(raw: NonNull<ffi::rte_mbuf>) -> Self {
        Mbuf { raw }
    }
}

impl fmt::Display for Mbuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let raw = self.raw();
        write!(
            f,
            "mbuf ({:p}): buffer_len={}, packet_len={}, data_len={}, data_offset={}",
            raw.buf_addr, raw.buf_len, raw.pkt_len, raw.data_len, raw.data_off,
        )
    }
}

impl Drop for Mbuf {
    fn drop(&mut self) {
        debug!("freeing mbuf ({:p}).", self.raw().buf_addr);

        unsafe {
            ffi::_rte_pktmbuf_free(self.raw_mut());
        }
    }
}
