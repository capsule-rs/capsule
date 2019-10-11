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

impl fmt::Debug for Mbuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let raw = self.raw();
        f.debug_struct(&format!("mbuf@{:p}", raw.buf_addr))
            .field("buffer_len", &raw.buf_len)
            .field("packet_len", &raw.pkt_len)
            .field("data_len", &raw.data_len)
            .field("data_offset", &raw.data_off)
            .finish()
    }
}

impl Drop for Mbuf {
    fn drop(&mut self) {
        debug!("freeing mbuf@{:p}.", self.raw().buf_addr);

        unsafe {
            ffi::_rte_pktmbuf_free(self.raw_mut());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[nb2::test]
    fn allocate_new_mbuf() {
        assert!(Mbuf::new().is_ok());
    }
}
