use crate::dpdk::rte;

pub struct MBuf {
    raw: *mut rte::rte_mbuf,
}

impl MBuf {
    pub unsafe fn new(raw: *mut rte::rte_mbuf) -> Self {
        MBuf { raw }
    }

    unsafe fn raw(&self) -> &mut rte::rte_mbuf {
        &mut (*self.raw)
    }

    pub unsafe fn raw_ptr(&self) -> *mut rte::rte_mbuf {
        self.raw
    }

    pub fn data_len(&self) -> u16 {
        unsafe { self.raw().data_len }
    }
}
