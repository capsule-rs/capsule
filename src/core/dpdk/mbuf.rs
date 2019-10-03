use crate::ffi;

pub struct MBuf {
    raw: *mut ffi::rte_mbuf,
}

impl MBuf {
    pub unsafe fn new(raw: *mut ffi::rte_mbuf) -> Self {
        MBuf { raw }
    }

    unsafe fn raw(&self) -> &mut ffi::rte_mbuf {
        &mut (*self.raw)
    }

    pub unsafe fn raw_ptr(&self) -> *mut ffi::rte_mbuf {
        self.raw
    }

    pub fn data_len(&self) -> u16 {
        unsafe { self.raw().data_len }
    }
}
