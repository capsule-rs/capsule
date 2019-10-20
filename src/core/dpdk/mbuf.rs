/*
* Copyright 2019 Comcast Cable Communications Management, LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* SPDX-License-Identifier: Apache-2.0
*/

use crate::dpdk::MEMPOOL;
use crate::ffi::{self, ToResult};
use crate::Result;
use std::convert::From;
use std::fmt;
use std::ptr::NonNull;

/// A DPDK message buffer that carries the network packet.
///
/// # Remarks
///
/// Multi-segment Mbuf is not supported. It's the application's responsibilty
/// to ensure that the ethernet device's MTU is less than the default size
/// of a single Mbuf segment (`RTE_MBUF_DEFAULT_DATAROOM` = 2048).
pub struct Mbuf {
    raw: NonNull<ffi::rte_mbuf>,
}

impl Mbuf {
    /// Creates a new Mbuf.
    ///
    /// The Mbuf is allocated from the `Mempool` assigned to the current
    /// executing thread by the `Runtime`. The call will fail if invoked
    /// from a thread not managed by the `Runtime`.
    pub fn new() -> Result<Self> {
        let mempool = MEMPOOL.with(|tls| tls.get());
        let raw = unsafe { ffi::_rte_pktmbuf_alloc(mempool).to_result()? };
        Ok(raw.into())
    }

    /// Returns the raw struct needed for FFI calls.
    fn raw(&self) -> &ffi::rte_mbuf {
        unsafe { self.raw.as_ref() }
    }

    /// Returns the raw struct needed for FFI calls.
    fn raw_mut(&mut self) -> &mut ffi::rte_mbuf {
        unsafe { self.raw.as_mut() }
    }

    /// Acquires the underlying raw struct pointer.
    ///
    /// It is the caller's the responsibility to free the raw pointer after
    /// use. Otherwise the Mbuf is leaked.
    pub(crate) fn into_ptr(self) -> *mut ffi::rte_mbuf {
        let ptr = self.raw.as_ptr();
        std::mem::forget(self);
        ptr
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
        trace!("freeing mbuf@{:p}.", self.raw().buf_addr);

        unsafe {
            ffi::_rte_pktmbuf_free(self.raw_mut());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[capsule::test]
    fn allocate_new_mbuf() {
        assert!(Mbuf::new().is_ok());
    }
}
