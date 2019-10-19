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

use crate::dpdk::SocketId;
use crate::ffi::{self, AsStr, ToCString, ToResult};
use crate::Result;
use std::cell::Cell;
use std::fmt;
use std::os::raw;
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicUsize, Ordering};

// A global counter used to generate a unique name for new mempools.
static MEMPOOL_COUNT: AtomicUsize = AtomicUsize::new(0);

/// A memory pool is an allocator of message buffers, or `Mbuf`. For best
/// performance, each socket should have a dedicated `Mempool`.
pub struct Mempool {
    raw: NonNull<ffi::rte_mempool>,
}

impl Mempool {
    /// Creates a new `Mempool` for `Mbuf`.
    ///
    /// `capacity` is the maximum number of `Mbuf` the `Mempool` can hold.
    /// The optimum size (in terms of memory usage) is when n is a power
    /// of two minus one.
    ///
    /// `cache_size` is the per core object cache. If cache_size is non-zero,
    /// the library will try to limit the accesses to the common lockless
    /// pool. The cache can be disabled if the argument is set to 0.
    ///
    /// `socket_id` is the socket where the memory should be allocated. The
    /// value can be `SocketId::ANY` if there is no constraint.
    ///
    /// # Errors
    ///
    /// If allocation fails, then `DpdkError` is returned.
    pub fn new(capacity: usize, cache_size: usize, socket_id: SocketId) -> Result<Self> {
        let n = MEMPOOL_COUNT.fetch_add(1, Ordering::Relaxed);
        let name = format!("mempool{}", n).to_cstring();
        let raw = unsafe {
            ffi::rte_pktmbuf_pool_create(
                name.as_ptr(),
                capacity as raw::c_uint,
                cache_size as raw::c_uint,
                0,
                ffi::RTE_MBUF_DEFAULT_BUF_SIZE as u16,
                socket_id.raw(),
            )
            .to_result()?
        };

        Ok(Self { raw })
    }

    /// Returns the raw struct needed for FFI calls.
    #[inline]
    pub fn raw(&self) -> &ffi::rte_mempool {
        unsafe { self.raw.as_ref() }
    }

    /// Returns the raw struct needed for FFI calls.
    #[inline]
    pub fn raw_mut(&mut self) -> &mut ffi::rte_mempool {
        unsafe { self.raw.as_mut() }
    }

    /// Returns the name of the `Mempool`.
    #[inline]
    pub fn name(&self) -> &str {
        self.raw().name[..].as_str()
    }
}

impl fmt::Debug for Mempool {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let raw = self.raw();
        f.debug_struct(self.name())
            .field("capacity", &raw.size)
            .field("populated", &raw.populated_size)
            .field("cache_size", &raw.cache_size)
            .field("flags", &format_args!("{:#x}", raw.flags))
            .field("socket", &raw.socket_id)
            .finish()
    }
}

impl Drop for Mempool {
    fn drop(&mut self) {
        debug!("freeing {}.", self.name());

        unsafe {
            ffi::rte_mempool_free(self.raw_mut());
        }
    }
}

thread_local! {
    /// `Mempool` on the same socket as the current core.
    ///
    /// It's set when the core is first initialized. New `Mbuf` is allocated
    /// from this `Mempool` when executed on this core.
    pub static MEMPOOL: Cell<*mut ffi::rte_mempool> = Cell::new(ptr::null_mut());
}
