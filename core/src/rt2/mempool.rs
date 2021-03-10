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

use crate::ffi::dpdk::{self, MempoolPtr, SocketId};
use crate::ffi::AsStr;
use crate::{debug, info};
use anyhow::Result;
use std::fmt;

/// A memory pool is an allocator of message buffers, or `Mbuf`. For best
/// performance, each socket should have a dedicated `Mempool`. However,
/// for simplicity, we currently only support one global Mempool. Multi-
/// socket support may be added in the future.
pub(crate) struct Mempool {
    ptr: MempoolPtr,
}

impl Mempool {
    /// Creates a new `Mempool`.
    ///
    /// `capacity` is the maximum number of Mbufs in the pool. The optimum
    /// size (in terms of memory usage) is when n is a power of two minus one.
    ///
    /// `cache_size` is the per core cache size. If `cache_size` is non-zero,
    /// caching is enabled. New `Mbuf` will be retrieved first from cache,
    /// subsequently from the common pool. The cache can be disabled if
    /// `cache_size` is set to 0.
    ///
    /// # Errors
    ///
    /// Returns `DpdkError` if the mempool allocation fails.
    pub(crate) fn new<S: Into<String>>(
        name: S,
        capacity: usize,
        cache_size: usize,
    ) -> Result<Self> {
        let name: String = name.into();
        let ptr = dpdk::pktmbuf_pool_create(&name, capacity, cache_size, SocketId::current())?;

        info!(mempool = ?name, "pool created.");

        Ok(Self { ptr })
    }

    /// Returns the raw pointer.
    pub(crate) fn ptr_mut(&mut self) -> &mut MempoolPtr {
        &mut self.ptr
    }

    /// Returns the pool name.
    #[inline]
    pub(crate) fn name(&self) -> &str {
        self.ptr.name[..].as_str()
    }

    /// Returns the maximum number of Mbufs in the pool.
    #[inline]
    pub(crate) fn capacity(&self) -> usize {
        self.ptr.size as usize
    }

    /// Returns the per core cache size.
    #[inline]
    pub(crate) fn cache_size(&self) -> usize {
        self.ptr.cache_size as usize
    }

    /// Returns the socket the pool is allocated from.
    #[inline]
    pub(crate) fn socket(&self) -> SocketId {
        self.ptr.socket_id.into()
    }
}

impl fmt::Debug for Mempool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mempool")
            .field("name", &self.name())
            .field("capacity", &self.capacity())
            .field("cache_size", &self.cache_size())
            .field("socket", &self.socket())
            .finish()
    }
}

impl Drop for Mempool {
    fn drop(&mut self) {
        dpdk::mempool_free(&mut self.ptr);
        debug!(mempool = ?self.name(), "pool freed.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[capsule::test]
    fn create_mempool() -> Result<()> {
        let pool = Mempool::new("pool1", 15, 1)?;

        assert_eq!("pool1", pool.name());
        assert_eq!(15, pool.capacity());
        assert_eq!(1, pool.cache_size());

        Ok(())
    }

    #[capsule::test]
    fn drop_mempool() -> Result<()> {
        let name = "pool2";
        let pool = Mempool::new(name, 7, 0)?;

        let res = dpdk::mempool_lookup(name);
        assert!(res.is_ok());

        drop(pool);

        let res = dpdk::mempool_lookup(name);
        assert!(res.is_err());

        Ok(())
    }
}
