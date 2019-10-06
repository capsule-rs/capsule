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

    fn pool(&self) -> &ffi::rte_mempool {
        unsafe { self.pool.as_ref() }
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
            "name: {}, capacity: {}, populated: {}, cache_size: {}, flags: {}, socket: {}",
            self.name(),
            pool.size,
            pool.populated_size,
            pool.cache_size,
            pool.flags,
            pool.socket_id,
        )
    }
}
