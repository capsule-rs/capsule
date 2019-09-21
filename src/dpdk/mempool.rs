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
                println!("private data size: {}", (*ptr).private_data_size);
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

    pub(crate) fn as_mut(&mut self) -> &mut rte::rte_mempool {
        &mut self.pool
    }
}
