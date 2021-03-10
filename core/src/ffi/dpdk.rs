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

use capsule_ffi as cffi;

use super::{AsStr, EasyPtr, ToCString, ToResult};
use crate::debug;
use anyhow::Result;
use std::fmt;
use std::ops::DerefMut;
use std::os::raw;
use thiserror::Error;

/// Initializes the Environment Abstraction Layer (EAL).
pub(crate) fn eal_init<S: Into<String>>(args: Vec<S>) -> Result<()> {
    let args = args
        .into_iter()
        .map(|s| Into::<String>::into(s).into_cstring())
        .collect::<Vec<_>>();
    debug!(arguments=?args);

    let mut ptrs = args
        .iter()
        .map(|s| s.as_ptr() as *mut raw::c_char)
        .collect::<Vec<_>>();
    let len = ptrs.len() as raw::c_int;

    let parsed =
        unsafe { cffi::rte_eal_init(len, ptrs.as_mut_ptr()).into_result(DpdkError::from_errno)? };
    debug!("EAL parsed {} arguments.", parsed);

    Ok(())
}

/// Cleans up the Environment Abstraction Layer (EAL).
pub(crate) fn eal_cleanup() -> Result<()> {
    unsafe { cffi::rte_eal_cleanup() }
        .into_result(DpdkError::from_errno)
        .map(|_| ())
}

/// An opaque identifier for a physical CPU socket.
///
/// A socket is also known as a NUMA node. On a multi-socket system, for best
/// performance, ensure that the cores and memory used for packet processing
/// are in the same socket as the network interface card.
#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub(crate) struct SocketId(raw::c_int);

impl SocketId {
    /// A socket ID representing any NUMA socket.
    pub(crate) const ANY: Self = SocketId(-1);

    /// Returns the ID of the socket the current core is on.
    #[inline]
    pub(crate) fn current() -> SocketId {
        unsafe { SocketId(cffi::rte_socket_id() as raw::c_int) }
    }
}

impl fmt::Debug for SocketId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "socket{}", self.0)
    }
}

impl From<raw::c_int> for SocketId {
    fn from(id: raw::c_int) -> Self {
        SocketId(id)
    }
}

/// A `rte_mempool` pointer.
pub(crate) type MempoolPtr = EasyPtr<cffi::rte_mempool>;

/// Creates a mbuf pool.
pub(crate) fn pktmbuf_pool_create<S: Into<String>>(
    name: S,
    capacity: usize,
    cache_size: usize,
    socket_id: SocketId,
) -> Result<MempoolPtr> {
    let name: String = name.into();

    let ptr = unsafe {
        cffi::rte_pktmbuf_pool_create(
            name.into_cstring().as_ptr(),
            capacity as raw::c_uint,
            cache_size as raw::c_uint,
            0,
            cffi::RTE_MBUF_DEFAULT_BUF_SIZE as u16,
            socket_id.0,
        )
        .into_result(|_| DpdkError::new())?
    };

    Ok(EasyPtr(ptr))
}

/// Looks up a mempool by the name.
pub(crate) fn mempool_lookup<S: Into<String>>(name: S) -> Result<MempoolPtr> {
    let name: String = name.into();

    let ptr = unsafe {
        cffi::rte_mempool_lookup(name.into_cstring().as_ptr()).into_result(|_| DpdkError::new())?
    };

    Ok(EasyPtr(ptr))
}

/// Frees a mempool.
pub(crate) fn mempool_free(ptr: &mut MempoolPtr) {
    unsafe { cffi::rte_mempool_free(ptr.deref_mut()) };
}

/// An error generated in `libdpdk`.
///
/// When an FFI call fails, the `errno` is translated into `DpdkError`.
#[derive(Debug, Error)]
#[error("{0}")]
pub(crate) struct DpdkError(String);

impl DpdkError {
    /// Returns the `DpdkError` for the most recent failure on the current
    /// thread.
    #[inline]
    pub(crate) fn new() -> Self {
        DpdkError::from_errno(-1)
    }

    /// Returns the `DpdkError` for a specific `errno`.
    #[inline]
    fn from_errno(errno: raw::c_int) -> Self {
        let errno = if errno == -1 {
            unsafe { cffi::_rte_errno() }
        } else {
            -errno
        };
        DpdkError(unsafe { cffi::rte_strerror(errno).as_str().into() })
    }
}
