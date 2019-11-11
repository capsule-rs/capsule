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

mod kni;
mod mbuf;
mod mempool;
mod port;
#[cfg(feature = "metrics")]
mod stats;

pub use self::kni::*;
pub use self::mbuf::*;
pub use self::mempool::*;
pub use self::port::*;
#[cfg(feature = "metrics")]
pub use self::stats::*;

use crate::ffi::{self, AsStr, ToCString, ToResult};
use crate::net::MacAddr;
use crate::{debug, Result};
use failure::Fail;
use libc;
use std::fmt;
use std::mem;
use std::os::raw;

/// An error generated in `libdpdk`.
///
/// When a FFI call fails, the `errno` is translated into `DpdkError`.
#[derive(Debug, Fail)]
#[fail(display = "{}", _0)]
pub struct DpdkError(String);

impl DpdkError {
    /// Returns the `DpdkError` for the most recent failure on the current
    /// thread.
    #[inline]
    pub(crate) fn new() -> Self {
        let errno = unsafe { ffi::_rte_errno() };
        DpdkError::new_with_errno(errno)
    }

    /// Returns the `DpdkError` for a specific `errno`.
    #[inline]
    pub(crate) fn new_with_errno(errno: raw::c_int) -> Self {
        let msg = unsafe { ffi::rte_strerror(errno) };
        DpdkError(msg.as_str().into())
    }
}

/// An opaque identifier for a physical CPU socket.
///
/// A socket is also known as a NUMA node. On a multi-socket system, for best
/// performance, ensure that the cores and memory used for packet processing
/// are in the same socket as the network interface card.
#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub struct SocketId(raw::c_int);

impl SocketId {
    /// A socket ID representing any NUMA node.
    pub const ANY: Self = SocketId(-1);

    /// Returns the ID of the socket the current core is on.
    #[inline]
    pub fn current() -> SocketId {
        unsafe { SocketId(ffi::rte_socket_id() as raw::c_int) }
    }

    /// Returns all the socket IDs detected on the system.
    #[inline]
    pub fn all() -> Vec<SocketId> {
        unsafe {
            (0..ffi::rte_socket_count())
                .map(|idx| ffi::rte_socket_id_by_idx(idx))
                .filter(|&sid| sid != -1)
                .map(SocketId)
                .collect::<Vec<_>>()
        }
    }

    /// Returns the raw value needed for FFI calls.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    #[inline]
    pub(crate) fn raw(&self) -> raw::c_int {
        self.0
    }
}

impl fmt::Debug for SocketId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "socket{}", self.0)
    }
}

/// An opaque identifier for a physical CPU core.
#[derive(Copy, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CoreId(raw::c_uint);

impl CoreId {
    /// Creates a new CoreId from the numeric ID assigned to the core
    /// by the system.
    #[inline]
    pub(crate) fn new(i: usize) -> CoreId {
        CoreId(i as raw::c_uint)
    }

    /// Returns the ID of the current core.
    #[inline]
    pub fn current() -> CoreId {
        unsafe { CoreId(ffi::_rte_lcore_id()) }
    }

    /// Returns the ID of the socket the core is on.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    #[inline]
    pub fn socket_id(&self) -> SocketId {
        unsafe { SocketId(ffi::_rte_lcore_to_socket_id(self.0) as raw::c_int) }
    }

    /// Returns the raw value needed for FFI calls.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    #[inline]
    pub(crate) fn raw(&self) -> raw::c_uint {
        self.0
    }

    /// Sets the current thread's affinity to this core.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    #[inline]
    pub(crate) fn set_thread_affinity(&self) -> Result<()> {
        unsafe {
            // the two types that represent `cpu_set` have identical layout,
            // hence it is safe to transmute between them.
            let mut set: libc::cpu_set_t = mem::zeroed();
            libc::CPU_SET(self.0 as usize, &mut set);
            let mut set: ffi::rte_cpuset_t = mem::transmute(set);
            ffi::rte_thread_set_affinity(&mut set)
                .to_result()
                .map(|_| ())
        }
    }
}

impl fmt::Debug for CoreId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "core{}", self.0)
    }
}

/// Initializes the Environment Abstraction Layer (EAL).
pub fn eal_init(args: Vec<String>) -> Result<()> {
    debug!(arguments=?args);

    let len = args.len() as raw::c_int;
    let mut args = args
        .into_iter()
        .map(|s| s.to_cstring().into_raw())
        .collect::<Vec<_>>();

    let res = unsafe { ffi::rte_eal_init(len, args.as_mut_ptr()) };
    debug!("EAL parsed {} arguments.", res);

    // EAL does not take ownership of the raw pointers. we should reclaim them
    // to free properly. but if we do, they are actually double-freed somehow
    // and cause heap corruption. don't quite understand this.

    // args.into_iter().for_each(|p| unsafe {
    //     let _ = CString::from_raw(p);
    // });

    res.to_result().map(|_| ())
}

/// Cleans up the Environment Abstraction Layer (EAL).
pub fn eal_cleanup() -> Result<()> {
    unsafe { ffi::rte_eal_cleanup().to_result().map(|_| ()) }
}

/// Returns the `MacAddr` of a port.
fn eth_macaddr_get(port_id: u16) -> MacAddr {
    let mut addr = ffi::ether_addr::default();
    unsafe {
        ffi::rte_eth_macaddr_get(port_id, &mut addr);
    }
    addr.addr_bytes.into()
}
