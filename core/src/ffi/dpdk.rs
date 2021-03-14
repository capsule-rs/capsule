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

use super::{AsStr, EasyPtr, ToCString, ToResult};
use crate::net::MacAddr;
use crate::{debug, error};
use anyhow::Result;
use capsule_ffi as cffi;
use std::fmt;
use std::ops::DerefMut;
use std::os::raw;
use std::panic::{self, AssertUnwindSafe};
use std::ptr;
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

/// An opaque identifier for a logical execution unit of the processor.
#[derive(Copy, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct LcoreId(raw::c_uint);

impl LcoreId {
    /// Any lcore to indicate that no thread affinity is set.
    pub(crate) const ANY: Self = LcoreId(raw::c_uint::MAX);

    /// Returns the ID of the current execution unit or `LcoreId::ANY` when
    /// called from a non-EAL thread.
    #[inline]
    pub(crate) fn current() -> LcoreId {
        unsafe { LcoreId(cffi::_rte_lcore_id()) }
    }
}

impl fmt::Debug for LcoreId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "lcore{}", self.0)
    }
}

/// Gets the next enabled lcore ID.
pub(crate) fn get_next_lcore(
    id: Option<LcoreId>,
    skip_master: bool,
    wrap: bool,
) -> Option<LcoreId> {
    let (i, wrap) = match id {
        Some(id) => (id.0, wrap as raw::c_int),
        None => (raw::c_uint::MAX, 1),
    };

    let skip_master = skip_master as raw::c_int;

    match unsafe { cffi::rte_get_next_lcore(i, skip_master, wrap) } {
        cffi::RTE_MAX_LCORE => None,
        id @ _ => Some(LcoreId(id)),
    }
}

/// The function passed to `rte_eal_remote_launch`.
unsafe extern "C" fn lcore_fn<F>(arg: *mut raw::c_void) -> raw::c_int
where
    F: FnOnce() -> () + Send + 'static,
{
    let f = Box::from_raw(arg as *mut F);

    // in case the closure panics, let's not crash the app.
    let result = panic::catch_unwind(AssertUnwindSafe(f));

    if let Err(err) = result {
        error!(lcore = ?LcoreId::current(), error = ?err, "failed to execute closure.");
    }

    0
}

/// Launches a function on another lcore.
pub(crate) fn eal_remote_launch<F>(worker_id: LcoreId, f: F) -> Result<()>
where
    F: FnOnce() -> () + Send + 'static,
{
    let ptr = Box::into_raw(Box::new(f)) as *mut raw::c_void;

    unsafe {
        cffi::rte_eal_remote_launch(Some(lcore_fn::<F>), ptr, worker_id.0)
            .into_result(DpdkError::from_errno)
            .map(|_| ())
    }
}

/// An opaque identifier for a PMD device port.
#[derive(Copy, Clone)]
pub(crate) struct PortId(u16);

impl PortId {
    /// Returns the ID of the socket the port is connected to.
    #[inline]
    pub(crate) fn socket(self) -> SocketId {
        unsafe { cffi::rte_eth_dev_socket_id(self.0).into() }
    }
}

impl fmt::Debug for PortId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "port{}", self.0)
    }
}

/// Gets the port id from device name.
pub(crate) fn eth_dev_get_port_by_name<S: Into<String>>(name: S) -> Result<PortId> {
    let name: String = name.into();
    let mut port_id = 0u16;
    unsafe {
        cffi::rte_eth_dev_get_port_by_name(name.into_cstring().as_ptr(), &mut port_id)
            .into_result(DpdkError::from_errno)?;
    }
    Ok(PortId(port_id))
}

/// Retrieves the Ethernet address of a device.
pub(crate) fn eth_macaddr_get(port_id: PortId) -> Result<MacAddr> {
    let mut addr = cffi::rte_ether_addr::default();
    unsafe {
        cffi::rte_eth_macaddr_get(port_id.0, &mut addr).into_result(DpdkError::from_errno)?;
    }
    Ok(addr.addr_bytes.into())
}

/// Retrieves the contextual information of a device.
pub(crate) fn eth_dev_info_get(port_id: PortId) -> Result<cffi::rte_eth_dev_info> {
    let mut port_info = cffi::rte_eth_dev_info::default();
    unsafe {
        cffi::rte_eth_dev_info_get(port_id.0, &mut port_info).into_result(DpdkError::from_errno)?;
    }
    Ok(port_info)
}

/// Checks that numbers of Rx and Tx descriptors satisfy descriptors limits
/// from the ethernet device information, otherwise adjust them to boundaries.
pub(crate) fn eth_dev_adjust_nb_rx_tx_desc(
    port_id: PortId,
    nb_rx_desc: usize,
    nb_tx_desc: usize,
) -> Result<(usize, usize)> {
    let mut nb_rx_desc = nb_rx_desc as u16;
    let mut nb_tx_desc = nb_tx_desc as u16;

    unsafe {
        cffi::rte_eth_dev_adjust_nb_rx_tx_desc(port_id.0, &mut nb_rx_desc, &mut nb_tx_desc)
            .into_result(DpdkError::from_errno)?;
    }

    Ok((nb_rx_desc as usize, nb_tx_desc as usize))
}

/// Returns the value of promiscuous mode for a device.
pub(crate) fn eth_promiscuous_get(port_id: PortId) -> bool {
    match unsafe { cffi::rte_eth_promiscuous_get(port_id.0).into_result(DpdkError::from_errno) } {
        Ok(1) => true,
        // assuming port_id is valid, we treat error as mode disabled.
        _ => false,
    }
}

/// Enables receipt in promiscuous mode for a device.
pub(crate) fn eth_promiscuous_enable(port_id: PortId) -> Result<()> {
    unsafe {
        cffi::rte_eth_promiscuous_enable(port_id.0)
            .into_result(DpdkError::from_errno)
            .map(|_| ())
    }
}

/// Disables receipt in promiscuous mode for a device.
pub(crate) fn eth_promiscuous_disable(port_id: PortId) -> Result<()> {
    unsafe {
        cffi::rte_eth_promiscuous_disable(port_id.0)
            .into_result(DpdkError::from_errno)
            .map(|_| ())
    }
}

/// Returns the value of allmulticast mode for a device.
pub(crate) fn eth_allmulticast_get(port_id: PortId) -> bool {
    match unsafe { cffi::rte_eth_allmulticast_get(port_id.0).into_result(DpdkError::from_errno) } {
        Ok(1) => true,
        // assuming port_id is valid, we treat error as mode disabled.
        _ => false,
    }
}

/// Enables the receipt of any multicast frame by a device.
pub(crate) fn eth_allmulticast_enable(port_id: PortId) -> Result<()> {
    unsafe {
        cffi::rte_eth_allmulticast_enable(port_id.0)
            .into_result(DpdkError::from_errno)
            .map(|_| ())
    }
}

/// Disables the receipt of any multicast frame by a device.
pub(crate) fn eth_allmulticast_disable(port_id: PortId) -> Result<()> {
    unsafe {
        cffi::rte_eth_allmulticast_disable(port_id.0)
            .into_result(DpdkError::from_errno)
            .map(|_| ())
    }
}

/// Configures a device.
pub(crate) fn eth_dev_configure(
    port_id: PortId,
    nb_rx_queue: usize,
    nb_tx_queue: usize,
    eth_conf: &cffi::rte_eth_conf,
) -> Result<()> {
    unsafe {
        cffi::rte_eth_dev_configure(port_id.0, nb_rx_queue as u16, nb_tx_queue as u16, eth_conf)
            .into_result(DpdkError::from_errno)
            .map(|_| ())
    }
}

/// Allocates and sets up a receive queue for a device.
pub(crate) fn eth_rx_queue_setup(
    port_id: PortId,
    rx_queue_id: usize,
    nb_rx_desc: usize,
    socket_id: SocketId,
    rx_conf: Option<&cffi::rte_eth_rxconf>,
    mb_pool: &mut MempoolPtr,
) -> Result<()> {
    unsafe {
        cffi::rte_eth_rx_queue_setup(
            port_id.0,
            rx_queue_id as u16,
            nb_rx_desc as u16,
            socket_id.0 as raw::c_uint,
            rx_conf.map_or(ptr::null(), |conf| conf),
            mb_pool.deref_mut(),
        )
        .into_result(DpdkError::from_errno)
        .map(|_| ())
    }
}

/// Allocates and sets up a transmit queue for a device.
pub(crate) fn eth_tx_queue_setup(
    port_id: PortId,
    tx_queue_id: usize,
    nb_tx_desc: usize,
    socket_id: SocketId,
    tx_conf: Option<&cffi::rte_eth_txconf>,
) -> Result<()> {
    unsafe {
        cffi::rte_eth_tx_queue_setup(
            port_id.0,
            tx_queue_id as u16,
            nb_tx_desc as u16,
            socket_id.0 as raw::c_uint,
            tx_conf.map_or(ptr::null(), |conf| conf),
        )
        .into_result(DpdkError::from_errno)
        .map(|_| ())
    }
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
