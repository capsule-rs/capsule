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

use super::{Mbuf, PortId};
use crate::dpdk::DpdkError;
use crate::ffi::{self, AsStr, ToResult};

#[cfg(feature = "metrics")]
use crate::metrics::{labels, Counter, SINK};
use crate::net::MacAddr;
use crate::{debug, error, warn};
use failure::{Fail, Fallible};
use futures::{future, Future, StreamExt};
use std::cmp;
use std::mem;
use std::os::raw;
use std::ptr::{self, NonNull};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

/// Creates a new KNI counter.
#[cfg(feature = "metrics")]
fn new_counter(name: &'static str, kni: &str, dir: &'static str) -> Counter {
    SINK.scoped("kni").counter_with_labels(
        name,
        labels!(
            "kni" => kni.to_string(),
            "dir" => dir,
        ),
    )
}

/// The KNI receive handle. Because the underlying interface is single
/// threaded, we must ensure that only one rx handle is created for each
/// interface.
#[allow(missing_debug_implementations)]
pub struct KniRx {
    raw: NonNull<ffi::rte_kni>,
    #[cfg(feature = "metrics")]
    packets: Counter,
    #[cfg(feature = "metrics")]
    octets: Counter,
}

impl KniRx {
    /// Creates a new `KniRx`.
    #[cfg(not(feature = "metrics"))]
    pub fn new(raw: NonNull<ffi::rte_kni>) -> Self {
        KniRx { raw }
    }

    /// Creates a new `KniRx`.
    #[cfg(feature = "metrics")]
    pub fn new(raw: NonNull<ffi::rte_kni>) -> Self {
        let name = unsafe { ffi::rte_kni_get_name(raw.as_ref()).as_str().to_owned() };
        let packets = new_counter("packets", &name, "rx");
        let octets = new_counter("octets", &name, "rx");
        KniRx {
            raw,
            packets,
            octets,
        }
    }

    /// Receives a burst of packets from the kernel, up to a maximum of
    /// **32** packets.
    pub fn receive(&mut self) -> Vec<Mbuf> {
        const RX_BURST_MAX: usize = 32;
        let mut ptrs = Vec::with_capacity(RX_BURST_MAX);

        let len = unsafe {
            ffi::rte_kni_rx_burst(
                self.raw.as_mut(),
                ptrs.as_mut_ptr(),
                RX_BURST_MAX as raw::c_uint,
            )
        };

        let mbufs = unsafe {
            ptrs.set_len(len as usize);
            ptrs.into_iter()
                .map(|ptr| Mbuf::from_ptr(ptr))
                .collect::<Vec<_>>()
        };

        unsafe {
            // checks if there are any link change requests, and handle them.
            if let Err(err) =
                ffi::rte_kni_handle_request(self.raw.as_mut()).to_result(|_| DpdkError::new())
            {
                warn!(message = "failed to handle change link requests.", ?err);
            }
        }

        #[cfg(feature = "metrics")]
        {
            self.packets.record(mbufs.len() as u64);

            let bytes: usize = mbufs.iter().map(Mbuf::data_len).sum();
            self.octets.record(bytes as u64);
        }

        mbufs
    }
}

/// In memory queue for the cores to deliver packets that are destined for
/// the kernel. Then another pipeline will collect these and forward them
/// on in a thread safe way.
#[allow(missing_debug_implementations)]
#[derive(Clone)]
pub struct KniTxQueue {
    tx_enque: UnboundedSender<Vec<Mbuf>>,
}

impl KniTxQueue {
    /// Transmits packets to the KNI tx queue.
    pub fn transmit(&mut self, packets: Vec<Mbuf>) {
        if let Err(err) = self.tx_enque.try_send(packets) {
            warn!(message = "failed to send to kni tx queue.");
            Mbuf::free_bulk(err.into_inner());
        }
    }
}

/// The KNI transmit handle. Because the underlying interface is single
/// threaded, we must ensure that only one tx handle is created for each
/// interface.
pub(crate) struct KniTx {
    raw: NonNull<ffi::rte_kni>,
    tx_deque: Option<UnboundedReceiver<Vec<Mbuf>>>,
    #[cfg(feature = "metrics")]
    packets: Counter,
    #[cfg(feature = "metrics")]
    octets: Counter,
    #[cfg(feature = "metrics")]
    dropped: Counter,
}

impl KniTx {
    /// Creates a new `KniTx`.
    #[cfg(not(feature = "metrics"))]
    pub(crate) fn new(raw: NonNull<ffi::rte_kni>, tx_deque: UnboundedReceiver<Vec<Mbuf>>) -> Self {
        KniTx {
            raw,
            tx_deque: Some(tx_deque),
        }
    }

    /// Creates a new `KniTx` with stats.
    #[cfg(feature = "metrics")]
    pub(crate) fn new(raw: NonNull<ffi::rte_kni>, tx_deque: UnboundedReceiver<Vec<Mbuf>>) -> Self {
        let name = unsafe { ffi::rte_kni_get_name(raw.as_ref()).as_str().to_owned() };
        let packets = new_counter("packets", &name, "tx");
        let octets = new_counter("octets", &name, "tx");
        let dropped = new_counter("dropped", &name, "tx");
        KniTx {
            raw,
            tx_deque: Some(tx_deque),
            packets,
            octets,
            dropped,
        }
    }

    /// Sends the packets to the kernel.
    pub(crate) fn transmit(&mut self, packets: Vec<Mbuf>) {
        let mut ptrs = packets.into_iter().map(Mbuf::into_ptr).collect::<Vec<_>>();

        loop {
            let to_send = ptrs.len() as raw::c_uint;
            let sent =
                unsafe { ffi::rte_kni_tx_burst(self.raw.as_mut(), ptrs.as_mut_ptr(), to_send) };

            if sent > 0 {
                #[cfg(feature = "metrics")]
                {
                    self.packets.record(sent as u64);

                    let bytes: u64 = ptrs[..sent as usize]
                        .iter()
                        .map(|&ptr| unsafe { (*ptr).data_len as u64 })
                        .sum();
                    self.octets.record(bytes);
                }

                if to_send - sent > 0 {
                    // still have packets not sent. tx queue is full but still making
                    // progress. we will keep trying until all packets are sent. drains
                    // the ones already sent first and try again on the rest.
                    let _ = ptrs.drain(..sent as usize);
                } else {
                    break;
                }
            } else {
                // tx queue is full and we can't make progress, start dropping packets
                // to avoid potentially stuck in an endless loop.
                #[cfg(feature = "metrics")]
                self.dropped.record(to_send as u64);

                super::mbuf_free_bulk(ptrs);
                break;
            }
        }
    }

    /// Converts the TX handle into a spawnable pipeline.
    pub(crate) fn into_pipeline(mut self) -> impl Future<Output = ()> {
        self.tx_deque.take().unwrap().for_each(move |packets| {
            self.transmit(packets);
            future::ready(())
        })
    }
}

// we need to send tx and rx across threads to run them.
unsafe impl Send for KniRx {}
unsafe impl Send for KniTx {}

/// KNI errors.
#[derive(Debug, Fail)]
pub(crate) enum KniError {
    #[fail(display = "KNI is not enabled for the port.")]
    Disabled,

    #[fail(display = "Another core owns the handle.")]
    NotAcquired,
}

/// Kernel NIC interface. This allows the DPDK application to exchange
/// packets with the kernel networking stack.
///
/// The DPDK implementation is single-threaded TX and RX. Only one thread
/// can receive and one thread can transmit on the interface at a time. To
/// support a multi-queued port with a single virtual interface, a multi
/// producer, single consumer channel is used to collect all the kernel
/// bound packets onto one thread for transmit.
pub(crate) struct Kni {
    raw: NonNull<ffi::rte_kni>,
    rx: Option<KniRx>,
    tx: Option<KniTx>,
    txq: KniTxQueue,
}

impl Kni {
    /// Creates a new KNI.
    pub(crate) fn new(raw: NonNull<ffi::rte_kni>) -> Kni {
        let (send, recv) = mpsc::unbounded_channel();

        // making 3 clones of the same raw pointer. but we know it is safe
        // to do because rx and tx happen on two independent queues. so while
        // each one is single-threaded, they can function in parallel.
        let rx = KniRx::new(raw);
        let tx = KniTx::new(raw, recv);
        let txq = KniTxQueue { tx_enque: send };

        Kni {
            raw,
            rx: Some(rx),
            tx: Some(tx),
            txq,
        }
    }

    /// Takes ownership of the RX handle.
    pub(crate) fn take_rx(&mut self) -> Fallible<KniRx> {
        self.rx.take().ok_or_else(|| KniError::NotAcquired.into())
    }

    /// Takes ownership of the TX handle.
    pub(crate) fn take_tx(&mut self) -> Fallible<KniTx> {
        self.tx.take().ok_or_else(|| KniError::NotAcquired.into())
    }

    /// Returns a TX queue handle to send packets to kernel.
    pub(crate) fn txq(&self) -> KniTxQueue {
        self.txq.clone()
    }

    /// Returns the raw struct needed for FFI calls.
    #[inline]
    pub(crate) fn raw_mut(&mut self) -> &mut ffi::rte_kni {
        unsafe { self.raw.as_mut() }
    }
}

impl Drop for Kni {
    fn drop(&mut self) {
        debug!("freeing kernel interface.");

        if let Err(err) =
            unsafe { ffi::rte_kni_release(self.raw_mut()).to_result(|_| DpdkError::new()) }
        {
            error!(message = "failed to release KNI device.", ?err);
        }
    }
}

/// Does not support changing the link MTU.
extern "C" fn change_mtu(port_id: u16, new_mtu: raw::c_uint) -> raw::c_int {
    warn!("ignored change port {} mtu to {}.", port_id, new_mtu);
    -1
}

/// Does not change the link up/down status, but will return 0 so the
/// command succeeds.
extern "C" fn config_network_if(port_id: u16, if_up: u8) -> raw::c_int {
    warn!("ignored change port {} status to {}.", port_id, if_up);
    0
}

/// Does not support changing the link MAC address.
extern "C" fn config_mac_address(port_id: u16, _mac_addr: *mut u8) -> raw::c_int {
    warn!("ignored change port {} mac address.", port_id);
    -1
}

/// Does not support changing the link promiscusity.
extern "C" fn config_promiscusity(port_id: u16, to_on: u8) -> raw::c_int {
    warn!("ignored change port {} promiscusity to {}.", port_id, to_on);
    -1
}

/// Builds a KNI device from the configuration values.
pub(crate) struct KniBuilder<'a> {
    mempool: &'a mut ffi::rte_mempool,
    conf: ffi::rte_kni_conf,
    ops: ffi::rte_kni_ops,
}

impl<'a> KniBuilder<'a> {
    /// Creates a new KNI device builder with the mempool for allocating
    /// new packets.
    pub(crate) fn new(mempool: &'a mut ffi::rte_mempool) -> Self {
        KniBuilder {
            mempool,
            conf: ffi::rte_kni_conf::default(),
            ops: ffi::rte_kni_ops::default(),
        }
    }

    pub(crate) fn name(&mut self, name: &str) -> &mut Self {
        unsafe {
            self.conf.name = mem::zeroed();
            ptr::copy(
                name.as_ptr(),
                self.conf.name.as_mut_ptr() as *mut u8,
                cmp::min(name.len(), self.conf.name.len()),
            );
        }
        self
    }

    pub(crate) fn port_id(&mut self, port_id: PortId) -> &mut Self {
        self.conf.group_id = port_id.raw();
        self.ops.port_id = port_id.raw();
        self
    }

    pub(crate) fn mac_addr(&mut self, mac: MacAddr) -> &mut Self {
        unsafe {
            self.conf.mac_addr = mem::transmute(mac);
        }
        self
    }

    pub(crate) fn finish(&mut self) -> Fallible<Kni> {
        self.conf.mbuf_size = ffi::RTE_MBUF_DEFAULT_BUF_SIZE;
        self.ops.change_mtu = Some(change_mtu);
        self.ops.config_network_if = Some(config_network_if);
        self.ops.config_mac_address = Some(config_mac_address);
        self.ops.config_promiscusity = Some(config_promiscusity);

        unsafe {
            ffi::rte_kni_alloc(self.mempool, &self.conf, &mut self.ops)
                .to_result(|_| DpdkError::new())
                .map(Kni::new)
        }
    }
}

/// Initializes and preallocates the KNI subsystem.
pub(crate) fn kni_init(max: usize) -> Fallible<()> {
    unsafe {
        ffi::rte_kni_init(max as raw::c_uint)
            .to_result(DpdkError::from_errno)
            .map(|_| ())
    }
}

/// Closes the KNI subsystem.
pub(crate) fn kni_close() {
    unsafe {
        ffi::rte_kni_close();
    }
}
