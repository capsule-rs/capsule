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

use crate::dpdk::{CoreId, Mempool, SocketId};
use crate::ffi::{self, ToCString, ToResult};
use crate::Result;
use failure::Fail;
use std::collections::HashMap;
use std::ptr;

/// An opaque identifier for a port.
#[derive(Copy, Clone, Debug)]
pub struct PortId(u16);

impl PortId {
    /// Returns the ID of the socket the port is connected to.
    ///
    /// For virtual devices, `rte_eth_dev_socket_id` will not return a
    /// real socket ID. The value returned will be discarded if it does
    /// not match any of the system's physical socket IDs.
    #[inline]
    pub fn socket_id(&self) -> Option<SocketId> {
        let id = unsafe { SocketId(ffi::rte_eth_dev_socket_id(self.0) as u32) };
        if SocketId::all().contains(&id) {
            Some(id)
        } else {
            None
        }
    }
}

/// An opaque identifier for a RX queue.
struct RxQueueId(u16);

/// An opaque identifier for a TX queue.
struct TxQueueId(u16);

pub struct PortHandle {
    port_id: PortId,
    rxq_id: RxQueueId,
    txq_id: TxQueueId,
}

pub struct Port {
    id: PortId,
    handles: HashMap<CoreId, PortHandle>,
    info: ffi::rte_eth_dev_info,
}

#[derive(Debug, Fail)]
#[fail(display = "Insufficient number of RX queues '{}'.", _0)]
pub struct InsufficientRxQueues(usize);

#[derive(Debug, Fail)]
#[fail(display = "Insufficient number of TX queues '{}'.", _0)]
pub struct InsufficientTxQueues(usize);

#[derive(Debug, Fail)]
#[fail(display = "Mempool for socket '{}' not found.", _0)]
pub struct MempoolNotFound(u32);

impl Port {
    pub fn init(
        name: String,
        rx_desc: usize,
        tx_desc: usize,
        cores: &[CoreId],
        mempools: &mut HashMap<SocketId, Mempool>,
    ) -> Result<Self> {
        unsafe {
            let name = name.to_cstring();

            let mut port_id = 0u16;
            ffi::rte_eth_dev_get_port_by_name(name.as_ptr(), &mut port_id).to_result()?;
            let port_id = PortId(port_id);
            debug!("{:?} has port id {}.", name, port_id.0);

            let len = cores.len() as u16;
            let mut port_info = ffi::rte_eth_dev_info::default();
            ffi::rte_eth_dev_info_get(port_id.0, &mut port_info);

            ensure!(
                port_info.max_rx_queues >= len,
                InsufficientRxQueues(port_info.max_rx_queues as usize)
            );
            ensure!(
                port_info.max_tx_queues >= len,
                InsufficientTxQueues(port_info.max_tx_queues as usize)
            );

            let port_conf = ffi::rte_eth_conf::default();
            ffi::rte_eth_dev_configure(port_id.0, len, len, &port_conf).to_result()?;

            let mut new_rx_desc = rx_desc as u16;
            let mut new_tx_desc = tx_desc as u16;
            ffi::rte_eth_dev_adjust_nb_rx_tx_desc(port_id.0, &mut new_rx_desc, &mut new_tx_desc)
                .to_result()?;

            info!(
                cond: new_rx_desc != rx_desc as u16,
                "adjusted number of RX descriptors from {} to {}.", rx_desc, new_rx_desc
            );
            info!(
                cond: new_tx_desc != tx_desc as u16,
                "adjusted number of TX descriptors from {} to {}.", tx_desc, new_tx_desc
            );

            // if the port is virtual, we tie it to the socket of the first core
            let socket_id = port_id
                .socket_id()
                .unwrap_or_else(|| cores.first().unwrap().socket_id());
            debug!("{:?} is connected to socket {}.", name, socket_id.0);

            let mempool = mempools
                .get_mut(&socket_id)
                .ok_or_else(|| MempoolNotFound(socket_id.0))?;

            let mut handles = HashMap::new();

            for idx in 0..len as usize {
                let core_id = cores[idx];

                warn!(
                    cond: core_id.socket_id() != socket_id,
                    "core '{}''s socket '{}' does not match port's socket '{}'.",
                    core_id.0,
                    core_id.socket_id().0,
                    socket_id.0
                );

                let rxq_id = RxQueueId(idx as u16);
                ffi::rte_eth_rx_queue_setup(
                    port_id.0,
                    rxq_id.0,
                    new_rx_desc,
                    socket_id.0,
                    ptr::null(),
                    mempool.pool_mut(),
                )
                .to_result()?;

                let txq_id = TxQueueId(idx as u16);
                ffi::rte_eth_tx_queue_setup(
                    port_id.0,
                    txq_id.0,
                    new_tx_desc,
                    socket_id.0,
                    ptr::null(),
                )
                .to_result()?;

                handles.insert(
                    core_id,
                    PortHandle {
                        port_id,
                        rxq_id,
                        txq_id,
                    },
                );

                debug!("core '{}' initialized for {:?}.", core_id.0, name);
            }

            Ok(Port {
                id: port_id,
                handles,
                info: port_info,
            })
        }
    }
}

// impl PmdPort {
//     pub fn driver_name(&self) -> &str {
//         unsafe {
//             CStr::from_ptr(self.dev_info.driver_name)
//                 .to_str()
//                 .unwrap_or("unknown")
//         }
//     }

//     pub fn start(&self) -> Result<(), Error> {
//         unsafe {
//             let ret = ffi::rte_eth_dev_start(self.port_id);
//             if ret == 0 {
//                 Ok(())
//             } else {
//                 Err(format_err!("{} device {} not started.", ret, self.name))
//             }
//         }
//     }

//     pub fn stop(&self) {
//         unsafe {
//             ffi::rte_eth_dev_stop(self.port_id);
//         }
//     }

//     pub fn receive(&self) -> Vec<MBuf> {
//         unsafe {
//             let batch_size = 32;
//             let mut buffer = Vec::with_capacity(batch_size);
//             let len =
//                 ffi::_rte_eth_rx_burst(self.port_id, 0, buffer.as_mut_ptr(), batch_size as u16);
//             println!("{} received.", len);
//             buffer
//                 .iter()
//                 .take(len as usize)
//                 .map(|&ptr| MBuf::new(ptr))
//                 .collect::<Vec<_>>()
//         }
//     }

//     pub fn send(&self, mbufs: Vec<MBuf>) {
//         unsafe {
//             let mut buffer = mbufs.iter().map(|mbuf| mbuf.raw_ptr()).collect::<Vec<_>>();
//             let len = ffi::_rte_eth_tx_burst(
//                 self.port_id,
//                 0,
//                 buffer.as_mut_ptr(),
//                 min(mbufs.len(), 32) as u16,
//             );
//             println!("{} sent.", len);
//         }
//     }
// }
