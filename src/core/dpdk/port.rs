use crate::dpdk::{CoreId, SocketId};
use crate::ffi::{self, AsStr, ToCString, ToResult};
use crate::mempool_map::MempoolMap2;
use crate::net::MacAddr;
use crate::Result;
use failure::Fail;
use std::collections::HashMap;
use std::fmt;
use std::os::raw;
use std::ptr;

/// An opaque identifier for an ethernet device port.
#[derive(Copy, Clone)]
pub struct PortId(u16);

impl PortId {
    /// Returns the ID of the socket the port is connected to.
    ///
    /// Virtual devices do not have real socket IDs. The value returned
    /// will be discarded if it does not match any of the system's physical
    /// socket IDs.
    #[inline]
    pub fn socket_id(self) -> Option<SocketId> {
        let id = unsafe { SocketId(ffi::rte_eth_dev_socket_id(self.0)) };
        if SocketId::all().contains(&id) {
            Some(id)
        } else {
            None
        }
    }
}

impl fmt::Debug for PortId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "port{}", self.0)
    }
}

/// The index of a receive queue.
struct RxQueueIndex(u16);

/// The index of a transmit queue.
struct TxQueueIndex(u16);

/// TODO:
pub struct PortQueue {
    port_id: PortId,
    rxq_index: RxQueueIndex,
    txq_index: TxQueueIndex,
}

/// Error indicating failed to initialize the port.
#[derive(Debug, Fail)]
pub enum PortError {
    /// The maximum number of RX queues is less than the number of cores
    /// assigned to the port.
    #[fail(display = "Insufficient number of RX queues '{}'.", _0)]
    InsufficientRxQueues(usize),
    /// The maximum number of TX queues is less than the number of cores
    /// assigned to the port.
    #[fail(display = "Insufficient number of TX queues '{}'.", _0)]
    InsufficientTxQueues(usize),
}

/// An ethernet device port.
pub struct Port {
    id: PortId,
    name: String,
    queues: HashMap<CoreId, PortQueue>,
    dev_info: ffi::rte_eth_dev_info,
}

impl Port {
    /// Returns the device name of the port.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Returns the MAC address of the port.
    pub fn mac_addr(&self) -> MacAddr {
        let mut addr = ffi::ether_addr::default();
        unsafe {
            ffi::rte_eth_macaddr_get(self.id.0, &mut addr);
        }
        addr.addr_bytes.into()
    }

    /// Starts the port. This is the final step before packets can be
    /// received or transmitted on this port. Promiscuous mode is also
    /// enabled automatically.
    ///
    /// # Errors
    ///
    /// If the port fails to start, `DpdkError` is returned.
    pub fn start(&mut self) -> Result<()> {
        unsafe {
            ffi::rte_eth_dev_start(self.id.0).to_result()?;
            ffi::rte_eth_promiscuous_enable(self.id.0);
        }

        info!("started port {}.", self.name());
        Ok(())
    }

    /// Stops the port.
    pub fn stop(&mut self) {
        unsafe {
            ffi::rte_eth_dev_stop(self.id.0);
        }

        info!("stopped port {}.", self.name());
    }
}

impl fmt::Debug for Port {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let info = self.dev_info;
        f.debug_struct(&self.name())
            .field("port", &self.id.0)
            .field("mac", &format_args!("\"{}\"", self.mac_addr()))
            .field("driver", &info.driver_name.as_str())
            .field("rx_offload", &format_args!("{:#x}", info.rx_offload_capa))
            .field("tx_offload", &format_args!("{:#x}", info.tx_offload_capa))
            .field("max_rxq", &info.max_rx_queues)
            .field("max_txq", &info.max_tx_queues)
            .field("socket", &self.id.socket_id().map_or(-1, |s| s.0))
            .finish()
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        debug!("freeing port {}.", self.name());

        unsafe {
            ffi::rte_eth_dev_close(self.id.0);
        }
    }
}

/// Builds a port from the configuration values.
pub struct PortBuilder<'a> {
    name: String,
    port_id: PortId,
    dev_info: ffi::rte_eth_dev_info,
    cores: Vec<CoreId>,
    mempools: MempoolMap2<'a>,
    rxd: u16,
    txd: u16,
}

impl<'a> PortBuilder<'a> {
    /// Creates a new `PortBuilder` with the given device name.
    ///
    /// The device name can be the following
    ///   * PCIe address, for example `0000:02:00.0`
    ///   * DPDK virtual device, for example `net_[pcap0|null0|tap0]`
    ///
    /// # Errors
    ///
    /// If the device is not found, `DpdkError` is returned.
    pub fn new(name: String) -> Result<Self> {
        let mut port_id = 0u16;
        unsafe {
            ffi::rte_eth_dev_get_port_by_name(name.clone().to_cstring().as_ptr(), &mut port_id)
                .to_result()?;
        }

        let port_id = PortId(port_id);
        debug!("{} is {:?}.", name, port_id);

        let mut dev_info = ffi::rte_eth_dev_info::default();
        unsafe {
            ffi::rte_eth_dev_info_get(port_id.0, &mut dev_info);
        }

        Ok(PortBuilder {
            name,
            port_id,
            dev_info,
            cores: vec![CoreId::new(0)],
            mempools: Default::default(),
            rxd: 0,
            txd: 0,
        })
    }

    /// Sets the processing cores assigned to the port.
    ///
    /// Each core assigned will receive from and transmit through the port
    /// independently using the run-to-completion model.
    ///
    /// # Errors
    ///
    /// If either the maximum number of RX or TX queues is less than the
    /// number of cores assigned, `PortError` is returned.
    pub fn cores(&mut self, cores: &[CoreId]) -> Result<&mut Self> {
        let mut cores = cores.to_vec();
        cores.sort();
        cores.dedup();
        let len = cores.len() as u16;

        ensure!(
            self.dev_info.max_rx_queues >= len,
            PortError::InsufficientRxQueues(self.dev_info.max_rx_queues as usize)
        );
        ensure!(
            self.dev_info.max_tx_queues >= len,
            PortError::InsufficientTxQueues(self.dev_info.max_tx_queues as usize)
        );

        self.cores = cores;
        Ok(self)
    }

    /// Sets the receive and transmit queues' capacity.
    ///
    /// `rxd` is the receive queue capacity and `txd` is the trasmit queue
    /// capacity. The values are checked against the descriptor limits of
    /// the ethernet device, and are adjusted if they exceed the boundaries.
    ///
    /// # Errors
    ///
    /// If the adjustment failed, `DpdkError` is returned.
    pub fn rx_tx_queue_capacity(&mut self, rxd: usize, txd: usize) -> Result<&mut Self> {
        let mut rxd2 = rxd as u16;
        let mut txd2 = txd as u16;

        unsafe {
            ffi::rte_eth_dev_adjust_nb_rx_tx_desc(self.port_id.0, &mut rxd2, &mut txd2)
                .to_result()?;
        }

        info!(
            cond: rxd2 != rxd as u16,
            "adjusted rxd from {} to {}.", rxd, rxd2
        );
        info!(
            cond: txd2 != txd as u16,
            "adjusted txd from {} to {}.", txd, txd2
        );

        self.rxd = rxd2;
        self.txd = txd2;
        Ok(self)
    }

    /// Sets the available mempools.
    pub fn mempools(&'a mut self, mempools: MempoolMap2<'a>) -> &'a mut Self {
        self.mempools = mempools;
        self
    }

    /// Creates the `Port`.
    pub fn finish(&mut self) -> Result<Port> {
        let len = self.cores.len() as u16;
        let conf = ffi::rte_eth_conf::default();

        // must configure the device first before everything else.
        unsafe {
            ffi::rte_eth_dev_configure(self.port_id.0, len, len, &conf).to_result()?;
        }

        // if the port is virtual, we will allocate it to the socket of
        // the first assigned core.
        let socket_id = self
            .port_id
            .socket_id()
            .unwrap_or_else(|| self.cores[0].socket_id());
        debug!("{} connected to {:?}.", self.name, socket_id);

        // the socket determines which pool to allocate mbufs from.
        let mempool = self.mempools.get_raw(&socket_id)?;

        let mut queues = HashMap::new();

        // for each core, we setup a rx/tx queue pair. for simplicity, we
        // will use the same index for both queues.
        for (idx, &core_id) in self.cores.iter().enumerate() {
            // for best performance, the port and cores should connect to
            // the same socket.
            warn!(
                cond: core_id.socket_id() != socket_id,
                "{:?}'s socket '{}' does not match port socket '{}'.",
                core_id,
                core_id.socket_id().0,
                socket_id.0
            );

            // configures the RX queue with defaults
            let rxq_index = RxQueueIndex(idx as u16);
            unsafe {
                ffi::rte_eth_rx_queue_setup(
                    self.port_id.0,
                    rxq_index.0,
                    self.rxd,
                    socket_id.0 as raw::c_uint,
                    ptr::null(),
                    mempool,
                )
                .to_result()?;
            }

            // configures the TX queue with defaults
            let txq_index = TxQueueIndex(idx as u16);
            unsafe {
                ffi::rte_eth_tx_queue_setup(
                    self.port_id.0,
                    txq_index.0,
                    self.txd,
                    socket_id.0 as raw::c_uint,
                    ptr::null(),
                )
                .to_result()?;
            }

            let queue = PortQueue {
                port_id: self.port_id,
                rxq_index,
                txq_index,
            };

            queues.insert(core_id, queue);
            debug!("initialized port queue for {:?}.", core_id);
        }

        info!("initialized port {}.", self.name);

        Ok(Port {
            id: self.port_id,
            name: self.name.clone(),
            queues,
            dev_info: self.dev_info,
        })
    }
}

// impl PmdPort {
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
