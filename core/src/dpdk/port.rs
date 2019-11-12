use super::{CoreId, Kni, KniBuilder, KniTxQueue, Mbuf, SocketId};
use crate::ffi::{self, AsStr, ToCString, ToResult};
#[cfg(feature = "metrics")]
use crate::metrics::{labels, Counter, SINK};
use crate::net::MacAddr;
use crate::runtime::MempoolMap2;
use crate::{debug, ensure, info, warn, Result};
use failure::Fail;
use std::collections::HashMap;
use std::fmt;
use std::mem;
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

    /// Returns the raw value needed for FFI calls.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    #[inline]
    pub(crate) fn raw(&self) -> u16 {
        self.0
    }
}

impl fmt::Debug for PortId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "port{}", self.0)
    }
}

/// The index of a receive queue.
#[derive(Copy, Clone)]
struct RxQueueIndex(u16);

/// The index of a transmit queue.
#[derive(Copy, Clone)]
struct TxQueueIndex(u16);

/// The receive and transmit queue abstraction. Instead of modeling them
/// as two standalone queues, in the run-to-completion mode, they are modeled
/// as a queue pair associated with the core that runs the pipeline from
/// receive to send.
#[derive(Clone)]
pub struct PortQueue {
    port_id: PortId,
    rxq: RxQueueIndex,
    txq: TxQueueIndex,
    kni: Option<KniTxQueue>,
    #[cfg(feature = "metrics")]
    counter: Option<Counter>,
}

impl PortQueue {
    fn new(port: PortId, rxq: RxQueueIndex, txq: TxQueueIndex) -> Self {
        PortQueue {
            port_id: port,
            rxq,
            txq,
            kni: None,
            #[cfg(feature = "metrics")]
            counter: None,
        }
    }

    /// Receives a burst of packets from the receive queue, up to a maximum
    /// of 32 packets.
    pub(crate) fn receive(&self) -> Vec<Mbuf> {
        const RX_BURST_MAX: usize = 32;
        let mut ptrs = Vec::with_capacity(RX_BURST_MAX);

        let len = unsafe {
            ffi::_rte_eth_rx_burst(
                self.port_id.0,
                self.rxq.0,
                ptrs.as_mut_ptr(),
                RX_BURST_MAX as u16,
            )
        };

        let mbufs = unsafe {
            // does a no-copy conversion to avoid extra allocation.
            Vec::from_raw_parts(ptrs.as_mut_ptr() as *mut Mbuf, len as usize, RX_BURST_MAX)
        };

        mem::forget(ptrs);
        mbufs
    }

    /// Sends the packets to the transmit queue.
    pub(crate) fn transmit(&self, mut packets: Vec<Mbuf>) {
        loop {
            let to_send = packets.len() as u16;
            let sent = unsafe {
                ffi::_rte_eth_tx_burst(
                    self.port_id.0,
                    self.txq.0,
                    // convert to a pointer to an array of `rte_mbuf` pointers
                    packets.as_mut_ptr() as *mut *mut ffi::rte_mbuf,
                    to_send,
                )
            };

            if sent > 0 {
                if to_send - sent > 0 {
                    // still have packets not sent. tx queue is full but still making
                    // progress. we will keep trying until all packets are sent. drains
                    // the ones already sent first and try again on the rest.
                    let drained = packets.drain(..sent as usize).collect::<Vec<_>>();

                    // ownership given to `rte_eth_tx_burst`, don't free them.
                    mem::forget(drained);
                } else {
                    // everything sent and ownership given to `rte_eth_tx_burst`, don't
                    // free them.
                    mem::forget(packets);
                    break;
                }
            } else {
                // tx queue is full and we can't make progress, start dropping packets
                // to avoid potentially stuck in an endless loop.
                #[cfg(feature = "metrics")]
                self.counter.as_ref().unwrap().record(packets.len() as u64);

                Mbuf::free_bulk(packets);
                break;
            }
        }
    }

    /// Returns a handle to send packets to the associated KNI interface.
    pub fn kni(&self) -> Option<&KniTxQueue> {
        self.kni.as_ref()
    }

    /// Sets the TX queue for the KNI interface.
    fn set_kni(&mut self, kni: KniTxQueue) {
        self.kni = Some(kni);
    }

    /// Sets the TX drop counter. All other metrics are already tracked by
    /// DPDK internally except for packets that are dropped because the TX
    /// queue is full.
    #[cfg(feature = "metrics")]
    fn set_counter(&mut self, counter: Counter) {
        self.counter = Some(counter);
    }

    /// Returns the MAC address of the port.
    pub fn mac_addr(&self) -> MacAddr {
        super::eth_macaddr_get(self.port_id.0)
    }
}

/// Error indicating failed to initialize the port.
#[derive(Debug, Fail)]
pub enum PortError {
    /// Port is not found.
    #[fail(display = "Port {} is not found.", _0)]
    NotFound(String),

    #[fail(display = "Port is not bound to any cores.")]
    CoreNotBound,

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
    device: String,
    queues: HashMap<CoreId, PortQueue>,
    kni: Option<Kni>,
    dev_info: ffi::rte_eth_dev_info,
}

impl Port {
    /// Returns the port id.
    pub fn id(&self) -> PortId {
        self.id
    }

    /// Returns the application assigned logical name of the port.
    ///
    /// For applications with more than one port, this name can be used to
    /// identifer the port.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Returns the MAC address of the port.
    pub fn mac_addr(&self) -> MacAddr {
        super::eth_macaddr_get(self.id.0)
    }

    /// Returns the available port queues.
    pub fn queues(&self) -> &HashMap<CoreId, PortQueue> {
        &self.queues
    }

    /// Returns the KNI.
    pub fn kni(&mut self) -> Option<&mut Kni> {
        self.kni.as_mut()
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

    #[cfg(feature = "metrics")]
    pub fn stats(&self) -> super::PortStats {
        super::PortStats::build(self)
    }
}

impl fmt::Debug for Port {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let info = self.dev_info;
        f.debug_struct(&self.name())
            .field("device", &self.device)
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
        debug!("freeing {}.", self.name);

        unsafe {
            ffi::rte_eth_dev_close(self.id.0);
        }
    }
}

/// Builds a port from the configuration values.
pub struct PortBuilder<'a> {
    name: String,
    device: String,
    port_id: PortId,
    dev_info: ffi::rte_eth_dev_info,
    cores: Vec<CoreId>,
    mempools: MempoolMap2<'a>,
    rxd: u16,
    txd: u16,
}

impl<'a> PortBuilder<'a> {
    /// Creates a new `PortBuilder` with a logical name and device name.
    ///
    /// The device name can be the following
    ///   * PCIe address, for example `0000:02:00.0`
    ///   * DPDK virtual device, for example `net_[pcap0|null0|tap0]`
    ///
    /// # Errors
    ///
    /// If the device is not found, `DpdkError` is returned.
    pub fn new(name: String, device: String) -> Result<Self> {
        let mut port_id = 0u16;
        unsafe {
            ffi::rte_eth_dev_get_port_by_name(device.clone().to_cstring().as_ptr(), &mut port_id)
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
            device,
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
        ensure!(!cores.is_empty(), PortError::CoreNotBound);

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
            message = "adjusted rxd.",
            before = rxd,
            after = rxd2
        );
        info!(
            cond: txd2 != txd as u16,
            message = "adjusted txd.",
            before = txd,
            after = txd2
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
    #[allow(clippy::cognitive_complexity)]
    pub fn finish(&mut self, with_kni: bool) -> Result<Port> {
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
        let mempool = self.mempools.get_raw(socket_id)?;

        // if the port has kni enabled, we will allocate an interface.
        let kni = if with_kni {
            let kni = KniBuilder::new(mempool)
                .name(&self.name)
                .port_id(self.port_id)
                .core_id(self.cores[0])
                .mac_addr(super::eth_macaddr_get(self.port_id.raw()))
                .finish()?;
            Some(kni)
        } else {
            None
        };

        let mut queues = HashMap::new();

        // for each core, we setup a rx/tx queue pair. for simplicity, we
        // will use the same index for both queues.
        for (idx, &core_id) in self.cores.iter().enumerate() {
            // for best performance, the port and cores should connect to
            // the same socket.
            warn!(
                cond: core_id.socket_id() != socket_id,
                message = "core socket does not match port socket.",
                core = ?core_id,
                core_socket = core_id.socket_id().0,
                port_socket = socket_id.0
            );

            // configures the RX queue with defaults
            let rxq = RxQueueIndex(idx as u16);
            unsafe {
                ffi::rte_eth_rx_queue_setup(
                    self.port_id.0,
                    rxq.0,
                    self.rxd,
                    socket_id.0 as raw::c_uint,
                    ptr::null(),
                    mempool,
                )
                .to_result()?;
            }

            // configures the TX queue with defaults
            let txq = TxQueueIndex(idx as u16);
            unsafe {
                ffi::rte_eth_tx_queue_setup(
                    self.port_id.0,
                    txq.0,
                    self.txd,
                    socket_id.0 as raw::c_uint,
                    ptr::null(),
                )
                .to_result()?;
            }

            let mut q = PortQueue::new(self.port_id, rxq, txq);

            if let Some(kni) = &kni {
                q.set_kni(kni.txq());
            }

            #[cfg(feature = "metrics")]
            {
                // have space to set up the stats per core.
                if ffi::RTE_ETHDEV_QUEUE_STAT_CNTRS >= len as u32 {
                    unsafe {
                        ffi::rte_eth_dev_set_rx_queue_stats_mapping(
                            self.port_id.0,
                            idx as u16,
                            idx as u8,
                        )
                        .to_result()?;

                        ffi::rte_eth_dev_set_tx_queue_stats_mapping(
                            self.port_id.0,
                            idx as u16,
                            idx as u8,
                        )
                        .to_result()?;
                    }
                }

                // counter to track dropped TX packets.
                let counter = SINK.scoped("port").counter_with_labels(
                    "dropped",
                    labels!(
                        "port" => self.name.clone(),
                        "dir" => "tx",
                    ),
                );
                q.set_counter(counter);
            }

            queues.insert(core_id, q);
            debug!("initialized port queue for {:?}.", core_id);
        }

        info!("initialized port {}.", self.name);

        Ok(Port {
            id: self.port_id,
            name: self.name.clone(),
            device: self.device.clone(),
            queues,
            kni,
            dev_info: self.dev_info,
        })
    }
}
