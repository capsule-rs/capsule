use crate::dpdk::{CoreId, Mempool, SocketId};
use crate::ffi::{self, AsStr, ToCString, ToResult};
use crate::Result;
use failure::Fail;
use std::collections::HashMap;
use std::fmt;
use std::os::raw;
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
    pub fn socket_id(self) -> Option<SocketId> {
        let id = unsafe { SocketId(ffi::rte_eth_dev_socket_id(self.0)) };
        if SocketId::all().contains(&id) {
            Some(id)
        } else {
            None
        }
    }
}

impl fmt::Display for PortId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "port{}", self.0)
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
    name: String,
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
pub struct MempoolNotFound(raw::c_int);

impl Port {
    pub fn init(
        name: String,
        rxd: usize,
        txd: usize,
        cores: &[CoreId],
        mempools: &mut HashMap<SocketId, Mempool>,
    ) -> Result<Self> {
        unsafe {
            let name = name.to_cstring();

            let mut port_id = 0u16;
            ffi::rte_eth_dev_get_port_by_name(name.as_ptr(), &mut port_id).to_result()?;
            let port_id = PortId(port_id);
            debug!("{:?} is {}.", name, port_id);

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

            let mut new_rxd = rxd as u16;
            let mut new_txd = txd as u16;
            ffi::rte_eth_dev_adjust_nb_rx_tx_desc(port_id.0, &mut new_rxd, &mut new_txd)
                .to_result()?;

            info!(
                cond: new_rxd != rxd as u16,
                "adjusted rxd from {} to {}.", rxd, new_rxd
            );
            info!(
                cond: new_txd != txd as u16,
                "adjusted txd from {} to {}.", txd, new_txd
            );

            // if the port is virtual, we tie it to the socket of the first core
            let socket_id = port_id
                .socket_id()
                .unwrap_or_else(|| cores.first().unwrap().socket_id());
            debug!("{:?} connected to {}.", name, socket_id);

            let mempool = mempools
                .get_mut(&socket_id)
                .ok_or_else(|| MempoolNotFound(socket_id.0))?;

            let mut handles = HashMap::new();

            for (idx, &core_id) in cores.iter().enumerate() {
                warn!(
                    cond: core_id.socket_id() != socket_id,
                    "{} socket '{}' does not match port socket '{}'.",
                    core_id.0,
                    core_id.socket_id().0,
                    socket_id.0
                );

                let rxq_id = RxQueueId(idx as u16);
                ffi::rte_eth_rx_queue_setup(
                    port_id.0,
                    rxq_id.0,
                    new_rxd,
                    socket_id.0 as raw::c_uint,
                    ptr::null(),
                    mempool.raw_mut(),
                )
                .to_result()?;

                let txq_id = TxQueueId(idx as u16);
                ffi::rte_eth_tx_queue_setup(
                    port_id.0,
                    txq_id.0,
                    new_txd,
                    socket_id.0 as raw::c_uint,
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

                debug!("initialized port queue for {}.", core_id);
            }

            Ok(Port {
                name: name.into_string().unwrap(),
                id: port_id,
                handles,
                info: port_info,
            })
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn start(&mut self) -> Result<()> {
        unsafe {
            ffi::rte_eth_dev_start(self.id.0).to_result()?;
            ffi::rte_eth_promiscuous_enable(self.id.0);
        }

        info!("started {}.", self.name());
        Ok(())
    }

    pub fn stop(&mut self) {
        unsafe {
            ffi::rte_eth_dev_stop(self.id.0);
        }

        info!("stopped {}.", self.name());
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let info = self.info;
        write!(
            f,
            "{}: port={}, driver={}, rx_offload={:#x}, tx_offload={:#x}, max_rxq={}, max_txq={}, socket={}",
            self.name,
            self.id.0,
            info.driver_name.as_str(),
            info.rx_offload_capa,
            info.tx_offload_capa,
            info.max_rx_queues,
            info.max_tx_queues,
            self.id.socket_id().map_or_else(|| "n/a".to_owned(), |sid| sid.0.to_string()),
        )
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        debug!("freeing {}.", self.name());

        unsafe {
            ffi::rte_eth_dev_close(self.id.0);
        }
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
