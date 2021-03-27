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

use super::{LcoreMap, Mempool, ShutdownTrigger};
use crate::ffi::dpdk::{self, LcoreId, MbufPtr, PortId, PortRxQueueId, PortTxQueueId};
use crate::net::MacAddr;
use crate::packets::{Mbuf, Packet, Postmark};
use crate::{debug, ensure, info, warn};
use anyhow::Result;
use async_channel::{self, Receiver, Sender};
use capsule_ffi as cffi;
use futures_lite::future;
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

/// A PMD device port.
pub struct Port {
    name: String,
    port_id: PortId,
    rx_lcores: Vec<usize>,
    tx_lcores: Vec<usize>,
    outbox: Option<Sender<MbufPtr>>,
    shutdown: Option<ShutdownTrigger>,
}

impl Port {
    /// Returns the application assigned logical name of the port.
    ///
    /// For applications with more than one port, this name can be used to
    /// identifer the port.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the port ID.
    pub(crate) fn port_id(&self) -> PortId {
        self.port_id
    }

    /// Returns the assigned RX lcores.
    pub fn rx_lcores(&self) -> &Vec<usize> {
        &self.rx_lcores
    }

    /// Returns the assigned TX lcores.
    pub fn tx_lcores(&self) -> &Vec<usize> {
        &self.tx_lcores
    }

    /// Returns the MAC address of the port.
    ///
    /// If fails to retrieve the MAC address, `MacAddr::default` is returned.
    pub fn mac_addr(&self) -> MacAddr {
        dpdk::eth_macaddr_get(self.port_id).unwrap_or_default()
    }

    /// Returns whether the port has promiscuous mode enabled.
    pub fn promiscuous(&self) -> bool {
        dpdk::eth_promiscuous_get(self.port_id)
    }

    /// Returns whether the port has multicast mode enabled.
    pub fn multicast(&self) -> bool {
        dpdk::eth_allmulticast_get(self.port_id)
    }

    /// Returns the outbox queue.
    ///
    /// # Errors
    ///
    /// Returns `PortError::TxNotEnabled` if the port is not configured
    /// to transmit packets.
    pub fn outbox(&self) -> Result<Outbox> {
        self.outbox
            .as_ref()
            .map(|s| Outbox(self.name.clone(), s.clone()))
            .ok_or(PortError::TxNotEnabled.into())
    }

    /// Spawns the port receiving loop.
    pub(crate) fn spawn_rx_loops<F>(&self, f: F, lcores: &LcoreMap) -> Result<()>
    where
        F: Fn(Mbuf) -> Result<Postmark> + Clone + Send + Sync + 'static,
    {
        // port is built with the builder, this would not panic.
        let shutdown = self.shutdown.as_ref().unwrap();

        // can't run loop without assigned rx cores.
        ensure!(self.rx_lcores.len() > 0, PortError::RxNotEnabled);
        // pipeline already set if the trigger is waited on.
        ensure!(!shutdown.is_waited(), PortError::PipelineSet);

        for (index, lcore_id) in self.rx_lcores.iter().enumerate() {
            let lcore = lcores.get(*lcore_id)?;
            let port_name = self.name.clone();
            let handle = shutdown.get_wait();
            let f = f.clone();

            debug!(port = ?self.name, lcore = ?lcore.id(), "spawning rx loop.");

            // the rx loop is endless, so we use a shutdown trigger to signal
            // when the loop should stop executing.
            lcore.spawn(future::or(
                async move {
                    handle.wait().await;
                    debug!(port = ?port_name, lcore = ?LcoreId::current(), "rx loop exited.");
                },
                rx_loop(self.name.clone(), self.port_id, index.into(), 32, f),
            ));
        }

        Ok(())
    }

    /// Spawns the port transmitting loop.
    pub(crate) fn spawn_tx_loops(&mut self, lcores: &LcoreMap) -> Result<()> {
        // though the channel is unbounded, in reality, it's bounded by the
        // mempool size because that's the max number of mbufs the program
        // has allocated.
        let (sender, receiver) = async_channel::unbounded();

        for (index, lcore_id) in self.tx_lcores.iter().enumerate() {
            let lcore = lcores.get(*lcore_id)?;
            let receiver = receiver.clone();

            debug!(port = ?self.name, lcore = ?lcore.id(), "spawning tx loop.");

            lcore.spawn(tx_loop(
                self.name.clone(),
                self.port_id,
                index.into(),
                32,
                receiver,
            ))
        }

        self.outbox = Some(sender);
        Ok(())
    }

    /// Starts the port. This is the final step before packets can be
    /// received or transmitted on this port.
    ///
    /// # Errors
    ///
    /// Returns `DpdkError` if the port fails to start.
    pub(crate) fn start(&self) -> Result<()> {
        dpdk::eth_dev_start(self.port_id)?;
        info!(port = ?self.name, "port started.");
        Ok(())
    }

    /// Stops the port.
    pub(crate) fn stop(&mut self) {
        if let Some(trigger) = self.shutdown.take() {
            debug!(port = ?self.name, "exiting rx loops.");
            trigger.fire();
        }

        dpdk::eth_dev_stop(self.port_id);
        info!(port = ?self.name, "port stopped.");
    }
}

impl fmt::Debug for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Port")
            .field("name", &self.name())
            .field("port_id", &self.port_id())
            .field("mac_addr", &format_args!("{}", self.mac_addr()))
            .field("rx_lcores", &self.rx_lcores)
            .field("tx_lcores", &self.tx_lcores)
            .field("promiscuous", &self.promiscuous())
            .field("multicast", &self.multicast())
            .finish()
    }
}

/// An in-memory queue of packets waiting for transmission.
#[derive(Clone)]
pub struct Outbox(String, Sender<MbufPtr>);

impl Outbox {
    /// Pushes a new packet to the back of the queue.
    pub fn push<P: Packet>(&self, packet: P) -> std::result::Result<(), Mbuf> {
        self.1
            .try_send(packet.reset().into_easyptr())
            .map_err(|err| Mbuf::from_easyptr(err.into_inner()))
    }
}

impl fmt::Debug for Outbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#outbox", self.0)
    }
}

/// Port's receive queue.
pub(crate) struct PortRxQueue {
    port_id: PortId,
    queue_id: PortRxQueueId,
}

impl PortRxQueue {
    /// Receives a burst of packets, up to the `Vec`'s capacity.
    pub(crate) fn receive(&self, mbufs: &mut Vec<MbufPtr>) {
        dpdk::eth_rx_burst(self.port_id, self.queue_id, mbufs);
    }
}

async fn rx_loop<F>(
    port_name: String,
    port_id: PortId,
    queue_id: PortRxQueueId,
    batch_size: usize,
    f: F,
) where
    F: Fn(Mbuf) -> Result<Postmark> + Send + Sync + 'static,
{
    debug!(port = ?port_name, lcore = ?LcoreId::current(), "executing rx loop.");

    let rxq = PortRxQueue { port_id, queue_id };
    let mut ptrs = Vec::with_capacity(batch_size);

    loop {
        rxq.receive(&mut ptrs);
        let mut drops = vec![];

        for ptr in ptrs.drain(..) {
            match f(Mbuf::from_easyptr(ptr)) {
                Ok(Postmark::Emit) => (),
                Ok(Postmark::Drop(ptr)) => drops.push(ptr),
                Err(_) => (),
            }
        }

        if !drops.is_empty() {
            Mbuf::free_bulk(drops);
        }

        // cooperatively moves to the back of the execution queue,
        // making room for other tasks before polling rx again.
        future::yield_now().await;
    }
}

/// Port's transmit queue.
pub(crate) struct PortTxQueue {
    port_id: PortId,
    queue_id: PortTxQueueId,
}

impl PortTxQueue {
    /// Transmits a burst of packets.
    ///
    /// If the TX is full, the excess packets are dropped.
    pub(crate) fn transmit(&self, mbufs: &mut Vec<MbufPtr>) {
        dpdk::eth_tx_burst(self.port_id, self.queue_id, mbufs);

        if !mbufs.is_empty() {
            // tx queue is full, we have to drop the excess.
            dpdk::pktmbuf_free_bulk(mbufs);
        }
    }
}

async fn tx_loop(
    port_name: String,
    port_id: PortId,
    queue_id: PortTxQueueId,
    batch_size: usize,
    receiver: Receiver<MbufPtr>,
) {
    debug!(port = ?port_name, lcore = ?LcoreId::current(), "executing tx loop.");

    let txq = PortTxQueue { port_id, queue_id };
    let mut ptrs = Vec::with_capacity(batch_size);

    loop {
        if let Ok(ptr) = receiver.recv().await {
            ptrs.push(ptr);

            // try to batch the packets up to batch size.
            for _ in 1..batch_size {
                match receiver.try_recv() {
                    Ok(ptr) => ptrs.push(ptr),
                    // no more packets to batch, ready to transmit.
                    Err(_) => break,
                }
            }

            txq.transmit(&mut ptrs);

            // cooperatively moves to the back of the execution queue,
            // making room for other tasks before transmitting again.
            future::yield_now().await;
        } else {
            // this branch can only be reached if the channel is closed,
            // indicating the tx loop should exit.
            break;
        }
    }

    debug!(port = ?port_name, lcore = ?LcoreId::current(), "tx loop exited.");
}

/// Map to lookup the port by the port name.
#[derive(Debug)]
pub struct PortMap(HashMap<String, Port>);

impl PortMap {
    /// Returns the port with the assigned name.
    ///
    /// # Errors
    ///
    /// Returns `PortError::NotFound` if the port name is not found.
    pub fn get(&self, name: &str) -> Result<&Port> {
        self.0.get(name).ok_or_else(|| PortError::NotFound.into())
    }

    /// Returns a port iterator.
    pub fn iter(&self) -> impl Iterator<Item = &Port> {
        self.0.values()
    }

    /// Returns a port iterator.
    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &'_ mut Port> {
        self.0.values_mut()
    }
}

impl From<Vec<Port>> for PortMap {
    fn from(ports: Vec<Port>) -> Self {
        let ports = ports
            .into_iter()
            .map(|port| (port.name.clone(), port))
            .collect::<HashMap<_, _>>();
        PortMap(ports)
    }
}

/// Port related errors.
#[derive(Debug, Error)]
pub enum PortError {
    /// The port is not found.
    #[error("port not found.")]
    NotFound,

    /// The maximum number of RX queues is less than the number of queues
    /// requested.
    #[error("insufficient number of receive queues. max is {0}.")]
    InsufficientRxQueues(u16),

    /// The maximum number of TX queues is less than the number of queues
    /// requested.
    #[error("insufficient number of transmit queues. max is {0}.")]
    InsufficientTxQueues(u16),

    /// The port does not have receive enabled.
    #[error("receive not enabled on port.")]
    RxNotEnabled,

    /// The port does not have transmit enabled.
    #[error("transmit not enabled on port.")]
    TxNotEnabled,

    /// The pipeline for the port is already set.
    #[error("pipeline already set.")]
    PipelineSet,
}

/// Port builder.
pub(crate) struct Builder {
    name: String,
    port_id: PortId,
    port_info: cffi::rte_eth_dev_info,
    port_conf: cffi::rte_eth_conf,
    rx_lcores: Vec<usize>,
    tx_lcores: Vec<usize>,
    rxqs: usize,
    txqs: usize,
}

impl Builder {
    /// Creates a new port `Builder` with a logical name and device name.
    ///
    /// The device name can be the following
    ///   * PCIe address (domain:bus:device.function), for example `0000:02:00.0`
    ///   * DPDK virtual device name, for example `net_[pcap0|null0|tap0]`
    ///
    /// # Errors
    ///
    /// Returns `DpdkError` if the `device` is not found or failed to retrieve
    /// the contextual information for the device.
    pub(crate) fn for_device<S1: Into<String>, S2: Into<String>>(
        name: S1,
        device: S2,
    ) -> Result<Self> {
        let name: String = name.into();
        let device: String = device.into();

        let port_id = dpdk::eth_dev_get_port_by_name(&device)?;
        debug!(?name, id = ?port_id, ?device);

        let port_info = dpdk::eth_dev_info_get(port_id)?;

        Ok(Builder {
            name,
            port_id,
            port_info,
            port_conf: cffi::rte_eth_conf::default(),
            rx_lcores: vec![],
            tx_lcores: vec![],
            rxqs: port_info.rx_desc_lim.nb_min as usize,
            txqs: port_info.tx_desc_lim.nb_min as usize,
        })
    }

    /// Sets the lcores to receive packets on.
    ///
    /// Enables receive side scaling if more than one lcore is used for RX or
    /// packet processing is offloaded to the workers.
    ///
    /// # Errors
    ///
    /// Returns `PortError` if the maximum number of RX queues is less than
    /// the number of lcores assigned.
    pub(crate) fn set_rx_lcores(&mut self, lcores: Vec<usize>) -> Result<&mut Self> {
        ensure!(
            self.port_info.max_rx_queues >= lcores.len() as u16,
            PortError::InsufficientRxQueues(self.port_info.max_rx_queues)
        );

        if lcores.len() > 1 {
            const RSS_HF: u64 =
                (cffi::ETH_RSS_IP | cffi::ETH_RSS_TCP | cffi::ETH_RSS_UDP | cffi::ETH_RSS_SCTP)
                    as u64;

            // enables receive side scaling.
            self.port_conf.rxmode.mq_mode = cffi::rte_eth_rx_mq_mode::ETH_MQ_RX_RSS;
            self.port_conf.rx_adv_conf.rss_conf.rss_hf =
                self.port_info.flow_type_rss_offloads & RSS_HF;

            debug!(
                port = ?self.name,
                rss_hf = self.port_conf.rx_adv_conf.rss_conf.rss_hf,
                "receive side scaling enabled."
            );
        }

        self.rx_lcores = lcores;
        Ok(self)
    }

    /// Sets the lcores to transmit packets on.
    ///
    /// # Errors
    ///
    /// Returns `PortError` if the maximum number of TX queues is less than
    /// the number of lcores assigned.
    pub(crate) fn set_tx_lcores(&mut self, lcores: Vec<usize>) -> Result<&mut Self> {
        ensure!(
            self.port_info.max_tx_queues >= lcores.len() as u16,
            PortError::InsufficientTxQueues(self.port_info.max_tx_queues)
        );

        self.tx_lcores = lcores;
        Ok(self)
    }

    /// Sets the capacity of each RX queue and TX queue.
    ///
    /// If the sizes are not within the limits of the device, they are adjusted
    /// to the boundaries.
    ///
    /// # Errors
    ///
    /// Returns `DpdkError` if failed to set the queue capacity.
    pub(crate) fn set_rxqs_txqs(&mut self, rxqs: usize, txqs: usize) -> Result<&mut Self> {
        let (rxqs2, txqs2) = dpdk::eth_dev_adjust_nb_rx_tx_desc(self.port_id, rxqs, txqs)?;

        info!(
            cond: rxqs2 != rxqs,
            port = ?self.name,
            before = rxqs,
            after = rxqs2,
            "rx ring size adjusted to limits.",
        );
        info!(
            cond: txqs2 != txqs,
            port = ?self.name,
            before = txqs,
            after = txqs2,
            "tx ring size adjusted to limits.",
        );

        self.rxqs = rxqs2;
        self.txqs = txqs2;
        Ok(self)
    }

    /// Sets the promiscuous mode of the port.
    ///
    /// # Errors
    ///
    /// Returns `DpdkError` if the device does not support configurable mode.
    pub(crate) fn set_promiscuous(&mut self, enable: bool) -> Result<&mut Self> {
        if enable {
            dpdk::eth_promiscuous_enable(self.port_id)?;
            debug!(port = ?self.name, "promiscuous mode enabled.");
        } else {
            dpdk::eth_promiscuous_disable(self.port_id)?;
            debug!(port = ?self.name, "promiscuous mode disabled.");
        }

        Ok(self)
    }

    /// Sets the multicast mode of the port.
    ///
    /// # Errors
    ///
    /// Returns `DpdkError` if the device does not support configurable mode.
    pub(crate) fn set_multicast(&mut self, enable: bool) -> Result<&mut Self> {
        if enable {
            dpdk::eth_allmulticast_enable(self.port_id)?;
            debug!(port = ?self.name, "multicast mode enabled.");
        } else {
            dpdk::eth_allmulticast_disable(self.port_id)?;
            debug!(port = ?self.name, "multicast mode disabled.");
        }

        Ok(self)
    }

    /// Builds the port.
    ///
    /// # Errors
    ///
    /// Returns `DpdkError` if fails to configure the device or any of the
    /// rx and tx queues.
    pub(crate) fn build(&mut self, mempool: &mut Mempool) -> Result<Port> {
        // turns on optimization for mbuf fast free.
        if self.port_info.tx_offload_capa & cffi::DEV_TX_OFFLOAD_MBUF_FAST_FREE as u64 > 0 {
            self.port_conf.txmode.offloads |= cffi::DEV_TX_OFFLOAD_MBUF_FAST_FREE as u64;
            debug!(port = ?self.name, "mbuf fast free enabled.");
        }

        // configures the device before everything else.
        dpdk::eth_dev_configure(
            self.port_id,
            self.rx_lcores.len(),
            self.tx_lcores.len(),
            &self.port_conf,
        )?;

        let socket = self.port_id.socket();
        warn!(
            cond: mempool.socket() != socket,
            message = "mempool socket does not match port socket.",
            mempool = ?mempool.socket(),
            port = ?socket
        );

        // configures the rx queues.
        for index in 0..self.rx_lcores.len() {
            dpdk::eth_rx_queue_setup(
                self.port_id,
                index.into(),
                self.rxqs,
                socket,
                None,
                mempool.ptr_mut(),
            )?;
        }

        // configures the tx queues.
        for index in 0..self.tx_lcores.len() {
            dpdk::eth_tx_queue_setup(self.port_id, index.into(), self.txqs, socket, None)?;
        }

        Ok(Port {
            name: self.name.clone(),
            port_id: self.port_id,
            rx_lcores: self.rx_lcores.clone(),
            tx_lcores: self.tx_lcores.clone(),
            outbox: None,
            shutdown: Some(ShutdownTrigger::new()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::dpdk::SocketId;

    #[capsule::test]
    fn port_not_found() {
        assert!(Builder::for_device("test0", "notfound").is_err());
    }

    #[capsule::test]
    fn set_rx_lcores() -> Result<()> {
        let mut builder = Builder::for_device("test0", "net_ring0")?;

        // ring port has a max rxq of 16.
        let lcores = (0..17).collect::<Vec<_>>();
        assert!(builder.set_rx_lcores(lcores).is_err());

        let lcores = (0..16).collect::<Vec<_>>();
        assert!(builder.set_rx_lcores(lcores.clone()).is_ok());
        assert_eq!(lcores, builder.rx_lcores);
        assert_eq!(
            cffi::rte_eth_rx_mq_mode::ETH_MQ_RX_RSS,
            builder.port_conf.rxmode.mq_mode
        );

        Ok(())
    }

    #[capsule::test]
    fn set_tx_lcores() -> Result<()> {
        let mut builder = Builder::for_device("test0", "net_ring0")?;

        // ring port has a max txq of 16.
        let lcores = (0..17).collect::<Vec<_>>();
        assert!(builder.set_tx_lcores(lcores).is_err());

        let lcores = (0..16).collect::<Vec<_>>();
        assert!(builder.set_tx_lcores(lcores.clone()).is_ok());
        assert_eq!(lcores, builder.tx_lcores);

        Ok(())
    }

    #[capsule::test]
    fn set_rxqs_txqs() -> Result<()> {
        let mut builder = Builder::for_device("test0", "net_ring0")?;

        // unfortunately can't test boundary adjustment
        assert!(builder.set_rxqs_txqs(32, 32).is_ok());
        assert_eq!(32, builder.rxqs);
        assert_eq!(32, builder.txqs);

        Ok(())
    }

    #[capsule::test]
    fn set_promiscuous() -> Result<()> {
        let mut builder = Builder::for_device("test0", "net_tap0")?;

        assert!(builder.set_promiscuous(true).is_ok());
        assert!(builder.set_promiscuous(false).is_ok());

        Ok(())
    }

    #[capsule::test]
    fn set_multicast() -> Result<()> {
        let mut builder = Builder::for_device("test0", "net_tap0")?;

        assert!(builder.set_multicast(true).is_ok());
        assert!(builder.set_multicast(false).is_ok());

        Ok(())
    }

    #[capsule::test]
    fn build_port() -> Result<()> {
        let rx_lcores = (0..2).collect::<Vec<_>>();
        let tx_lcores = (3..6).collect::<Vec<_>>();
        let mut pool = Mempool::new("mp_build_port", 15, 0, SocketId::ANY)?;
        let port = Builder::for_device("test0", "net_ring0")?
            .set_rx_lcores(rx_lcores.clone())?
            .set_tx_lcores(tx_lcores.clone())?
            .build(&mut pool)?;

        assert_eq!("test0", port.name());
        assert!(port.promiscuous());
        assert!(port.multicast());
        assert_eq!(rx_lcores, port.rx_lcores);
        assert_eq!(tx_lcores, port.tx_lcores);

        Ok(())
    }

    #[capsule::test]
    fn port_rx_tx() -> Result<()> {
        let mut pool = Mempool::new("mp_port_rx", 15, 0, SocketId::ANY)?;
        let port = Builder::for_device("test0", "net_null0")?
            .set_rx_lcores(vec![0])?
            .set_tx_lcores(vec![0])?
            .build(&mut pool)?;

        let mut packets = Vec::with_capacity(4);
        assert_eq!(0, packets.len());

        let rxq = PortRxQueue {
            port_id: port.port_id,
            queue_id: 0.into(),
        };

        rxq.receive(&mut packets);
        assert_eq!(4, packets.len());
        assert_eq!(4, dpdk::mempool_in_use_count(pool.ptr_mut()));

        let txq = PortTxQueue {
            port_id: port.port_id,
            queue_id: 0.into(),
        };

        txq.transmit(&mut packets);
        assert_eq!(0, packets.len());
        assert_eq!(0, dpdk::mempool_in_use_count(pool.ptr_mut()));

        Ok(())
    }
}
