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

//! Capsule runtime.

mod config;
mod lcore;
mod mempool;
#[cfg(feature = "pcap-dump")]
#[cfg_attr(docsrs, doc(cfg(feature = "pcap-dump")))]
mod pcap_dump;
mod port;

pub use self::config::*;
pub(crate) use self::lcore::*;
pub use self::lcore::{Lcore, LcoreMap, LcoreNotFound};
pub use self::mempool::Mempool;
pub(crate) use self::mempool::*;
pub use self::port::{Outbox, Port, PortError, PortMap};

use crate::ffi::dpdk::{self, LcoreId};
use crate::packets::{Mbuf, Postmark};
use crate::{debug, info};
use anyhow::Result;
use async_channel::{self, Receiver, Sender};
use std::fmt;
use std::mem::ManuallyDrop;
use std::ops::DerefMut;

/// Trigger for the shutdown.
pub(crate) struct ShutdownTrigger(Sender<()>, Receiver<()>);

impl ShutdownTrigger {
    /// Creates a new shutdown trigger.
    ///
    /// Leverages the behavior of an async channel. When the sender is dropped
    /// from scope, it closes the channel and causes the receiver side future
    /// in the executor queue to resolve.
    pub(crate) fn new() -> Self {
        let (s, r) = async_channel::unbounded();
        Self(s, r)
    }

    /// Returns a wait handle.
    pub(crate) fn get_wait(&self) -> ShutdownWait {
        ShutdownWait(self.1.clone())
    }

    /// Returns whether the trigger is being waited on.
    pub(crate) fn is_waited(&self) -> bool {
        // a receiver count greater than 1 indicating that there are receiver
        // clones in scope, hence the trigger is being waited on.
        self.0.receiver_count() > 1
    }

    /// Triggers the shutdown.
    pub(crate) fn fire(self) {
        drop(self.0)
    }
}

/// Shutdown wait handle.
pub(crate) struct ShutdownWait(Receiver<()>);

impl ShutdownWait {
    /// A future that waits till the shutdown trigger is fired.
    pub(crate) async fn wait(&self) {
        self.0.recv().await.unwrap_or(())
    }
}

/// The Capsule runtime.
///
/// The runtime initializes the underlying DPDK environment, and it also manages
/// the task scheduler that executes the packet processing tasks.
pub struct Runtime {
    mempool: ManuallyDrop<Mempool>,
    lcores: ManuallyDrop<LcoreMap>,
    ports: ManuallyDrop<PortMap>,
    #[cfg(feature = "pcap-dump")]
    pcap_dump: ManuallyDrop<self::pcap_dump::PcapDump>,
}

impl Runtime {
    /// Returns the mempool.
    ///
    /// For simplicity, we currently only support one global Mempool. Multi-
    /// socket support may be added in the future.
    pub fn mempool(&self) -> &Mempool {
        &self.mempool
    }

    /// Returns the lcores.
    pub fn lcores(&self) -> &LcoreMap {
        &self.lcores
    }

    /// Returns the configured ports.
    pub fn ports(&self) -> &PortMap {
        &self.ports
    }

    /// Initializes a new runtime from config settings.
    pub fn from_config(config: RuntimeConfig) -> Result<Self> {
        info!("starting runtime.");

        debug!("initializing EAL ...");
        dpdk::eal_init(config.to_eal_args())?;

        debug!("initializing mempool ...");
        let socket = LcoreId::main().socket();
        let mut mempool = Mempool::new(
            "mempool",
            config.mempool.capacity,
            config.mempool.cache_size,
            socket,
        )?;
        debug!(?mempool);

        debug!("initializing lcore schedulers ...");
        let lcores = self::lcore_pool();

        for lcore in lcores.iter() {
            let mut ptr = mempool.ptr_mut().clone();
            lcore.block_on(async move { MEMPOOL.with(|tls| tls.set(ptr.deref_mut())) });
        }

        info!("initializing ports ...");
        let mut ports = Vec::new();
        for port in config.ports.iter() {
            let mut port = port::Builder::for_device(&port.name, &port.device)?
                .set_rxqs_txqs(port.rxqs, port.txqs)?
                .set_promiscuous(port.promiscuous)?
                .set_multicast(port.multicast)?
                .set_rx_lcores(port.rx_cores.clone())?
                .set_tx_lcores(port.tx_cores.clone())?
                .build(&mut mempool)?;

            debug!(?port);

            if !port.tx_lcores().is_empty() {
                port.spawn_tx_loops(&lcores)?;
            }

            port.start()?;
            ports.push(port);
        }
        let ports: PortMap = ports.into();

        #[cfg(feature = "pcap-dump")]
        let pcap_dump = self::pcap_dump::enable_pcap_dump(&config.data_dir(), &ports, &lcores)?;

        info!("runtime ready.");

        Ok(Runtime {
            mempool: ManuallyDrop::new(mempool),
            lcores: ManuallyDrop::new(lcores),
            ports: ManuallyDrop::new(ports),
            #[cfg(feature = "pcap-dump")]
            pcap_dump: ManuallyDrop::new(pcap_dump),
        })
    }

    /// Sets the packet processing pipeline for port.
    pub fn set_port_pipeline<F>(&self, port: &str, f: F) -> Result<()>
    where
        F: Fn(Mbuf) -> Result<Postmark> + Clone + Send + Sync + 'static,
    {
        let port = self.ports.get(port)?;
        port.spawn_rx_loops(f, &self.lcores)?;
        Ok(())
    }

    /// Starts the runtime execution.
    pub fn execute(self) -> Result<RuntimeGuard> {
        Ok(RuntimeGuard { runtime: self })
    }
}

impl fmt::Debug for Runtime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Runtime")
            .field("mempool", &self.mempool)
            .finish()
    }
}

/// The RAII guard to stop and cleanup the runtime resources on drop.
pub struct RuntimeGuard {
    runtime: Runtime,
}

impl Drop for RuntimeGuard {
    fn drop(&mut self) {
        info!("shutting down runtime.");

        for port in self.runtime.ports.iter_mut() {
            port.stop();
        }

        unsafe {
            #[cfg(feature = "pcap-dump")]
            ManuallyDrop::drop(&mut self.runtime.pcap_dump);
            ManuallyDrop::drop(&mut self.runtime.ports);
            ManuallyDrop::drop(&mut self.runtime.lcores);
            ManuallyDrop::drop(&mut self.runtime.mempool);
        }

        debug!("freeing EAL ...");
        let _ = dpdk::eal_cleanup();
        info!("runtime shutdown.");
    }
}

impl fmt::Debug for RuntimeGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RuntimeGuard")
    }
}
