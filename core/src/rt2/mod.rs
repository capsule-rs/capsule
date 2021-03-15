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

mod config;
mod lcore;
mod mempool;
mod port;

pub use self::config::*;
pub(crate) use self::lcore::*;
pub(crate) use self::mempool::*;
pub(crate) use self::port::*;

use crate::ffi::dpdk::{self, LcoreId};
use crate::{debug, info};
use anyhow::Result;
use std::fmt;
use std::mem::ManuallyDrop;

/// The Capsule runtime.
///
/// The runtime initializes the underlying DPDK environment, and it also manages
/// the task scheduler that executes the packet processing tasks.
pub struct Runtime {
    mempool: ManuallyDrop<Mempool>,
    lcores: ManuallyDrop<LcoreMap>,
    ports: ManuallyDrop<PortMap>,
}

impl Runtime {
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

        info!("initializing ports ...");
        let mut ports = Vec::new();
        for port in config.ports.iter() {
            let port = port::Builder::for_device(&port.name, &port.device)?
                .set_rxqs_txqs(port.rxqs, port.txqs)?
                .set_promiscuous(port.promiscuous)?
                .set_multicast(port.multicast)?
                .set_rx_lcores(port.rx_cores.clone())?
                .set_tx_lcores(port.tx_cores.clone())?
                .build(&mut mempool)?;

            debug!(?port);
            ports.push(port);
        }

        info!("runtime ready.");

        Ok(Runtime {
            mempool: ManuallyDrop::new(mempool),
            lcores: ManuallyDrop::new(lcores),
            ports: ManuallyDrop::new(ports.into()),
        })
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

        unsafe {
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
