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

mod core_map;
mod mempool_map;

pub use self::core_map::*;
pub use self::mempool_map::*;

use crate::dpdk::{eal_cleanup, eal_init, CoreId, Port, PortBuilder};
use crate::settings::RuntimeSettings;
use crate::{debug, info, Result};
use futures::{future, stream, StreamExt};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_net::driver;
use tokio_net::signal::unix::{self, SignalKind};

/// Supported Unix signals.
pub enum UnixSignal {
    SIGHUP,
    SIGINT,
    SIGTERM,
}

pub struct Runtime {
    ports: Vec<Port>,
    mempools: MempoolMap,
    core_map: CoreMap,
    on_signal: Arc<dyn Fn(UnixSignal) -> bool>,
    config: RuntimeSettings,
}

impl Runtime {
    /// Builds a runtime from config settings.
    #[allow(clippy::cognitive_complexity)]
    pub fn build(config: RuntimeSettings) -> Result<Self> {
        info!("initializing EAL...");
        eal_init(config.to_eal_args())?;

        let cores = config.all_cores();

        info!("initializing mempools...");
        let mut sockets = cores.iter().map(CoreId::socket_id).collect::<HashSet<_>>();
        let sockets = sockets.drain().collect::<Vec<_>>();
        let mut mempools =
            MempoolMap::new(config.mempool.capacity, config.mempool.cache_size, &sockets)?;

        info!("intializing cores...");
        let core_map = CoreMapBuilder::new()
            .cores(&cores)
            .master_core(config.master_core)
            .mempools(mempools.borrow_mut())
            .finish()?;

        info!("initializing ports...");
        let mut ports = vec![];
        for conf in config.ports.iter() {
            let port = PortBuilder::new(conf.name.clone())?
                .cores(&conf.cores)?
                .mempools(mempools.borrow_mut())
                .rx_tx_queue_capacity(conf.rxd, conf.txd)?
                .finish()?;

            debug!(?port);
            ports.push(port);
        }

        info!("runtime ready.");

        Ok(Runtime {
            ports,
            mempools,
            core_map,
            on_signal: Arc::new(|_| true),
            config,
        })
    }

    /// Sets the Unix signal handler.
    ///
    /// `SIGHUP`, `SIGINT` and `SIGTERM` are the supported Unix signals.
    /// The return of the handler determines whether to terminate the
    /// process. `true` indicates the signal is received and the process
    /// should be terminated. `false` indicates to discard the signal and
    /// keep the process running.
    ///
    /// # Example
    ///
    /// ```
    /// Runtime::build(&config)?;
    ///     .set_on_signal(|signal| match signal {
    ///         UnixSignal::SIGHUP => {
    ///             reload_config();
    ///             false
    ///         }
    ///         _ => true,
    ///     })
    ///     .execute();
    /// ```
    pub fn set_on_signal<T>(&mut self, on_signal: T) -> &mut Self
    where
        T: Fn(UnixSignal) -> bool + 'static,
    {
        self.on_signal = Arc::new(on_signal);
        self
    }

    /// Blocks the main thread until a timeout expires.
    ///
    /// This mode is useful for running integration tests. The timeout
    /// duration can be set in `RuntimeSettings`.
    fn wait_for_timeout(&mut self, timeout: u64) -> Result<()> {
        let MasterExecutor {
            ref timer,
            ref mut thread,
            ..
        } = self.core_map.master_core;

        let when = Instant::now() + Duration::from_secs(timeout);
        let main_loop = timer.delay(when);

        debug!("waiting for {} seconds...", timeout);
        thread.block_on(main_loop);

        info!("timed out after {} seconds.", timeout);
        Ok(())
    }

    /// Blocks the main thread until receives a signal to terminate.
    fn wait_for_signal(&mut self) -> Result<()> {
        // pass each signal stream through the `on_signal` closure,
        // and discard any that shouldn't stop the execution.
        let on_signal = &self.on_signal;
        let sighup = unix::signal(SignalKind::hangup())?.filter(|_| {
            let exit = on_signal(UnixSignal::SIGHUP);
            future::ready(exit)
        });
        let sigint = unix::signal(SignalKind::interrupt())?.filter(|_| {
            let exit = on_signal(UnixSignal::SIGINT);
            future::ready(exit)
        });
        let sigterm = unix::signal(SignalKind::terminate())?.filter(|_| {
            let exit = on_signal(UnixSignal::SIGTERM);
            future::ready(exit)
        });

        // combine the signal streams and turn it into a future
        let main_loop = stream::select(stream::select(sighup, sigint), sigterm).into_future();

        let MasterExecutor {
            ref reactor,
            ref mut thread,
            ..
        } = self.core_map.master_core;

        // set the reactor so we can receive the signals and run the
        // future on the master core.
        debug!("waiting for a Unix signal...");
        let _guard = driver::set_default(&reactor);
        let _ = thread.block_on(main_loop);

        info!("signaled to stop.");
        Ok(())
    }

    pub fn execute(&mut self) -> Result<()> {
        match self.config.duration {
            None | Some(0) => self.wait_for_signal(),
            Some(d) => self.wait_for_timeout(d),
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        debug!("freeing EAL.");
        eal_cleanup().unwrap();
    }
}
