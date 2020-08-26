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

pub(crate) use self::core_map::*;

use crate::batch::Pipeline;
use crate::config::RuntimeConfig;
use crate::dpdk::{
    self, CoreId, KniError, KniRx, Mempool, Port, PortBuilder, PortError, PortQueue,
};
use crate::{debug, ensure, info};
use failure::Fallible;
use futures::{future, stream, StreamExt};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::mem::ManuallyDrop;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_executor::current_thread;
use tokio_net::driver;
use tokio_net::signal::unix::{self, SignalKind};
use tokio_timer::{timer, Interval};

/// Supported [Unix signals].
///
/// [Unix signals]: https://en.wikipedia.org/wiki/Signal_(IPC)#POSIX_signals
#[derive(Copy, Clone, Debug)]
pub enum UnixSignal {
    /// This signal is sent to a process when its controlling terminal is closed.
    /// In modern systems, this signal usually means that the controlling pseudo
    /// or virtual terminal has been closed. Many daemons will reload their
    /// configuration files and reopen their log files instead of exiting when
    /// receiving this signal. `nohup` is a command to make a command ignore the
    /// signal.
    SIGHUP = libc::SIGHUP as isize,
    /// This signal is sent to a process by its controlling terminal when a user
    /// wishes to interrupt the process. This is typically initiated by pressing
    /// `Ctrl-C`, but on some systems, the "delete" character or "break" key can
    /// be used.
    SIGINT = libc::SIGINT as isize,
    /// This signal is sent to a process to request its termination. Unlike the
    /// `SIGKILL` signal, it can be caught and interpreted or ignored by the
    /// process. This allows the process to perform nice termination releasing
    /// resources and saving state if appropriate. `SIGINT` is nearly identical
    /// to `SIGTERM`.
    SIGTERM = libc::SIGTERM as isize,
}

/// The Capsule runtime.
///
/// The runtime initializes the underlying DPDK environment, and it also manages
/// the task scheduler that executes the packet processing pipelines.
pub struct Runtime {
    ports: ManuallyDrop<Vec<Port>>,
    mempools: ManuallyDrop<Vec<Mempool>>,
    core_map: CoreMap,
    on_signal: Arc<dyn Fn(UnixSignal) -> bool>,
    config: RuntimeConfig,
}

impl Runtime {
    /// Builds a runtime from config settings.
    #[allow(clippy::cognitive_complexity)]
    pub fn build(config: RuntimeConfig) -> Fallible<Self> {
        info!("initializing EAL...");
        dpdk::eal_init(config.to_eal_args())?;

        #[cfg(feature = "metrics")]
        {
            info!("initializing metrics subsystem...");
            crate::metrics::init()?;
        }

        let cores = config.all_cores();

        info!("initializing mempools...");
        let sockets = cores.iter().map(CoreId::socket_id).collect::<HashSet<_>>();
        let mut mempools = vec![];
        for socket in sockets {
            let mempool = Mempool::new(config.mempool.capacity, config.mempool.cache_size, socket)?;
            debug!(?mempool);
            mempools.push(mempool);
        }

        info!("intializing cores...");
        let core_map = CoreMapBuilder::new()
            .app_name(&config.app_name)
            .cores(&cores)
            .master_core(config.master_core)
            .mempools(&mut mempools)
            .finish()?;

        let len = config.num_knis();
        if len > 0 {
            info!("initializing KNI subsystem...");
            dpdk::kni_init(len)?;
        }

        info!("initializing ports...");
        let mut ports = vec![];
        for conf in config.ports.iter() {
            let port = PortBuilder::new(conf.name.clone(), conf.device.clone())?
                .cores(&conf.cores)?
                .mempools(&mut mempools)
                .rx_tx_queue_capacity(conf.rxd, conf.txd)?
                .finish(conf.promiscuous, conf.multicast, conf.kni)?;

            debug!(?port);
            ports.push(port);
        }

        #[cfg(feature = "metrics")]
        {
            crate::metrics::register_port_stats(&ports);
            crate::metrics::register_mempool_stats(&mempools);
        }

        info!("runtime ready.");

        Ok(Runtime {
            ports: ManuallyDrop::new(ports),
            mempools: ManuallyDrop::new(mempools),
            core_map,
            on_signal: Arc::new(|_| true),
            config,
        })
    }

    #[inline]
    fn get_port(&self, name: &str) -> Fallible<&Port> {
        self.ports
            .iter()
            .find(|p| p.name() == name)
            .ok_or_else(|| PortError::NotFound(name.to_owned()).into())
    }

    #[inline]
    fn get_port_mut(&mut self, name: &str) -> Fallible<&mut Port> {
        self.ports
            .iter_mut()
            .find(|p| p.name() == name)
            .ok_or_else(|| PortError::NotFound(name.to_owned()).into())
    }

    #[inline]
    fn get_core(&self, core_id: CoreId) -> Fallible<&CoreExecutor> {
        self.core_map
            .cores
            .get(&core_id)
            .ok_or_else(|| CoreError::NotFound(core_id).into())
    }

    #[inline]
    fn get_port_qs(&self, core_id: CoreId) -> Fallible<HashMap<String, PortQueue>> {
        let map = self
            .ports
            .iter()
            .filter_map(|p| {
                p.queues()
                    .get(&core_id)
                    .map(|q| (p.name().to_owned(), q.clone()))
            })
            .collect::<HashMap<_, _>>();

        ensure!(!map.is_empty(), CoreError::NotAssigned(core_id));

        Ok(map)
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
    ///         SIGHUP => {
    ///             reload_config();
    ///             false
    ///         }
    ///         _ => true,
    ///     })
    ///     .execute();
    /// ```
    pub fn set_on_signal<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn(UnixSignal) -> bool + 'static,
    {
        self.on_signal = Arc::new(f);
        self
    }

    /// Installs a pipeline to a port. The pipeline will run on all the
    /// cores assigned to the port.
    ///
    /// `port` is the logical name that identifies the port. The `installer`
    /// is a closure that takes in a [`PortQueue`] and returns a [`Pipeline`]
    /// that will be spawned onto the thread executor.
    ///
    /// # Example
    ///
    /// ```
    /// Runtime::build(config)?
    ///     .add_add_pipeline_to_port("eth1", install)?
    ///     .execute()
    /// ```
    ///
    /// [`PortQueue`]: crate::PortQueue
    /// [`Pipeline`]: crate::batch::Pipeline
    pub fn add_pipeline_to_port<T: Pipeline + 'static, F>(
        &mut self,
        port: &str,
        installer: F,
    ) -> Fallible<&mut Self>
    where
        F: Fn(PortQueue) -> T + Send + Sync + 'static,
    {
        let port = self.get_port(port)?;
        let f = Arc::new(installer);

        for (core_id, port_q) in port.queues() {
            let f = f.clone();
            let port_q = port_q.clone();
            let thread = &self.get_core(*core_id)?.thread;

            // spawns the bootstrap. we want the bootstrapping to execute on the
            // target core instead of the master core. that way the actual task
            // is spawned locally and the type bounds are less restricting.
            thread.spawn(future::lazy(move |_| {
                let fut = f(port_q);
                debug!("spawned pipeline {}.", fut.name());
                current_thread::spawn(fut);
            }))?;

            debug!("installed pipeline on port_q for {:?}.", core_id);
        }

        info!("installed pipeline for port {}.", port.name());

        Ok(self)
    }

    /// Installs a pipeline to a KNI enabled port to receive packets coming
    /// from the kernel. This pipeline will run on a randomly select core
    /// that's assigned to the port.
    ///
    /// # Remarks
    ///
    /// This function has be to invoked once per port. Otherwise the packets
    /// coming from the kernel will be silently dropped. For the most common
    /// use case where the application only needs simple packet forwarding,
    /// use [`batch::splice`] to join the kernel's RX with the port's TX.
    ///
    /// # Example
    ///
    /// ```
    /// Runtime::build(config)?
    ///     .add_add_pipeline_to_port("kni0", install)?
    ///     .add_kni_rx_pipeline_to_port("kni0", batch::splice)?
    ///     .execute()
    /// ```
    ///
    /// [`batch::splice`]: crate::batch::splice
    pub fn add_kni_rx_pipeline_to_port<T: Pipeline + 'static, F>(
        &mut self,
        port: &str,
        installer: F,
    ) -> Fallible<&mut Self>
    where
        F: FnOnce(KniRx, PortQueue) -> T + Send + Sync + 'static,
    {
        // takes ownership of the kni rx handle.
        let kni_rx = self
            .get_port_mut(port)?
            .kni()
            .ok_or_else(|| KniError::Disabled)?
            .take_rx()?;

        // selects a core to run a rx pipeline for this port. the selection is
        // randomly choosing the last core we find. if the port has more than one
        // core assigned, this will be different from the core that's running the
        // tx pipeline.
        let port = self.get_port(port)?;
        let core_id = port.queues().keys().last().unwrap();
        let port_q = port.queues()[core_id].clone();
        let thread = &self.get_core(*core_id)?.thread;

        // spawns the bootstrap. we want the bootstrapping to execute on the
        // target core instead of the master core.
        thread.spawn(future::lazy(move |_| {
            let fut = installer(kni_rx, port_q);
            debug!("spawned kni rx pipeline {}.", fut.name());
            current_thread::spawn(fut);
        }))?;

        info!("installed kni rx pipeline for port {}.", port.name());

        Ok(self)
    }

    /// Installs a pipeline to a core. All the ports the core is assigned
    /// to will be available to the pipeline.
    ///
    /// `core` is the logical id that identifies the core. The `installer`
    /// is a closure that takes in a hashmap of [`PortQueues`] and returns a
    /// [`Pipeline`] that will be spawned onto the thread executor of the core.
    ///
    /// # Example
    ///
    /// ```
    /// Runtime::build(config)?
    ///     .add_pipeline_to_core(1, install)?
    ///     .execute()
    /// ```
    ///
    /// [`PortQueues`]: crate::PortQueue
    /// [`Pipeline`]: crate::batch::Pipeline
    pub fn add_pipeline_to_core<T: Pipeline + 'static, F>(
        &mut self,
        core: usize,
        installer: F,
    ) -> Fallible<&mut Self>
    where
        F: FnOnce(HashMap<String, PortQueue>) -> T + Send + Sync + 'static,
    {
        let core_id = CoreId::new(core);
        let thread = &self.get_core(core_id)?.thread;
        let port_qs = self.get_port_qs(core_id)?;

        // spawns the bootstrap. we want the bootstrapping to execute on the
        // target core instead of the master core.
        thread.spawn(future::lazy(move |_| {
            let fut = installer(port_qs);
            debug!("spawned pipeline {}.", fut.name());
            current_thread::spawn(fut);
        }))?;

        info!("installed pipeline for {:?}.", core_id);

        Ok(self)
    }

    /// Installs a periodic pipeline to a core.
    ///
    /// `core` is the logical id that identifies the core. The `installer` is a
    /// closure that takes in a hashmap of [`PortQueues`] and returns a
    /// [`Pipeline`] that will be run periodically every `dur` interval.
    ///
    /// # Remarks
    ///
    /// All the ports the core is assigned to will be available to this
    /// pipeline. However they should only be used to transmit packets. This
    /// variant is for pipelines that generate new packets periodically.
    /// A new packet batch can be created with [`batch::poll_fn`] and ingested
    /// into the pipeline.
    ///
    /// # Example
    ///
    /// ```
    /// Runtime::build(config)?
    ///     .add_periodic_pipeline_to_core(1, install, Duration::from_millis(10))?
    ///     .execute()
    /// ```
    ///
    /// [`PortQueues`]: crate::PortQueue
    /// [`Pipeline`]: crate::batch::Pipeline
    /// [`batch::poll_fn`]: crate::batch::poll_fn
    pub fn add_periodic_pipeline_to_core<T: Pipeline + 'static, F>(
        &mut self,
        core: usize,
        installer: F,
        dur: Duration,
    ) -> Fallible<&mut Self>
    where
        F: FnOnce(HashMap<String, PortQueue>) -> T + Send + Sync + 'static,
    {
        let core_id = CoreId::new(core);
        let thread = &self.get_core(core_id)?.thread;
        let port_qs = self.get_port_qs(core_id)?;

        // spawns the bootstrap. we want the bootstrapping to execute on the
        // target core instead of the master core so the periodic task is
        // associated with the correct timer instance.
        thread.spawn(future::lazy(move |_| {
            let mut pipeline = installer(port_qs);
            debug!("spawned periodic pipeline {}.", pipeline.name());
            let fut = Interval::new_interval(dur).for_each(move |_| {
                pipeline.run_once();
                future::ready(())
            });
            current_thread::spawn(fut);
        }))?;

        info!("installed periodic pipeline for {:?}.", core_id);

        Ok(self)
    }

    /// Installs a periodic task to a core.
    ///
    /// `core` is the logical id that identifies the core. `task` is the
    /// closure to execute. The task will rerun every `dur` interval.
    ///
    /// # Example
    ///
    /// ```
    /// Runtime::build(config)?
    ///     .add_periodic_task_to_core(0, print_stats, Duration::from_secs(1))?
    ///     .execute()
    /// ```
    pub fn add_periodic_task_to_core<F>(
        &mut self,
        core: usize,
        task: F,
        dur: Duration,
    ) -> Fallible<&mut Self>
    where
        F: Fn() + Send + Sync + 'static,
    {
        let core_id = CoreId::new(core);
        let thread = &self.get_core(core_id)?.thread;

        // spawns the bootstrap. we want the bootstrapping to execute on the
        // target core instead of the master core so the periodic task is
        // associated with the correct timer instance.
        thread.spawn(future::lazy(move |_| {
            let fut = Interval::new_interval(dur).for_each(move |_| {
                task();
                future::ready(())
            });
            debug!("spawned periodic task.");
            current_thread::spawn(fut);
        }))?;

        info!("installed periodic task for {:?}.", core_id);

        Ok(self)
    }

    /// Blocks the main thread until a timeout expires.
    ///
    /// This mode is useful for running integration tests. The timeout
    /// duration can be set in `RuntimeSettings`.
    fn wait_for_timeout(&mut self, timeout: Duration) -> Fallible<()> {
        let MasterExecutor {
            ref timer,
            ref mut thread,
            ..
        } = self.core_map.master_core;

        let when = Instant::now() + timeout;
        let delay = timer.delay(when);

        debug!("waiting for {:?}...", timeout);
        let _timer = timer::set_default(&timer);
        thread.block_on(delay);
        info!("timed out after {:?}.", timeout);

        Ok(())
    }

    /// Blocks the main thread until receives a signal to terminate.
    fn wait_for_signal(&mut self) -> Fallible<()> {
        let sighup = unix::signal(SignalKind::hangup())?.map(|_| UnixSignal::SIGHUP);
        let sigint = unix::signal(SignalKind::interrupt())?.map(|_| UnixSignal::SIGINT);
        let sigterm = unix::signal(SignalKind::terminate())?.map(|_| UnixSignal::SIGTERM);

        // combines the streams together
        let stream = stream::select(stream::select(sighup, sigint), sigterm);

        // passes each signal through the `on_signal` closure, and discard
        // any that shouldn't stop the execution.
        let f = self.on_signal.clone();
        let mut stream = stream.filter(|&signal| future::ready(f(signal)));

        let MasterExecutor {
            ref reactor,
            ref timer,
            ref mut thread,
            ..
        } = self.core_map.master_core;

        // sets the reactor so we receive the signals and runs the future
        // on the master core. the execution stops on the first signal that
        // wasn't filtered out.
        debug!("waiting for a Unix signal...");
        let _guard = driver::set_default(&reactor);
        let _timer = timer::set_default(&timer);
        let _ = thread.block_on(stream.next());
        info!("signaled to stop.");

        Ok(())
    }

    /// Installs the KNI TX pipelines.
    fn add_kni_tx_pipelines(&mut self) -> Fallible<()> {
        let mut map = HashMap::new();
        for port in self.ports.iter_mut() {
            // selects a core if we need to run a tx pipeline for this port. the
            // selection is randomly choosing the first core we find. if the port
            // has more than one core assigned, this will be different from the
            // core that's running the rx pipeline.
            let core_id = *port.queues().keys().next().unwrap();

            // if the port is kni enabled, then we will take ownership of the
            // tx handle.
            if let Some(kni) = port.kni() {
                map.insert(core_id, kni.take_tx()?);
            }
        }

        // spawns all the pipelines.
        for (core_id, kni_tx) in map.into_iter() {
            let thread = &self.get_core(core_id)?.thread;
            thread.spawn(kni_tx.into_pipeline())?;

            info!("installed kni tx pipeline on {:?}.", core_id);
        }

        Ok(())
    }

    /// Starts all the ports to receive packets.
    fn start_ports(&mut self) -> Fallible<()> {
        for port in self.ports.iter_mut() {
            port.start()?;
        }

        Ok(())
    }

    /// Unparks all the cores to start task execution.
    fn unpark_cores(&mut self) {
        for core in self.core_map.cores.values() {
            if let Some(unpark) = &core.unpark {
                unpark.unpark();
            }
        }
    }

    /// Shuts down all the cores to stop task execution.
    #[allow(clippy::cognitive_complexity)]
    fn shutdown_cores(&mut self) {
        for (core_id, core) in &mut self.core_map.cores {
            if let Some(trigger) = core.shutdown.take() {
                debug!("shutting down {:?}.", core_id);
                trigger.shutdown();
                debug!("sent {:?} shutdown trigger.", core_id);
                let handle = core.join.take().unwrap();
                let _ = handle.join();
                info!("terminated {:?}.", core_id);
            }
        }
    }

    /// Stops all the ports.
    fn stop_ports(&mut self) {
        for port in self.ports.iter_mut() {
            port.stop();
        }
    }

    /// Executes the pipeline(s) until a stop signal is received.
    pub fn execute(&mut self) -> Fallible<()> {
        self.add_kni_tx_pipelines()?;
        self.start_ports()?;
        self.unpark_cores();

        // runs the app until main loop finishes.
        match self.config.duration {
            None => self.wait_for_signal(),
            Some(d) => self.wait_for_timeout(d),
        }?;

        self.shutdown_cores();
        self.stop_ports();
        info!("runtime terminated.");

        Ok(())
    }
}

impl<'a> fmt::Debug for Runtime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("runtime")
            .field("runtime configuration", &format!("{:?}", self.config))
            .finish()
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        // the default rust drop order is self before fields, which is the wrong
        // order for what EAL needs. To control the order, we manually drop the
        // fields first.
        unsafe {
            ManuallyDrop::drop(&mut self.ports);
            ManuallyDrop::drop(&mut self.mempools);
        }

        if self.config.num_knis() > 0 {
            debug!("freeing KNI subsystem.");
            dpdk::kni_close();
        }

        debug!("freeing EAL.");
        dpdk::eal_cleanup().unwrap();
    }
}
