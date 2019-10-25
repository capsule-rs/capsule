mod core_map;
mod mempool_map;

pub use self::core_map::*;
pub use self::mempool_map::*;

use crate::batch::Executable;
use crate::dpdk::{eal_cleanup, eal_init, CoreId, Port, PortBuilder, PortError, PortQueue};
use crate::settings::RuntimeSettings;
use crate::{debug, ensure, info, Result};
use futures::{future, stream, StreamExt};
use libc;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::timer::Interval;
use tokio_executor::current_thread;
use tokio_net::driver;
use tokio_net::signal::unix::{self, SignalKind};

/// Supported Unix signals.
#[derive(Debug)]
pub enum UnixSignal {
    SIGHUP = libc::SIGHUP as isize,
    SIGINT = libc::SIGINT as isize,
    SIGTERM = libc::SIGTERM as isize,
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
    pub fn set_on_signal<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn(UnixSignal) -> bool + 'static,
    {
        self.on_signal = Arc::new(f);
        self
    }

    pub fn add_pipeline_to_port<T: Executable + 'static, F>(
        &mut self,
        index: usize,
        f: F,
    ) -> Result<&mut Self>
    where
        F: Fn(PortQueue) -> T + Send + Sync + 'static,
    {
        ensure!(index < self.ports.len(), PortError::NotFound);

        let f = Arc::new(f);
        let port = &self.ports[index];

        for (core_id, port_q) in port.queues() {
            let f = f.clone();
            let port_q = port_q.clone();
            let thread = &self.core_map.cores[core_id].thread;

            // spawns the bootstrap. we need the bootstrapping to execute on the
            // target core instead of the master core because we can't create
            // an `Interval` with the correct `Timer` otherwise. The fn that
            // we need is unfortunately internal to `tokio`.
            thread.spawn(future::lazy(move |_| {
                // let's turn port q into a batch executable.
                let mut batch = f(port_q);

                // turns the batch executable into a repeated task.
                let task = Interval::new_interval(Duration::from_micros(10))
                    .for_each(move |_| future::ready(batch.execute()));

                // and schedules the task on the same core.
                current_thread::spawn(task);
            }))?;

            debug!("installed pipeline on port_q for {:?}.", core_id);
        }

        info!("installed pipeline for port {}.", index);

        Ok(self)
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
        // starts all the ports so we can receive packets.
        for port in self.ports.iter_mut() {
            port.start()?;
        }

        // unparks all the cores to start task execution.
        for (_, core) in &self.core_map.cores {
            match &core.unpark {
                Some(unpark) => unpark.unpark(),
                _ => (), // this is master core no unpark.
            }
        }

        // runs the app until main loop finishes.
        match self.config.duration {
            None | Some(0) => self.wait_for_signal(),
            Some(d) => self.wait_for_timeout(d),
        }?;

        // shuts down all the cores.
        for (_, core) in &mut self.core_map.cores {
            match &core.shutdown {
                Some(trigger) => {
                    trigger.shutdown();
                    let handle = core.join.take().unwrap();
                    let _ = handle.join();
                }
                _ => (), // this is master core no shutdown.
            }
        }

        // stops all the ports.
        for port in self.ports.iter_mut() {
            port.stop();
        }

        Ok(())
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        debug!("freeing EAL.");
        eal_cleanup().unwrap();
    }
}
