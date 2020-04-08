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

use crate::dpdk::{CoreId, Mempool, MempoolMap, MEMPOOL};
use crate::{debug, error, ffi, info};
use failure::{Fail, Fallible};
use futures::Future;
use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::{self, JoinHandle};
use tokio::sync::oneshot;
use tokio_executor::current_thread::{self, CurrentThread};
use tokio_executor::park::ParkThread;
use tokio_net::driver::{self, Reactor};
use tokio_timer::timer::{self, Timer};

/// A sync-channel based park handle.
///
/// This is designed to be a single use handle. We only need to park the
/// core one time at initialization time. Once unparked, we will never
/// park the core again.
pub(crate) struct Park {
    core_id: CoreId,
    sender: SyncSender<()>,
    receiver: Receiver<()>,
}

impl Park {
    fn new(core_id: CoreId) -> Self {
        let (sender, receiver) = mpsc::sync_channel(0);
        Park {
            core_id,
            sender,
            receiver,
        }
    }

    fn unpark(&self) -> Unpark {
        Unpark {
            core_id: self.core_id,
            sender: self.sender.clone(),
        }
    }

    fn park(&self) {
        if let Err(err) = self.receiver.recv() {
            // we are not expecting failures, but we will log it in case.
            error!(message = "park failed.", core=?self.core_id, ?err);
        }
    }
}

/// A sync-channel based unpark handle.
///
/// This is designed to be a single use handle. We will unpark a core one
/// time after all initialization completes. Do not reinvoke this.
pub(crate) struct Unpark {
    core_id: CoreId,
    sender: SyncSender<()>,
}

impl Unpark {
    pub(crate) fn unpark(&self) {
        if let Err(err) = self.sender.send(()) {
            // we are not expecting failures, but we will log it in case.
            error!(message = "unpark failed.", core=?self.core_id, ?err);
        }
    }
}

/// A tokio oneshot channel based shutdown mechanism.
pub(crate) struct Shutdown {
    receiver: oneshot::Receiver<()>,
}

impl Shutdown {
    fn new(core_id: CoreId) -> (Self, ShutdownTrigger) {
        let (sender, receiver) = oneshot::channel();
        let shutdown = Shutdown { receiver };
        let trigger = ShutdownTrigger { core_id, sender };
        (shutdown, trigger)
    }

    fn into_task(self) -> impl Future {
        self.receiver
    }
}

/// A sync-channel based shutdown trigger to terminate a background thread.
pub(crate) struct ShutdownTrigger {
    core_id: CoreId,
    sender: oneshot::Sender<()>,
}

impl ShutdownTrigger {
    pub(crate) fn shutdown(self) {
        if let Err(err) = self.sender.send(()) {
            // we are not expecting failures, but we will log it in case.
            error!(message = "shutdown failed.", core=?self.core_id, ?err);
        }
    }
}

/// A abstraction used to interact with the master/main thread.
///
/// This is an additional handle to the master thread for performing tasks.
/// Use this `thread` handle to run the main loop. Use the `reactor` handle
/// to catch Unix signals to terminate the main loop. Use the `timer` handle
/// to create new time based tasks with either a `Delay` or `Interval`.
pub(crate) struct MasterExecutor {
    pub(crate) reactor: driver::Handle,
    pub(crate) timer: timer::Handle,
    pub(crate) thread: CurrentThread<Timer<Reactor>>,
}

/// A thread/core abstraction used to interact with a background thread
/// from the master/main thread.
///
/// When a background thread is first spawned, it is parked and waiting for
/// tasks. Use the `timer` handle to create new time based tasks with either
/// a `Delay` or `Interval`. Use the thread handle to spawn tasks onto the
/// background thread. Use `unpark` when they are ready to execute tasks.
///
/// The master thread also has an associated `CoreExecutor`, but `unpark`
/// won't do anything because the thread is not parked. Tasks can be spawned
/// onto it with this handle just like a background thread.
pub(crate) struct CoreExecutor {
    pub(crate) timer: timer::Handle,
    pub(crate) thread: current_thread::Handle,
    pub(crate) unpark: Option<Unpark>,
    pub(crate) shutdown: Option<ShutdownTrigger>,
    pub(crate) join: Option<JoinHandle<()>>,
}

/// Core errors.
#[derive(Debug, Fail)]
pub(crate) enum CoreError {
    /// Core is not found.
    #[fail(display = "{:?} is not found.", _0)]
    NotFound(CoreId),

    /// Core is not assigned to any ports.
    #[fail(display = "{:?} is not assigned to any ports.", _0)]
    NotAssigned(CoreId),
}

/// Map of all the core handles.
pub(crate) struct CoreMap {
    pub(crate) master_core: MasterExecutor,
    pub(crate) cores: HashMap<CoreId, CoreExecutor>,
}

/// By default, raw pointers do not implement `Send`. We need a simple
/// wrapper so we can send the mempool pointer to a background thread and
/// assigned it to that thread. Otherwise, we wont' be able to create new
/// `Mbuf`s on the background threads.
struct SendablePtr(*mut ffi::rte_mempool);

unsafe impl std::marker::Send for SendablePtr {}

/// Builder for core map.
pub(crate) struct CoreMapBuilder<'a> {
    app_name: String,
    cores: HashSet<CoreId>,
    master_core: CoreId,
    mempools: MempoolMap<'a>,
}

impl<'a> CoreMapBuilder<'a> {
    pub(crate) fn new() -> Self {
        CoreMapBuilder {
            app_name: String::new(),
            cores: Default::default(),
            master_core: CoreId::new(0),
            mempools: Default::default(),
        }
    }

    pub(crate) fn app_name(&mut self, app_name: &str) -> &mut Self {
        self.app_name = app_name.to_owned();
        self
    }

    pub(crate) fn cores(&mut self, cores: &[CoreId]) -> &mut Self {
        self.cores = cores.iter().cloned().collect();
        self
    }

    pub(crate) fn master_core(&mut self, master_core: CoreId) -> &mut Self {
        self.master_core = master_core;
        self
    }

    pub(crate) fn mempools(&'a mut self, mempools: &'a mut [Mempool]) -> &'a mut Self {
        self.mempools = MempoolMap::new(mempools);
        self
    }

    #[allow(clippy::cognitive_complexity)]
    pub(crate) fn finish(&'a mut self) -> Fallible<CoreMap> {
        let mut map = HashMap::new();

        // first initializes the master core, which the current running
        // thread should be affinitized to.
        let socket_id = self.master_core.socket_id();
        let mempool = self.mempools.get_raw(socket_id)?;

        let (master_thread, core_executor) = init_master_core(self.master_core, mempool)?;

        // adds the master core to the map. tasks can be spawned onto the
        // master core like any other cores.
        map.insert(self.master_core, core_executor);

        info!("initialized master on {:?}.", self.master_core);

        // the core list may also include the master core, to avoid double
        // init, let's try remove it just in case.
        self.cores.remove(&self.master_core);

        // next initializes all the cores other than the master core
        for &core_id in self.cores.iter() {
            // finds the mempool that matches the core's socket, and wraps the
            // reference in a sendable pointer because we are sending it to
            // a background thread
            let socket_id = core_id.socket_id();
            let mempool = self.mempools.get_raw(socket_id)?;
            let ptr = SendablePtr(mempool);

            // creates a synchronous channel so we can retrieve the executor for
            // the background core.
            let (sender, receiver) = mpsc::sync_channel(0);

            // spawns a new background thread and initializes a core executor on
            // that thread.
            let join = thread::Builder::new()
                .name(format!("{}-{:?}", self.app_name, core_id))
                .spawn(move || {
                    debug!("spawned background thread {:?}.", thread::current().id());

                    match init_background_core(core_id, ptr.0) {
                        Ok((mut thread, park, shutdown, executor)) => {
                            info!("initialized thread on {:?}.", core_id);

                            // keeps a timer handle for later use.
                            let timer_handle = executor.timer.clone();

                            // sends the executor back to the master core. it's safe to unwrap
                            // the result because the receiving end is guaranteed to be in scope.
                            sender.send(Ok(executor)).unwrap();

                            info!("parking {:?}.", core_id);

                            // sleeps the thread for now since there's nothing to be done yet.
                            // once new tasks are spawned, the master core can unpark this and
                            // let the execution continue.
                            park.park();

                            info!("unparked {:?}.", core_id);

                            // once the thread wakes up, we will run all the spawned tasks and
                            // wait until a shutdown is triggered from the master core.
                            let _timer = timer::set_default(&timer_handle);
                            let _ = thread.block_on(shutdown.into_task());

                            info!("unblocked {:?}.", core_id);
                        }
                        // propogates the error back to the master core.
                        Err(err) => sender.send(Err(err)).unwrap(),
                    }
                })?;

            // blocks and waits for the background thread to finish initialize.
            // when done, we add the executor to the map.
            let mut executor = receiver.recv().unwrap()?;
            executor.join = Some(join);
            map.insert(core_id, executor);
        }

        Ok(CoreMap {
            master_core: master_thread,
            cores: map,
        })
    }
}

fn init_master_core(
    id: CoreId,
    mempool: *mut ffi::rte_mempool,
) -> Fallible<(MasterExecutor, CoreExecutor)> {
    // affinitize the running thread to this core.
    id.set_thread_affinity()?;

    // sets the mempool
    MEMPOOL.with(|tls| tls.set(mempool));

    // starts a reactor so we can receive signals on the master core.
    let reactor = Reactor::new()?;
    let reactor_handle = reactor.handle();

    // starts a per-core timer so we can schedule timed tasks.
    let timer = Timer::new(reactor);
    let timer_handle = timer.handle();

    // starts the single-threaded executor, we can use this handle
    // to spawn tasks onto this core from the master core.
    let thread = CurrentThread::new_with_park(timer);
    let thread_handle = thread.handle();

    let main = MasterExecutor {
        reactor: reactor_handle,
        timer: timer_handle.clone(),
        thread,
    };

    let executor = CoreExecutor {
        timer: timer_handle,
        thread: thread_handle,
        unpark: None,
        shutdown: None,
        join: None,
    };

    Ok((main, executor))
}

fn init_background_core(
    id: CoreId,
    mempool: *mut ffi::rte_mempool,
) -> Fallible<(
    CurrentThread<Timer<ParkThread>>,
    Park,
    Shutdown,
    CoreExecutor,
)> {
    // affinitize the running thread to this core.
    id.set_thread_affinity()?;

    // sets the mempool
    MEMPOOL.with(|tls| tls.set(mempool));

    // starts a per-core timer so we can schedule timed tasks.
    let park = ParkThread::new();
    let timer = Timer::new(park);
    let timer_handle = timer.handle();

    // starts the single-threaded executor, we can use this handle
    // to spawn tasks onto this core from the master core.
    let thread = CurrentThread::new_with_park(timer);
    let thread_handle = thread.handle();

    // problem with using the regular thread park is when a task is
    // spawned, the handle will implicitly unpark the thread. we have
    // no way to control that behavior. so instead, we use a channel
    // based unpark mechanism to block the thread from further
    // execution until we are ready to proceed.
    let park = Park::new(id);

    // shutdown handle for the core.
    let (shutdown, trigger) = Shutdown::new(id);

    let executor = CoreExecutor {
        timer: timer_handle,
        thread: thread_handle,
        unpark: Some(park.unpark()),
        shutdown: Some(trigger),
        join: None,
    };

    Ok((thread, park, shutdown, executor))
}
