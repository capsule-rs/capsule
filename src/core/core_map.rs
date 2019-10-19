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

use crate::dpdk::{CoreId, Mempool, MempoolNotFound, SocketId, MEMPOOL};
use crate::ffi;
use crate::Result;
use std::collections::{HashMap, HashSet};
use std::sync::mpsc;
use std::thread;
use tokio_executor::current_thread;
use tokio_executor::park::{Park, ParkThread, UnparkThread};
use tokio_timer::timer::{self, Timer};

type CurrentThread = current_thread::CurrentThread<Timer<ParkThread>>;

struct CoreExecutor {
    unpark: UnparkThread,
    timer: timer::Handle,
    thread: current_thread::Handle,
}

pub struct CoreMap {
    master_core: CurrentThread,
    cores: HashMap<CoreId, CoreExecutor>,
}

impl CoreMap {}

struct SendablePtr(*mut ffi::rte_mempool);

unsafe impl std::marker::Send for SendablePtr {}

pub struct CoreMapBuilder<'a> {
    cores: HashSet<CoreId>,
    master_core: CoreId,
    mempools: HashMap<SocketId, &'a mut Mempool>,
}

impl<'a> CoreMapBuilder<'a> {
    pub fn new() -> Self {
        CoreMapBuilder {
            cores: Default::default(),
            master_core: CoreId::new(0),
            mempools: Default::default(),
        }
    }

    pub fn cores(&mut self, cores: &[CoreId]) -> &mut Self {
        self.cores = cores.iter().cloned().collect();
        self
    }

    pub fn master_core(&mut self, master_core: &CoreId) -> &mut Self {
        self.master_core = master_core.clone();
        self
    }

    pub fn mempools(&mut self, mempools: &'a mut HashMap<SocketId, Mempool>) -> &mut Self {
        self.mempools = mempools.iter_mut().map(|(&k, v)| (k, v)).collect();
        self
    }

    pub fn finish(&mut self) -> Result<CoreMap> {
        let mut map = HashMap::new();

        // first initializes the master core, which the current running
        // thread should be affinitized to.
        let socket_id = self.master_core.socket_id();
        let mempool = self
            .mempools
            .get_mut(&socket_id)
            .ok_or_else(|| MempoolNotFound(socket_id.raw()))?
            .raw_mut();

        let (master_thread, core_executor) = init_core(&self.master_core, mempool)?;

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
            let mempool = self
                .mempools
                .get_mut(&socket_id)
                .ok_or_else(|| MempoolNotFound(socket_id.raw()))?
                .raw_mut();
            let ptr = SendablePtr(mempool);

            // creates a synchronous channel so we can retrieve the executor for
            // the background core.
            let (sender, receiver) = mpsc::sync_channel(0);

            // spawns a new background thread and initializes a core executor on
            // that thread.
            let _ = thread::spawn(move || {
                debug!("spawned background thread {:?}.", thread::current().id());

                match init_core(&core_id, ptr.0) {
                    Ok((mut thread, executor)) => {
                        info!("initialized thread on {:?}.", core_id);
                        // sends the executor back to the master core. it's safe to unwrap
                        // the result because the receiving end is guaranteed to be in scope.
                        sender.send(Ok(executor)).unwrap();

                        info!("parking {:?}.", core_id);

                        // sleeps the thread for now since there's nothing to be done yet.
                        // once new tasks are spawned, the master core can unpark this and
                        // let the execution continue.
                        let _ = ParkThread::new().park();

                        info!("unparked {:?}.", core_id);

                        // once the thread wakes up, we will run all the spawned tasks to
                        // completion or log the failure.
                        if let Err(err) = thread.run() {
                            error!("{}", err);
                        }

                        info!("shutting down {:?}.", core_id);
                    }
                    // propogates the error back to the master core.
                    Err(err) => sender.send(Err(err)).unwrap(),
                }
            });

            // blocks and waits for the background thread to finish initialize.
            // when done, we add the executor to the map.
            let executor = receiver.recv().unwrap()?;
            map.insert(core_id, executor);
        }

        Ok(CoreMap {
            master_core: master_thread,
            cores: map,
        })
    }
}

fn init_core(id: &CoreId, mempool: *mut ffi::rte_mempool) -> Result<(CurrentThread, CoreExecutor)> {
    // affinitize the running thread to this core.
    id.set_thread_affinity()?;

    // sets the mempool
    MEMPOOL.with(|tls| tls.set(mempool));

    // keeps a unpark handle so we can unpark the core when we
    // are ready to execute the tasks scheduled on this core.
    let park = ParkThread::new();
    let unpark = park.unpark();

    // starts a per-core timer so we can schedule timed tasks.
    let timer = Timer::new(park);
    let timer_handle = timer.handle();

    // starts the single-threaded executor, we can use this handle
    // to spawn tasks onto this core from the master core.
    let thread = CurrentThread::new_with_park(timer);
    let thread_handle = thread.handle();

    let executor = CoreExecutor {
        unpark,
        timer: timer_handle,
        thread: thread_handle,
    };

    Ok((thread, executor))
}
