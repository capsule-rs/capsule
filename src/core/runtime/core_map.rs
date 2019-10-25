use super::MempoolMap2;
use crate::dpdk::{CoreId, MEMPOOL};
use crate::{debug, error, ffi, info, Result};
use std::collections::{HashMap, HashSet};
use std::sync::mpsc;
use std::thread;
use tokio_executor::current_thread::{self, CurrentThread};
use tokio_executor::park::Park;
use tokio_executor::threadpool::park::{DefaultPark, DefaultUnpark};
use tokio_net::driver::{self, Reactor};
use tokio_timer::timer::{self, Timer};

/// A abstraction used to interact with the master/main thread.
///
/// This is an additional handle to the master thread for performing tasks.
/// Use this `thread` handle to run the main loop. Use the `reactor` handle
/// to catch Unix signals to terminate the main loop. Use the `timer` handle
/// to create new time based tasks with either a `Delay` or `Interval`.
pub struct MasterExecutor {
    pub reactor: driver::Handle,
    pub timer: timer::Handle,
    pub thread: CurrentThread<Timer<Reactor>>,
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
pub struct CoreExecutor {
    pub unpark: DefaultUnpark,
    pub timer: timer::Handle,
    pub thread: current_thread::Handle,
}

/// Map of all the core handles.
pub struct CoreMap {
    pub master_core: MasterExecutor,
    pub cores: HashMap<CoreId, CoreExecutor>,
}

/// By default, raw pointers do not implement `Send`. We need a simple
/// wrapper so we can send the mempool pointer to a background thread and
/// assigned it to that thread. Otherwise, we wont' be able to create new
/// `Mbuf`s on the background threads.
struct SendablePtr(*mut ffi::rte_mempool);

unsafe impl std::marker::Send for SendablePtr {}

/// Builder for core map.
pub struct CoreMapBuilder<'a> {
    cores: HashSet<CoreId>,
    master_core: CoreId,
    mempools: MempoolMap2<'a>,
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

    pub fn master_core(&mut self, master_core: CoreId) -> &mut Self {
        self.master_core = master_core;
        self
    }

    pub fn mempools(&'a mut self, mempools: MempoolMap2<'a>) -> &'a mut Self {
        self.mempools = mempools;
        self
    }

    #[allow(clippy::cognitive_complexity)]
    pub fn finish(&'a mut self) -> Result<CoreMap> {
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
            let _ = thread::spawn(move || {
                debug!("spawned background thread {:?}.", thread::current().id());

                match init_background_core(core_id, ptr.0) {
                    Ok((mut thread, executor)) => {
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
                        let _ = thread.get_park_mut().park();

                        info!("unparked {:?}.", core_id);

                        // once the thread wakes up, we will run all the spawned tasks to
                        // completion or log the failure.
                        let _timer = timer::set_default(&timer_handle);
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

fn init_master_core(
    id: CoreId,
    mempool: *mut ffi::rte_mempool,
) -> Result<(MasterExecutor, CoreExecutor)> {
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

    // don't really use this but need to create one so we can treat
    // master core like a regular core as well. trying to unpark it
    // later won't do anything.
    let park = DefaultPark::new();
    let unpark = park.unpark();

    let executor = CoreExecutor {
        unpark,
        timer: timer_handle,
        thread: thread_handle,
    };

    Ok((main, executor))
}

fn init_background_core(
    id: CoreId,
    mempool: *mut ffi::rte_mempool,
) -> Result<(CurrentThread<Timer<DefaultPark>>, CoreExecutor)> {
    // affinitize the running thread to this core.
    id.set_thread_affinity()?;

    // sets the mempool
    MEMPOOL.with(|tls| tls.set(mempool));

    // keeps a unpark handle so we can unpark the core from the master
    // core when we are ready to execute the tasks scheduled.
    let park = DefaultPark::new();
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
