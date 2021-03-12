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

use crate::ffi::dpdk::{self, LcoreId};
use crate::info;
use anyhow::Result;
use async_channel::{self, Receiver, Recv, Sender};
use async_executor::Executor;
use futures_lite::future;
use std::future::Future;
use std::sync::Arc;

/// Trigger for the shutdown.
pub(crate) struct Trigger(Sender<()>);

impl Trigger {
    /// Triggers the shutdown.
    pub(crate) fn fire(self) {
        drop(self.0)
    }
}

/// Shutdown wait handle.
pub(crate) struct Shutdown(Receiver<()>);

impl Shutdown {
    /// A future that waits till the trigger is fired.
    pub(crate) fn wait(&self) -> Recv<'_, ()> {
        self.0.recv()
    }
}

/// Creates a shutdown and trigger pair.
///
/// Leverages the behavior of an async channel. When the sender is dropped
/// from scope, it closes the channel and causes the receiver side future
/// in the executor queue to resolve.
pub(crate) fn shutdown_trigger() -> (Trigger, Shutdown) {
    let (s, r) = async_channel::unbounded();
    (Trigger(s), Shutdown(r))
}

/// An async executor abstraction on top of a DPDK logical core.
pub(crate) struct Lcore {
    id: LcoreId,
    executor: Arc<Executor<'static>>,
    trigger: Option<Trigger>,
}

impl Lcore {
    /// Creates a new executor for the given lcore id.
    fn new(id: LcoreId) -> Result<Self> {
        let executor = Arc::new(Executor::new());
        let (trigger, shutdown) = shutdown_trigger();

        let executor2 = Arc::clone(&executor);
        dpdk::eal_remote_launch(id, move || {
            info!(lcore = ?id, "lcore started.");
            let _ = future::block_on(executor2.run(shutdown.wait()));
            info!(lcore = ?id, "lcore stopped.");
        })?;

        Ok(Lcore {
            id,
            executor,
            trigger: Some(trigger),
        })
    }

    /// Spawns an async task and waits for it to complete.
    pub(crate) fn block_on<T: Send + 'static>(
        &self,
        future: impl Future<Output = T> + Send + 'static,
    ) -> T {
        let task = self.executor.spawn(future);
        future::block_on(task)
    }

    /// Spawns a background async task.
    pub(crate) fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) {
        self.executor.spawn(future).detach();
    }
}

impl Drop for Lcore {
    fn drop(&mut self) {
        if let Some(trigger) = self.trigger.take() {
            info!(lcore = ?self.id, "stopping lcore.");
            trigger.fire();
        }
    }
}

/// Returns the enabled worker lcores.
pub(crate) fn lcore_pool() -> Vec<Lcore> {
    let mut lcores = Vec::new();
    let mut current = None;

    while let Some(id) = dpdk::get_next_lcore(current, true, false) {
        lcores.push(Lcore::new(id).unwrap());
        current = Some(id);
    }

    lcores
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[capsule::test]
    fn get_current_lcore_id_from_eal() {
        let next_id = dpdk::get_next_lcore(None, true, false).expect("panic!");
        let lcore = Lcore::new(next_id).expect("panic!");
        let lcore_id = lcore.block_on(async { LcoreId::current() });

        assert_eq!(next_id, lcore_id);
    }

    #[capsule::test]
    fn get_current_lcore_id_from_non_eal() {
        let lcore_id = thread::spawn(|| LcoreId::current()).join().expect("panic!");

        assert_eq!(LcoreId::ANY, lcore_id);
    }
}
