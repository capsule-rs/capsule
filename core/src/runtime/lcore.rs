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

use super::ShutdownTrigger;
use crate::ffi::dpdk::{self, LcoreId};
use crate::{debug, info};
use anyhow::Result;
use async_executor::Executor;
use futures_lite::future;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::sync::Arc;
use thiserror::Error;

/// An async executor abstraction on top of a DPDK logical core.
pub struct Lcore {
    id: LcoreId,
    executor: Arc<Executor<'static>>,
    shutdown: Option<ShutdownTrigger>,
}

impl Lcore {
    /// Creates a new executor for the given lcore id.
    ///
    /// # Errors
    ///
    /// Returns `DpdkError` if the executor fails to run on the given lcore.
    fn new(id: LcoreId) -> Result<Self> {
        debug!(?id, "starting lcore.");
        let trigger = ShutdownTrigger::new();
        let executor = Arc::new(Executor::new());

        let handle = trigger.get_wait();
        let executor2 = Arc::clone(&executor);
        dpdk::eal_remote_launch(id, move || {
            info!(?id, "lcore started.");
            let _ = future::block_on(executor2.run(handle.wait()));
            info!(?id, "lcore stopped.");
        })?;

        Ok(Lcore {
            id,
            executor,
            shutdown: Some(trigger),
        })
    }

    /// Returns the lcore id.
    pub(crate) fn id(&self) -> LcoreId {
        self.id
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
    pub fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) {
        self.executor.spawn(future).detach();
    }
}

impl fmt::Debug for Lcore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lcore").field("id", &self.id()).finish()
    }
}

impl Drop for Lcore {
    fn drop(&mut self) {
        if let Some(trigger) = self.shutdown.take() {
            debug!(id = ?self.id, "stopping lcore.");
            trigger.fire();
        }
    }
}

/// Lcore not found error.
#[derive(Debug, Error)]
#[error("lcore not found.")]
pub struct LcoreNotFound;

/// Map to lookup the lcore by the assigned id.
#[derive(Debug)]
pub struct LcoreMap(HashMap<usize, Lcore>);

impl LcoreMap {
    /// Returns the lcore with the assigned id.
    pub fn get(&self, id: usize) -> Result<&Lcore> {
        self.0.get(&id).ok_or_else(|| LcoreNotFound.into())
    }

    /// Returns a lcore iterator.
    pub fn iter(&self) -> impl Iterator<Item = &Lcore> {
        self.0.values()
    }
}

impl From<Vec<Lcore>> for LcoreMap {
    fn from(lcores: Vec<Lcore>) -> Self {
        let map = lcores
            .into_iter()
            .map(|lcore| (lcore.id.raw(), lcore))
            .collect::<HashMap<_, _>>();
        LcoreMap(map)
    }
}

/// Returns the enabled worker lcores.
pub(crate) fn lcore_pool() -> LcoreMap {
    let mut lcores = Vec::new();
    let mut current = None;

    while let Some(id) = dpdk::get_next_lcore(current, true, false) {
        lcores.push(Lcore::new(id).unwrap());
        current = Some(id);
    }

    lcores.into()
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
        let lcore_id = thread::spawn(LcoreId::current).join().expect("panic!");

        assert_eq!(LcoreId::ANY, lcore_id);
    }
}
