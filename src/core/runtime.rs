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

use crate::core_map::{CoreMap, CoreMapBuilder};
use crate::dpdk::{eal_cleanup, eal_init, CoreId, Port, PortBuilder};
use crate::mempool_map::MempoolMap;
use crate::settings::RuntimeSettings;
use crate::Result;
use std::collections::HashSet;

pub struct Runtime {
    ports: Vec<Port>,
    mempools: MempoolMap,
    core_map: CoreMap,
}

impl Runtime {
    pub fn init(config: RuntimeSettings) -> Result<Self> {
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
            .master_core(&CoreId::new(config.master_core))
            .mempools(mempools.borrow_mut())
            .finish()?;

        info!("initializing ports...");
        let mut ports = vec![];
        for conf in config.ports.iter() {
            let port = PortBuilder::new(conf.name.clone())?
                .cores(&conf.cores())?
                .mempools(mempools.borrow_mut())
                .rx_tx_queue_capacity(conf.rxd, conf.txd)?
                .finish()?;

            debug!(?port);
            ports.push(port);
        }

        Ok(Runtime {
            ports,
            mempools,
            core_map,
        })
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        debug!("freeing EAL.");
        eal_cleanup().unwrap();
    }
}
