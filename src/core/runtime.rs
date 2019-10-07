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

use crate::dpdk::{eal_init, Mempool, Port, SocketId};
use crate::Result;
use log::{debug, info};
use std::collections::HashMap;

pub struct Runtime {
    mempools: HashMap<SocketId, Mempool>,
}

impl Runtime {
    pub fn init(args: Vec<String>) -> Result<Self> {
        eal_init(args)?;

        info!("creating mempools...");
        let socket_id = SocketId::current();
        let mut mempool = Mempool::create(65535, 16, socket_id)?;
        info!("created '{}'.", mempool.name());
        debug!("{}", mempool);

        let port = Port::init("net_pcap2".to_owned(), &mut mempool)?;

        // let ports = ["0000:00:08.0", "net_pcap2"];
        // let ports = ports
        //     .iter()
        //     .map(|&name| Port::init(name.to_owned(), &mut mempool))
        //     .collect::<Vec<_>>();

        let mut mempools = HashMap::new();
        mempools.insert(socket_id, mempool);

        Ok(Runtime { mempools })
    }
}
