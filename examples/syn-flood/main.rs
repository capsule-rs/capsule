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

use capsule::batch::{Batch, Pipeline};
use capsule::config::load_config;
use capsule::metrics;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::{Ethernet, Packet, Tcp};
use capsule::{batch, Mbuf, PortQueue, Runtime};
use failure::Fallible;
use metrics_core::{Builder, Drain, Observe};
use metrics_runtime::observers::YamlBuilder;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;
use tracing::{debug, error, Level};
use tracing_subscriber::fmt;

fn install(qs: HashMap<String, PortQueue>) -> impl Pipeline {
    let mac = qs["eth1"].mac_addr();
    let localhost = Ipv4Addr::new(127, 0, 0, 1);

    // starts the src ip at 10.0.0.0
    let mut next_ip = 10u32 << 24;

    batch::poll_fn(|| {
        Mbuf::alloc_bulk(128).unwrap_or_else(|err| {
            error!(?err);
            vec![]
        })
    })
    .map(move |packet| {
        let mut ethernet = packet.push::<Ethernet>()?;
        ethernet.set_src(mac);

        // +1 to gen the next ip
        next_ip += 1;

        let mut v4 = ethernet.push::<Ipv4>()?;
        v4.set_src(next_ip.into());
        v4.set_dst(localhost);

        let mut tcp = v4.push::<Tcp<Ipv4>>()?;
        tcp.set_syn();
        tcp.set_seq_no(1);
        tcp.set_window(10);
        tcp.set_dst_port(80);
        tcp.reconcile_all();

        Ok(tcp)
    })
    .send(qs["eth1"].clone())
}

fn print_stats() {
    let mut observer = YamlBuilder::new().build();
    metrics::global().controller().observe(&mut observer);
    println!("{}", observer.drain());
}

fn main() -> Fallible<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = load_config()?;
    debug!(?config);

    Runtime::build(config)?
        .add_periodic_pipeline_to_core(1, install, Duration::from_millis(10))?
        .add_periodic_task_to_core(0, print_stats, Duration::from_secs(1))?
        .execute()
}
