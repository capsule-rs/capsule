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

use anyhow::{anyhow, Result};
use capsule::packets::ethernet::{EtherTypes, Ethernet};
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::ip::v6::Ipv6;
use capsule::packets::ip::IpPacket;
use capsule::packets::tcp::{Tcp, Tcp4, Tcp6};
use capsule::packets::{Mbuf, Packet, Postmark};
use capsule::runtime::{self, Runtime};
use colored::Colorize;
use signal_hook::consts;
use signal_hook::flag;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::fmt;

fn dump_pkt(packet: Mbuf) -> Result<Postmark> {
    let ethernet = packet.parse::<Ethernet>()?;

    let fmt = format!("{:?}", ethernet).magenta().bold();
    info!("{}", fmt);

    match ethernet.ether_type() {
        EtherTypes::Ipv4 => dump_ip4(&ethernet),
        EtherTypes::Ipv6 => dump_ip6(&ethernet),
        _ => Err(anyhow!("not v4 or v6.")),
    }?;

    Ok(Postmark::Drop(ethernet.reset()))
}

fn dump_ip4(ethernet: &Ethernet) -> Result<()> {
    let ip4 = ethernet.peek::<Ipv4>()?;
    let fmt = format!("{:?}", ip4).yellow();
    info!("{}", fmt);

    let tcp = ip4.peek::<Tcp4>()?;
    dump_tcp(&tcp);

    Ok(())
}

fn dump_ip6(ethernet: &Ethernet) -> Result<()> {
    let ip6 = ethernet.peek::<Ipv6>()?;
    let fmt = format!("{:?}", ip6).cyan();
    info!("{}", fmt);

    let tcp = ip6.peek::<Tcp6>()?;
    dump_tcp(&tcp);

    Ok(())
}

fn dump_tcp<T: IpPacket>(tcp: &Tcp<T>) {
    let fmt = format!("{:?}", tcp).green();
    info!("{}", fmt);

    let fmt = format!("{:?}", tcp.flow()).bright_blue();
    info!("{}", fmt);
}

fn main() -> Result<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = runtime::load_config()?;
    let runtime = Runtime::from_config(config)?;
    runtime.set_port_pipeline("cap0", dump_pkt)?;
    runtime.set_port_pipeline("cap1", dump_pkt)?;
    let _guard = runtime.execute()?;

    let term = Arc::new(AtomicBool::new(false));
    flag::register(consts::SIGINT, Arc::clone(&term))?;
    info!("ctrl-c to quit ...");
    while !term.load(Ordering::Relaxed) {}

    Ok(())
}
