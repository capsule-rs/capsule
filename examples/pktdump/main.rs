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
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::ip::v6::Ipv6;
use capsule::packets::ip::IpPacket;
use capsule::packets::{EtherTypes, Ethernet, Packet, Tcp, Tcp4, Tcp6};
use capsule::rt2::{self, Mbuf, Runtime};
use colored::*;
use signal_hook::consts;
use signal_hook::flag;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, Level};
use tracing_subscriber::fmt;

#[inline]
fn dump_pkt(packet: Mbuf) -> Result<()> {
    let ethernet = packet.parse::<Ethernet>()?;

    let info_fmt = format!("{:?}", ethernet).magenta().bold();
    println!("{}", info_fmt);

    match ethernet.ether_type() {
        EtherTypes::Ipv4 => dump_v4(&ethernet),
        EtherTypes::Ipv6 => dump_v6(&ethernet),
        _ => Err(anyhow!("not v4 or v6.")),
    }
}

#[inline]
fn dump_v4(ethernet: &Ethernet) -> Result<()> {
    let v4 = ethernet.peek::<Ipv4>()?;
    let info_fmt = format!("{:?}", v4).yellow();
    println!("{}", info_fmt);

    let tcp = v4.peek::<Tcp4>()?;
    dump_tcp(&tcp);

    Ok(())
}

#[inline]
fn dump_v6(ethernet: &Ethernet) -> Result<()> {
    let v6 = ethernet.peek::<Ipv6>()?;
    let info_fmt = format!("{:?}", v6).cyan();
    println!("{}", info_fmt);

    let tcp = v6.peek::<Tcp6>()?;
    dump_tcp(&tcp);

    Ok(())
}

#[inline]
fn dump_tcp<T: IpPacket>(tcp: &Tcp<T>) {
    let tcp_fmt = format!("{:?}", tcp).green();
    println!("{}", tcp_fmt);

    let flow_fmt = format!("{:?}", tcp.flow()).bright_blue();
    println!("{}", flow_fmt);
}

fn main() -> Result<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = rt2::load_config()?;
    debug!(?config);

    let runtime = Runtime::from_config(config)?;
    runtime.set_port_pipeline("eth1", dump_pkt)?;
    runtime.set_port_pipeline("eth2", dump_pkt)?;
    let _guard = runtime.execute()?;

    let term = Arc::new(AtomicBool::new(false));
    flag::register(consts::SIGINT, Arc::clone(&term))?;
    println!("ctrl-c to quit ...");
    while !term.load(Ordering::Relaxed) {}

    Ok(())
}
