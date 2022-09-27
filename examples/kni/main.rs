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
use capsule::packets::ethernet::Ethernet;
use capsule::packets::icmp::v6::Icmpv6;
use capsule::packets::ip::v6::{Ipv6, Ipv6Packet};
use capsule::packets::ip::ProtocolNumbers;
use capsule::packets::udp::Udp6;
use capsule::packets::{Mbuf, Packet, Postmark};
use capsule::runtime::{self, Outbox, Runtime};
use colored::Colorize;
use signal_hook::consts;
use signal_hook::flag;
use std::str;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::fmt;

fn route_pkt(packet: Mbuf, kni0: &Outbox) -> Result<Postmark> {
    let ipv6 = packet.parse::<Ethernet>()?.parse::<Ipv6>()?;

    match ipv6.next_header() {
        ProtocolNumbers::Icmpv6 => {
            let icmp = ipv6.parse::<Icmpv6<Ipv6>>()?;
            let fmt = format!("to kni0: {}", icmp.msg_type()).cyan();
            info!("{}", fmt);
            let _ = kni0.push(icmp);
            Ok(Postmark::Emit)
        }
        ProtocolNumbers::Udp => {
            let udp = ipv6.parse::<Udp6>()?;
            let fmt = format!("you said: {}", str::from_utf8(udp.data())?).bright_blue();
            info!("{}", fmt);
            Ok(Postmark::Drop(udp.reset()))
        }
        _ => {
            let fmt = format!("not supported: {}", ipv6.next_header()).red();
            info!("{}", fmt);
            Ok(Postmark::Drop(ipv6.reset()))
        }
    }
}

fn from_kni(packet: Mbuf, cap0: &Outbox) -> Result<Postmark> {
    let icmp = packet
        .parse::<Ethernet>()?
        .parse::<Ipv6>()?
        .parse::<Icmpv6<Ipv6>>()?;

    let fmt = format!("from kni0: {}", icmp.msg_type()).green();
    info!("{}", fmt);

    let _ = cap0.push(icmp);
    Ok(Postmark::Emit)
}

fn main() -> Result<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = runtime::load_config()?;
    let runtime = Runtime::from_config(config)?;

    let kni0 = runtime.ports().get("kni0")?.outbox()?;
    runtime.set_port_pipeline("cap0", move |packet| route_pkt(packet, &kni0))?;

    let cap0 = runtime.ports().get("cap0")?.outbox()?;
    runtime.set_port_pipeline("kni0", move |packet| from_kni(packet, &cap0))?;

    let _guard = runtime.execute()?;

    let term = Arc::new(AtomicBool::new(false));
    flag::register(consts::SIGINT, Arc::clone(&term))?;
    info!("ctrl-c to quit ...");
    while !term.load(Ordering::Relaxed) {}

    Ok(())
}
