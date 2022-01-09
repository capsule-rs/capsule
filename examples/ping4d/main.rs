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
use capsule::packets::icmp::v4::{EchoReply, EchoRequest};
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::{Mbuf, Packet, Postmark};
use capsule::runtime::{self, Outbox, Runtime};
use signal_hook::consts;
use signal_hook::flag;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::fmt;

fn reply_echo(packet: Mbuf, cap0: &Outbox) -> Result<Postmark> {
    let reply = Mbuf::new()?;

    let ethernet = packet.peek::<Ethernet>()?;
    let mut reply = reply.push::<Ethernet>()?;
    reply.set_src(ethernet.dst());
    reply.set_dst(ethernet.src());

    let ip4 = ethernet.peek::<Ipv4>()?;
    let mut reply = reply.push::<Ipv4>()?;
    reply.set_src(ip4.dst());
    reply.set_dst(ip4.src());
    reply.set_ttl(255);

    let request = ip4.peek::<EchoRequest>()?;
    let mut reply = reply.push::<EchoReply>()?;
    reply.set_identifier(request.identifier());
    reply.set_seq_no(request.seq_no());
    reply.set_data(request.data())?;
    reply.reconcile_all();

    info!(?request);
    info!(?reply);

    let _ = cap0.push(reply);

    Ok(Postmark::Drop(packet))
}

fn main() -> Result<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = runtime::load_config()?;
    let runtime = Runtime::from_config(config)?;

    let outbox = runtime.ports().get("cap0")?.outbox()?;
    runtime.set_port_pipeline("cap0", move |packet| reply_echo(packet, &outbox))?;

    let _guard = runtime.execute()?;

    let term = Arc::new(AtomicBool::new(false));
    flag::register(consts::SIGINT, Arc::clone(&term))?;
    info!("ctrl-c to quit ...");
    while !term.load(Ordering::Relaxed) {}

    Ok(())
}
