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

use capsule::batch::{Batch, Pipeline, Poll};
use capsule::config::load_config;
use capsule::packets::icmp::v4::{EchoReply, EchoRequest, Icmpv4};
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::{Ethernet, Packet};
use capsule::{Mbuf, PortQueue, Runtime};
use failure::Fallible;
use tracing::{debug, Level};
use tracing_subscriber::fmt;

fn reply_echo(packet: &Mbuf) -> Fallible<Icmpv4<EchoReply>> {
    let reply = Mbuf::new()?;

    let ethernet = packet.peek::<Ethernet>()?;
    let mut reply = reply.push::<Ethernet>()?;
    reply.set_src(ethernet.dst());
    reply.set_dst(ethernet.src());

    let ipv4 = ethernet.peek::<Ipv4>()?;
    let mut reply = reply.push::<Ipv4>()?;
    reply.set_src(ipv4.dst());
    reply.set_dst(ipv4.src());
    reply.set_ttl(255);

    let request = ipv4.peek::<Icmpv4<EchoRequest>>()?;
    let mut reply = reply.push::<Icmpv4<EchoReply>>()?;
    reply.set_identifier(request.identifier());
    reply.set_seq_no(request.seq_no());
    reply.set_data(request.data())?;
    reply.cascade();

    debug!(?request);
    debug!(?reply);

    Ok(reply)
}

fn install(q: PortQueue) -> impl Pipeline {
    Poll::new(q.clone()).replace(reply_echo).send(q)
}

fn main() -> Fallible<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = load_config()?;
    debug!(?config);

    Runtime::build(config)?
        .add_pipeline_to_port("eth1", install)?
        .execute()
}
