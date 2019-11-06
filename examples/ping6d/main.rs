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

use capsule::packets::icmp::v6::{EchoReply, EchoRequest, Icmpv6};
use capsule::packets::ip::v6::Ipv6;
use capsule::packets::{Ethernet, Packet};
use capsule::settings::load_config;
use capsule::{Batch, Mbuf, Pipeline, Poll, PortQueue, Result, Runtime};
use tracing::{debug, Level};
use tracing_subscriber::fmt;

fn reply_echo(packet: &Mbuf) -> Result<Icmpv6<Ipv6, EchoReply>> {
    let reply = Mbuf::new()?;

    let ethernet = packet.peek::<Ethernet>()?;
    let mut reply = reply.push::<Ethernet>()?;
    reply.set_src(ethernet.dst());
    reply.set_dst(ethernet.src());

    let ipv6 = ethernet.peek::<Ipv6>()?;
    let mut reply = reply.push::<Ipv6>()?;
    reply.set_src(ipv6.dst());
    reply.set_dst(ipv6.src());

    let request = ipv6.peek::<Icmpv6<Ipv6, EchoRequest>>()?;
    let mut reply = reply.push::<Icmpv6<Ipv6, EchoReply>>()?;
    reply.set_identifier(request.identifier());
    reply.set_seq_no(request.seq_no());
    reply.set_data(request.data())?;
    reply.cascade();

    debug!(?request);
    debug!(?reply);

    Ok(reply)
}

fn install(q: PortQueue) -> impl Pipeline {
    Poll::new(q).replace(reply_echo).send(q)
}

fn main() -> Result<()> {
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
