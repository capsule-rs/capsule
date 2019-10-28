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

use capsule::packets::{
    ip::{v4::Ipv4, v6::Ipv6, IpPacket},
    EtherTypes, Ethernet, Packet, Tcp,
};
use capsule::settings::load_config;
use capsule::{compose, Batch, Mbuf, Pipeline, Poll, PortQueue, Result, Runtime};
use colored::*;
use tracing::{debug, Level};
use tracing_subscriber::fmt;

#[inline]
fn dump_eth(packet: Mbuf) -> Result<Ethernet> {
    let ethernet = packet.parse::<Ethernet>()?;

    let info_fmt = format!("{:?}", ethernet).magenta().bold();
    println!("{}", info_fmt);

    Ok(ethernet)
}

#[inline]
fn dump_v4(ethernet: &Ethernet) -> Result<()> {
    let v4 = ethernet.peek::<Ipv4>()?;
    let info_fmt = format!("{:?}", v4).yellow();
    println!("{}", info_fmt);

    let tcp = v4.peek::<Tcp<Ipv4>>()?;
    dump_tcp(&tcp);

    Ok(())
}

#[inline]
fn dump_v6(ethernet: &Ethernet) -> Result<()> {
    let v6 = ethernet.peek::<Ipv6>()?;
    let info_fmt = format!("{:?}", v6).cyan();
    println!("{}", info_fmt);

    let tcp = v6.peek::<Tcp<Ipv6>>()?;
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

fn install(q: PortQueue) -> impl Pipeline {
    Poll::new(q)
        .map(dump_eth)
        .group_by(
            |ethernet| ethernet.ether_type(),
            |groups| {
                compose!(
                    groups,
                    EtherTypes::Ipv4 => |group| {
                        group.for_each(dump_v4)
                    },
                    EtherTypes::Ipv6 => |group| {
                        group.for_each(dump_v6)
                    }
                );
            },
        )
        .send(q)
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
        .add_pipeline_to_port("eth2", install)?
        .execute()
}
