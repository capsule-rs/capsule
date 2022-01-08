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

use crate::packets::ethernet::Ethernet;
use crate::packets::ip::v4::Ip4;
use crate::packets::ip::v6::{Ip6, SegmentRouting};
use crate::packets::tcp::{Tcp, Tcp4, Tcp6};
use crate::packets::udp::{Udp4, Udp6};
use crate::packets::Packet;

/// [`Packet`] extension trait.
///
/// Helper methods for packet conversion that make testing less verbose. Does
/// not guarantee that the result of the conversion will be a valid packet,
/// and will panic if the conversion fails.
///
/// [`Packet`]: crate::packets::Packet
pub trait PacketExt: Packet + Sized {
    /// Converts the packet into an Ethernet packet.
    fn into_eth(self) -> Ethernet {
        self.reset().parse::<Ethernet>().unwrap()
    }

    /// Converts the packet into an IPv4 packet.
    fn into_ip4(self) -> Ip4 {
        self.into_eth().parse::<Ip4>().unwrap()
    }

    /// Converts the packet into a TCP packet inside IPv4.
    fn into_tcp4(self) -> Tcp4 {
        self.into_ip4().parse::<Tcp4>().unwrap()
    }

    /// Converts the packet into a UDP packet inside IPv4.
    fn into_udp4(self) -> Udp4 {
        self.into_ip4().parse::<Udp4>().unwrap()
    }

    /// Converts the packet into an IPv6 packet.
    fn into_ip6(self) -> Ip6 {
        self.into_eth().parse::<Ip6>().unwrap()
    }

    /// Converts the packet into a TCP packet inside IPv6.
    fn into_tcp6(self) -> Tcp6 {
        self.into_ip6().parse::<Tcp6>().unwrap()
    }

    /// Converts the packet into a UDP packet inside IPv6.
    fn into_udp6(self) -> Udp6 {
        self.into_ip6().parse::<Udp6>().unwrap()
    }

    /// Converts the packet into an IPv6 packet with a SRH extension.
    fn into_sr(self) -> SegmentRouting<Ip6> {
        self.into_ip6().parse::<SegmentRouting<Ip6>>().unwrap()
    }

    /// Converts the packet into a TCP packet inside IPv6 with a SRH extension.
    fn into_sr_tcp(self) -> Tcp<SegmentRouting<Ip6>> {
        self.into_sr().parse::<Tcp<SegmentRouting<Ip6>>>().unwrap()
    }
}

impl<T> PacketExt for T where T: Packet + Sized {}
