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

use crate::dpdk::BufferError;
use crate::net::MacAddr;
use crate::packets::types::u16be;
use crate::packets::{Internal, Packet};
use crate::{ensure, Mbuf, SizeOf};
use failure::Fallible;
use std::fmt;
use std::ptr::NonNull;

const ETH_HEADER_SIZE: usize = 14;

// Tag protocol identifiers.
const VLAN_802_1Q: u16 = 0x8100;
const VLAN_802_1AD: u16 = 0x88a8;

/// Ethernet II frame.
///
/// This is an implementation of the Ethernet II frame specified in IEEE
/// 802.3. The payload can have a size up to the MTU of 1500 octets, or
/// more in the case of jumbo frames. The frame check sequence or FCS that
/// follows the payload is handled by the hardware and is not included.
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Dst MAC  |  Src MAC  |Typ|             Payload               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+                                   |
/// |                                                               |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// - *Destination MAC*: 48-bit MAC address of the originator of the packet.
///
/// - *Source MAC*:      48-bit MAC address of the intended recipient of
///                      the packet.
///
/// - *Ether Type*:      16-bit indicator. Identifies which protocol is
///                      encapsulated in the payload of the frame.
///
/// # 802.1Q aka Dot1q
///
/// For networks support virtual LANs, the frame may include an extra VLAN
/// tag after the source MAC as specified in [IEEE 802.1Q].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Dst MAC  |  Src MAC  | V-TAG |Typ|          Payload          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// The tag has the following format, with TPID set to `0x8100`.
///
/// ```
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   16 bits   | 3 bits  | 1 bit | 12 bits |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             |            TCI            |
/// +    TPID     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             |   PCP   |  DEI  |   VID   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// - *TPID*:            16-bit tag protocol identifier, located at the same
///                      position as the EtherType field in untagged frames.
///
/// - *TCI*:             16-bit tag control information containing the following
///                      sub-fields.
///
/// - *PCP*:             3-bit priority code point which refers to the IEEE
///                      802.1p class of service and maps to the frame priority
///                      level.
///
/// - *DEI*:             1-bit drop eligible indicator, may be used separately
///                      or in conjunction with PCP to indicate frames eligible
///                      to be dropped in the presence of congestion.
///
/// - *VID*:             12-bit VLAN identifier specifying the VLAN to which the
///                      frame belongs.
///
/// # 802.1ad aka QinQ
///
/// The frame may be double tagged as per [IEEE 802.1ad].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Dst MAC  |  Src MAC  | S-TAG | C-TAG |Typ|     Payload       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Double tagging can be useful for ISPs, allowing them to use VLANs internally
/// while mixing traffic from clients that are already VLAN tagged. The outer
/// S-TAG, or service tag, comes first, followed by the inner C-TAG, or customer
/// tag. In such cases, 802.1ad specifies a TPID of `0x88a8` for S-TAG.
///
/// [IEEE 802.1Q]: https://en.wikipedia.org/wiki/IEEE_802.1Q
/// [IEEE 802.1ad]: https://en.wikipedia.org/wiki/IEEE_802.1ad
pub struct Ethernet {
    envelope: Mbuf,
    header: NonNull<EthernetHeader>,
    offset: usize,
}

impl Ethernet {
    #[inline]
    fn header(&self) -> &EthernetHeader {
        unsafe { self.header.as_ref() }
    }

    #[inline]
    fn header_mut(&mut self) -> &mut EthernetHeader {
        unsafe { self.header.as_mut() }
    }

    /// Returns the source MAC address.
    #[inline]
    pub fn src(&self) -> MacAddr {
        self.header().src
    }

    /// Sets the source MAC address.
    #[inline]
    pub fn set_src(&mut self, src: MacAddr) {
        self.header_mut().src = src
    }

    /// Returns the destination MAC address.
    #[inline]
    pub fn dst(&self) -> MacAddr {
        self.header().dst
    }

    /// Sets the destination MAC address.
    #[inline]
    pub fn set_dst(&mut self, dst: MacAddr) {
        self.header_mut().dst = dst
    }

    /// Returns the marker that indicates whether the frame is VLAN.
    #[inline]
    fn vlan_marker(&self) -> u16 {
        unsafe { self.header().chunk.ether_type.into() }
    }

    /// Returns the protocol identifier of the payload.
    #[inline]
    pub fn ether_type(&self) -> EtherType {
        let header = self.header();
        let ether_type = unsafe {
            match self.vlan_marker() {
                VLAN_802_1Q => header.chunk.dot1q.ether_type,
                VLAN_802_1AD => header.chunk.qinq.ether_type,
                _ => header.chunk.ether_type,
            }
        };

        EtherType::new(ether_type.into())
    }

    /// Sets the protocol identifier of the payload.
    #[inline]
    pub fn set_ether_type(&mut self, ether_type: EtherType) {
        let ether_type = ether_type.0.into();
        match self.vlan_marker() {
            VLAN_802_1Q => self.header_mut().chunk.dot1q.ether_type = ether_type,
            VLAN_802_1AD => self.header_mut().chunk.qinq.ether_type = ether_type,
            _ => self.header_mut().chunk.ether_type = ether_type,
        }
    }

    /// Returns whether the frame is VLAN Dot1q (802.1Q) tagged.
    #[inline]
    pub fn is_dot1q(&self) -> bool {
        self.vlan_marker() == VLAN_802_1Q
    }

    /// Returns whether the frame is VLAN QinQ (802.1ad) tagged.
    #[inline]
    pub fn is_qinq(&self) -> bool {
        self.vlan_marker() == VLAN_802_1AD
    }

    /// Swaps the source MAC address with the destination MAC address.
    #[inline]
    pub fn swap_addresses(&mut self) {
        let src = self.src();
        let dst = self.dst();
        self.set_src(dst);
        self.set_dst(src);
    }
}

impl fmt::Debug for Ethernet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ethernet")
            .field("src", &format!("{}", self.src()))
            .field("dst", &format!("{}", self.dst()))
            .field("ether_type", &format!("{}", self.ether_type()))
            .field("vlan", &(self.is_dot1q() || self.is_qinq()))
            .field("$offset", &self.offset())
            .field("$len", &self.len())
            .field("$header_len", &self.header_len())
            .finish()
    }
}

impl Packet for Ethernet {
    /// The preceding type for Ethernet must be `Mbuf`.
    type Envelope = Mbuf;

    #[inline]
    fn envelope(&self) -> &Self::Envelope {
        &self.envelope
    }

    #[inline]
    fn envelope_mut(&mut self) -> &mut Self::Envelope {
        &mut self.envelope
    }

    #[inline]
    fn offset(&self) -> usize {
        self.offset
    }

    /// Returns the length of the packet header.
    ///
    /// The length of the Ethernet header depends on the VLAN tags.
    #[inline]
    fn header_len(&self) -> usize {
        if self.is_dot1q() {
            EthernetHeader::size_of() + VlanTag::size_of()
        } else if self.is_qinq() {
            EthernetHeader::size_of() + VlanTag::size_of() * 2
        } else {
            EthernetHeader::size_of()
        }
    }

    #[inline]
    unsafe fn clone(&self, internal: Internal) -> Self {
        Ethernet {
            envelope: self.envelope.clone(internal),
            header: self.header,
            offset: self.offset,
        }
    }

    #[inline]
    fn try_parse(envelope: Self::Envelope, _internal: Internal) -> Fallible<Self> {
        let mbuf = envelope.mbuf();
        let offset = envelope.payload_offset();
        let header = mbuf.read_data(offset)?;

        let packet = Ethernet {
            envelope,
            header,
            offset,
        };

        // we've only parsed 14 bytes as the Ethernet header, in case of
        // vlan, we need to make sure there's enough data for the whole
        // header including tags, otherwise accessing the union type in the
        // header will cause a panic.
        ensure!(
            packet.mbuf().data_len() >= packet.header_len(),
            BufferError::OutOfBuffer(packet.header_len(), packet.mbuf().data_len())
        );

        Ok(packet)
    }

    #[inline]
    fn try_push(mut envelope: Self::Envelope, _internal: Internal) -> Fallible<Self> {
        let offset = envelope.payload_offset();
        let mbuf = envelope.mbuf_mut();

        // can't write `EthernetHeader` directly because the union size
        // is actually 22 (14 + double vlan tags). writing the union into
        // the buffer will cause data corruption because it will write
        // past the 14 bytes we extended the buffer by.
        mbuf.extend(offset, ETH_HEADER_SIZE)?;
        let _ = mbuf.write_data_slice(offset, &[0; ETH_HEADER_SIZE])?;
        let header = mbuf.read_data(offset)?;

        Ok(Ethernet {
            envelope,
            header,
            offset,
        })
    }

    #[inline]
    fn deparse(self) -> Self::Envelope {
        self.envelope
    }
}

/// The protocol identifier of the Ethernet frame payload.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
pub struct EtherType(pub u16);

impl EtherType {
    /// Creates an Ethernet payload protocol identifier.
    pub fn new(value: u16) -> Self {
        EtherType(value)
    }
}

/// Supported Ethernet payload protocol types.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod EtherTypes {
    use super::EtherType;

    /// Address resolution protocol.
    pub const Arp: EtherType = EtherType(0x0806);
    /// Internet Protocol version 4.
    pub const Ipv4: EtherType = EtherType(0x0800);
    /// Internet Protocol version 6.
    pub const Ipv6: EtherType = EtherType(0x86DD);
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                EtherTypes::Arp => "ARP".to_string(),
                EtherTypes::Ipv4 => "IPv4".to_string(),
                EtherTypes::Ipv6 => "IPv6".to_string(),
                _ => {
                    let t = self.0;
                    format!("0x{:04x}", t)
                }
            }
        )
    }
}

/// VLAN tag.
#[derive(Clone, Copy, Debug, Default, SizeOf)]
#[repr(C, packed)]
struct VlanTag {
    tpid: u16be,
    tci: u16be,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
impl VlanTag {
    /// Returns the tag protocol identifier, either 802.1q (Dot1q) or 802.1ad (QinQ).
    #[allow(dead_code)]
    #[inline]
    fn tag_id(&self) -> u16 {
        self.tpid.into()
    }

    /// Returns the priority code point.
    #[allow(dead_code)]
    #[inline]
    fn priority(&self) -> u8 {
        let tci: u16 = self.tci.into();
        (tci >> 13) as u8
    }

    /// Returns whether the frame is eligible to be dropped in the presence
    /// of congestion.
    #[allow(dead_code)]
    #[inline]
    fn drop_eligible(&self) -> bool {
        self.tci & u16be::from(0x1000) > u16be::MIN
    }

    /// Returns the VLAN identifier.
    #[allow(dead_code)]
    #[inline]
    fn identifier(&self) -> u16 {
        (self.tci & u16be::from(0x0fff)).into()
    }
}

/// Dot1q chunk for a VLAN header.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
struct Dot1q {
    tag: VlanTag,
    ether_type: u16be,
}

/// QinQ chunk for a VLAN header.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
struct Qinq {
    stag: VlanTag,
    ctag: VlanTag,
    ether_type: u16be,
}

/// The Ethernet header chunk follows the source MAC.
#[allow(missing_debug_implementations)]
#[derive(Clone, Copy)]
#[repr(C, packed)]
union Chunk {
    ether_type: u16be,
    dot1q: Dot1q,
    qinq: Qinq,
}

impl Default for Chunk {
    fn default() -> Chunk {
        Chunk {
            ether_type: u16be::default(),
        }
    }
}

/// Ethernet header.
#[allow(missing_debug_implementations)]
#[derive(Clone, Copy, Default)]
#[repr(C, packed)]
struct EthernetHeader {
    dst: MacAddr,
    src: MacAddr,
    chunk: Chunk,
}

impl SizeOf for EthernetHeader {
    /// Size of the Ethernet header.
    ///
    /// Because the Ethernet header is not fixed and modeled with a union, the
    /// memory layout size is not the correct header size. For a brand new
    /// Ethernet header, we will always report 14 bytes as the fixed portion,
    /// which is the minimum size without any tags. `Ethernet::header_len()`
    /// will report the correct instance size based on the presence or absence
    /// of VLAN tags.
    #[inline]
    fn size_of() -> usize {
        ETH_HEADER_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testils::byte_arrays::{IPV4_UDP_PACKET, VLAN_DOT1Q_PACKET, VLAN_QINQ_PACKET};

    #[test]
    fn size_of_ethernet_header() {
        assert_eq!(14, EthernetHeader::size_of());
    }

    #[test]
    fn ether_type_to_string() {
        assert_eq!("ARP", EtherTypes::Arp.to_string());
        assert_eq!("IPv4", EtherTypes::Ipv4.to_string());
        assert_eq!("IPv6", EtherTypes::Ipv6.to_string());
        assert_eq!("0x0000", EtherType::new(0).to_string());
    }

    #[capsule::test]
    fn parse_ethernet_packet() {
        let packet = Mbuf::from_bytes(&IPV4_UDP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();

        assert_eq!("00:00:00:00:00:01", ethernet.dst().to_string());
        assert_eq!("00:00:00:00:00:02", ethernet.src().to_string());
        assert_eq!(EtherTypes::Ipv4, ethernet.ether_type());
    }

    #[capsule::test]
    fn parse_dot1q_packet() {
        let packet = Mbuf::from_bytes(&VLAN_DOT1Q_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();

        assert_eq!("00:00:00:00:00:01", ethernet.dst().to_string());
        assert_eq!("00:00:00:00:00:02", ethernet.src().to_string());
        assert!(ethernet.is_dot1q());
        assert_eq!(EtherTypes::Arp, ethernet.ether_type());
        assert_eq!(18, ethernet.header_len());
    }

    #[capsule::test]
    fn parse_qinq_packet() {
        let packet = Mbuf::from_bytes(&VLAN_QINQ_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();

        assert_eq!("00:00:00:00:00:01", ethernet.dst().to_string());
        assert_eq!("00:00:00:00:00:02", ethernet.src().to_string());
        assert!(ethernet.is_qinq());
        assert_eq!(EtherTypes::Arp, ethernet.ether_type());
        assert_eq!(22, ethernet.header_len());
    }

    #[capsule::test]
    fn swap_addresses() {
        let packet = Mbuf::from_bytes(&IPV4_UDP_PACKET).unwrap();
        let mut ethernet = packet.parse::<Ethernet>().unwrap();
        ethernet.swap_addresses();

        assert_eq!("00:00:00:00:00:02", ethernet.dst().to_string());
        assert_eq!("00:00:00:00:00:01", ethernet.src().to_string());
    }

    #[capsule::test]
    fn push_ethernet_packet() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();

        assert_eq!(EthernetHeader::size_of(), ethernet.len());
    }

    /// Bug in v0.1.3 when pushing an Ethernet packet.
    ///
    /// Because `EthernetHeader` is a union, writing it directly into the
    /// buffer causes the 8 bytes following the 14-byte tagless header to be
    /// corrupted. The following code caused the bug.
    ///
    /// ```
    /// mbuf.extend(offset, 14)?;
    /// mbuf.write_data(offset, &EthernetHeader::default())?;
    /// ```
    #[capsule::test]
    fn bug_push_ethernet_corrupts_buffer() {
        let data = [255u8; 8];
        let packet = Mbuf::from_bytes(&data).unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();

        let overflow = ethernet.mbuf().read_data_slice::<u8>(14, 8).unwrap();
        assert_eq!(&data, unsafe { overflow.as_ref() });
    }
}
