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

//! Address Resolution Protocol.

use crate::net::MacAddr;
use crate::packets::types::u16be;
use crate::packets::{EtherTypes, Ethernet, Internal, Packet, ParseError};
use crate::{ensure, SizeOf};
use failure::Fallible;
use std::fmt;
use std::net::Ipv4Addr;
use std::ptr::NonNull;

/// Address Resolution Protocol packet based on [IETF RFC 826].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Hardware Type         |         Protocol Type         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    H Length   |    P Length   |         Operation Code        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Source Hardware Address                     
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Source Protocol Address                     
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Target Hardware Address                     
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Target Protocol Address                     
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// - *Hardware Type*: (16 bits)
///      The network link protocol type.
///
/// - *Protocol Type*: (16 bits)
///      The internetwork protocol for which the ARP request is intended.
///
/// - *H Length*: (8 bits)
///      Length (in octets) of a hardware address.
///
/// - *P Length*: (8 bits)
///      Length (in octets) of a protocol address.
///
/// - *Operation Code*: (16 bits)
///      The operation that the sender is performing.
///
/// - *Source Hardware Address*: (H length octets)
///      Hardware address of the sender. In an ARP request this field is used
///      to indicate the address of the host sending the request. In an ARP
///      reply this field is used to indicate the address of the host that the
///      request was looking for.
///
/// - *Source Protocol Address*: (P length octets)
///      Protocol address of the sender.
///
/// - *Target Hardware Address*: (H length octets)
///      Hardware address of the intended receiver. In an ARP request this
///      field is ignored. In an ARP reply this field is used to indicate the
///      address of the host that originated the ARP request.
///
/// - *Target Protocol Address*: (P length octets)
///      Protocol address of the intended receiver.
///
/// [IETF RFC 826]: https://tools.ietf.org/html/rfc826
pub struct Arp<H: HardwareAddr, P: ProtocolAddr> {
    envelope: Ethernet,
    header: NonNull<ArpHeader<H, P>>,
    offset: usize,
}

impl<H: HardwareAddr, P: ProtocolAddr> Arp<H, P> {
    #[inline]
    fn header(&self) -> &ArpHeader<H, P> {
        unsafe { self.header.as_ref() }
    }

    #[inline]
    fn header_mut(&mut self) -> &mut ArpHeader<H, P> {
        unsafe { self.header.as_mut() }
    }

    /// Returns the hardware type.
    #[inline]
    pub fn hardware_type(&self) -> HardwareType {
        HardwareType::new(self.header().hardware_type.into())
    }

    /// Sets the hardware type.
    #[inline]
    fn set_hardware_type(&mut self, hardware_type: HardwareType) {
        self.header_mut().hardware_type = hardware_type.0.into()
    }

    /// Returns the protocol type.
    #[inline]
    pub fn protocol_type(&self) -> ProtocolType {
        ProtocolType::new(self.header().protocol_type.into())
    }

    /// Sets the protocol type.
    #[inline]
    fn set_protocol_type(&mut self, protocol_type: ProtocolType) {
        self.header_mut().protocol_type = protocol_type.0.into()
    }

    /// Returns the hardware address length.
    #[inline]
    pub fn hardware_addr_len(&self) -> u8 {
        self.header().hardware_addr_len
    }

    /// Sets the hardware address length.
    #[inline]
    fn set_hardware_addr_len(&mut self, len: u8) {
        self.header_mut().hardware_addr_len = len
    }

    /// Returns the protocol address length.
    #[inline]
    pub fn protocol_addr_len(&self) -> u8 {
        self.header().protocol_addr_len
    }

    /// Sets the protocol address length.
    #[inline]
    fn set_protocol_addr_len(&mut self, len: u8) {
        self.header_mut().protocol_addr_len = len
    }

    /// Returns the operation code.
    #[inline]
    pub fn operation_code(&self) -> OperationCode {
        OperationCode::new(self.header().operation_code.into())
    }

    /// Sets the operation code.
    #[inline]
    pub fn set_operation_code(&mut self, code: OperationCode) {
        self.header_mut().operation_code = code.0.into()
    }

    /// Returns the source hardware address.
    #[inline]
    pub fn src_hardware_addr(&self) -> H {
        self.header().src_hardware_addr
    }

    /// Sets the source hardware address.
    #[inline]
    pub fn set_src_hardware_addr(&mut self, addr: H) {
        self.header_mut().src_hardware_addr = addr
    }

    /// Returns the source protocol address.
    #[inline]
    pub fn src_protocol_addr(&self) -> P {
        self.header().src_protocol_addr
    }

    /// Sets the source protocol address.
    #[inline]
    pub fn set_src_protocol_addr(&mut self, addr: P) {
        self.header_mut().src_protocol_addr = addr
    }

    /// Returns the target hardware address.
    #[inline]
    pub fn tgt_hardware_addr(&self) -> H {
        self.header().tgt_hardware_addr
    }

    /// Sets the target hardware address.
    #[inline]
    pub fn set_tgt_hardware_addr(&mut self, addr: H) {
        self.header_mut().tgt_hardware_addr = addr
    }

    /// Returns the target protocol address.
    #[inline]
    pub fn tgt_protocol_addr(&self) -> P {
        self.header().tgt_protocol_addr
    }

    /// Sets the target protocol address.
    #[inline]
    pub fn set_tgt_protocol_addr(&mut self, addr: P) {
        self.header_mut().tgt_protocol_addr = addr
    }
}

impl<H: HardwareAddr, P: ProtocolAddr> fmt::Debug for Arp<H, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("arp")
            .field("hardware_type", &format!("{}", self.hardware_type()))
            .field("protocol_type", &format!("{}", self.protocol_type()))
            .field("hardware_addr_len", &self.hardware_addr_len())
            .field("protocol_addr_len", &self.protocol_addr_len())
            .field("operation_code", &format!("{}", self.operation_code()))
            .field(
                "src_hardware_addr",
                &format!("{}", self.src_hardware_addr()),
            )
            .field(
                "src_protocol_addr",
                &format!("{}", self.src_protocol_addr()),
            )
            .field(
                "tgt_hardware_addr",
                &format!("{}", self.tgt_hardware_addr()),
            )
            .field(
                "tgt_protocol_addr",
                &format!("{}", self.tgt_protocol_addr()),
            )
            .field("$offset", &self.offset())
            .field("$len", &self.len())
            .field("$header_len", &self.header_len())
            .finish()
    }
}

impl<H: HardwareAddr, P: ProtocolAddr> Packet for Arp<H, P> {
    /// The preceding type for ARP must be `Ethernet`.
    type Envelope = Ethernet;

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

    #[inline]
    fn header_len(&self) -> usize {
        ArpHeader::<H, P>::size_of()
    }

    #[inline]
    unsafe fn clone(&self, internal: Internal) -> Self {
        Arp {
            envelope: self.envelope.clone(internal),
            header: self.header,
            offset: self.offset,
        }
    }

    #[inline]
    fn try_parse(envelope: Self::Envelope, _internal: Internal) -> Fallible<Self> {
        ensure!(
            envelope.ether_type() == EtherTypes::Arp,
            ParseError::new("not an ARP packet.")
        );

        let mbuf = envelope.mbuf();
        let offset = envelope.payload_offset();
        let header = mbuf.read_data(offset)?;

        let packet = Arp {
            envelope,
            header,
            offset,
        };

        ensure!(
            packet.hardware_type() == H::addr_type(),
            ParseError::new(&format!(
                "hardware type {} does not match expected {}.",
                packet.hardware_type(),
                H::addr_type()
            ))
        );
        ensure!(
            packet.protocol_type() == P::addr_type(),
            ParseError::new(&format!(
                "protocol type {} does not match expected {}.",
                packet.protocol_type(),
                P::addr_type()
            ))
        );
        ensure!(
            packet.hardware_addr_len() == H::size_of() as u8,
            ParseError::new(&format!(
                "hardware address length {} does not match expected {}.",
                packet.hardware_addr_len(),
                H::size_of()
            ))
        );
        ensure!(
            packet.protocol_addr_len() == P::size_of() as u8,
            ParseError::new(&format!(
                "protocol address length {} does not match expected {}.",
                packet.protocol_addr_len(),
                P::size_of()
            ))
        );

        Ok(packet)
    }

    #[inline]
    fn try_push(mut envelope: Self::Envelope, _internal: Internal) -> Fallible<Self> {
        let offset = envelope.payload_offset();
        let mbuf = envelope.mbuf_mut();

        mbuf.extend(offset, ArpHeader::<H, P>::size_of())?;
        let header = mbuf.write_data(offset, &ArpHeader::<H, P>::default())?;

        envelope.set_ether_type(EtherTypes::Arp);

        let mut packet = Arp {
            envelope,
            header,
            offset,
        };

        packet.set_hardware_type(H::addr_type());
        packet.set_protocol_type(P::addr_type());
        packet.set_hardware_addr_len(H::size_of() as u8);
        packet.set_protocol_addr_len(P::size_of() as u8);

        Ok(packet)
    }

    #[inline]
    fn deparse(self) -> Self::Envelope {
        self.envelope
    }
}

/// [IANA] assigned hardware type.
///
/// See [`HardwareTypes`] for which are current supported.
///
/// [IANA]: https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-2
/// [`HardwareTypes`]: crate::packets::arp::HardwareTypes
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
pub struct HardwareType(u16);

impl HardwareType {
    /// Creates a new hardware type.
    pub fn new(value: u16) -> Self {
        HardwareType(value)
    }
}

/// Supported hardware types.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod HardwareTypes {
    use super::HardwareType;

    /// Ethernet.
    pub const Ethernet: HardwareType = HardwareType(0x0001);
}

impl fmt::Display for HardwareType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                HardwareTypes::Ethernet => "Ethernet".to_string(),
                _ => {
                    let t = self.0;
                    format!("0x{:04x}", t)
                }
            }
        )
    }
}

/// [IANA] assigned protocol type.
///
/// See [`ProtocolTypes`] for which are current supported.
///
/// [IANA]: https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-3
/// [`ProtocolTypes`]: crate::packets::arp::ProtocolTypes
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
pub struct ProtocolType(u16);

impl ProtocolType {
    /// Creates a new protocol type.
    pub fn new(value: u16) -> Self {
        ProtocolType(value)
    }
}

/// Supported protocol types.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod ProtocolTypes {
    use super::ProtocolType;

    /// Internet protocol version 4.
    pub const Ipv4: ProtocolType = ProtocolType(0x0800);
}

impl fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                ProtocolTypes::Ipv4 => "IPv4".to_string(),
                _ => {
                    let t = self.0;
                    format!("0x{:04x}", t)
                }
            }
        )
    }
}

/// [IANA] assigned operation code.
///
/// See [`OperationCodes`] for which are current supported.
///
/// [IANA]: https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
/// [`OperationCodes`]: crate::packets::arp::OperationCodes
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
pub struct OperationCode(u16);

impl OperationCode {
    /// Creates a new operation code.
    pub fn new(value: u16) -> Self {
        OperationCode(value)
    }
}

/// Supported operation codes.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod OperationCodes {
    use super::OperationCode;

    /// Request.
    pub const Request: OperationCode = OperationCode(1);
    /// Reply.
    pub const Reply: OperationCode = OperationCode(2);
    /// Request reverse.
    pub const RequestReverse: OperationCode = OperationCode(3);
    /// Reply reverse.
    pub const ReplyReverse: OperationCode = OperationCode(4);
}

impl fmt::Display for OperationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                OperationCodes::Request => "Request".to_string(),
                OperationCodes::Reply => "Reply".to_string(),
                OperationCodes::RequestReverse => "Request reverse".to_string(),
                OperationCodes::ReplyReverse => "Reply reverse".to_string(),
                _ => {
                    let t = self.0;
                    format!("0x{:04x}", t)
                }
            }
        )
    }
}

/// A trait implemented by ARP hardware address types.
pub trait HardwareAddr: SizeOf + Copy + fmt::Display {
    /// Returns the associated hardware type of the given address.
    fn addr_type() -> HardwareType;

    /// Returns the default value.
    ///
    /// This is synonymous with `Default::default`, but is necessary when
    /// an external crate type doesn't implement the `Default` trait.
    fn default() -> Self;
}

impl SizeOf for MacAddr {
    fn size_of() -> usize {
        6
    }
}

impl HardwareAddr for MacAddr {
    fn addr_type() -> HardwareType {
        HardwareTypes::Ethernet
    }

    fn default() -> Self {
        Default::default()
    }
}

/// A trait implemented by ARP protocol address types.
pub trait ProtocolAddr: SizeOf + Copy + fmt::Display {
    /// Returns the associated protocol type of the given address.
    fn addr_type() -> ProtocolType;

    /// Returns the default value.
    ///
    /// This is synonymous with `Default::default`, but is necessary when
    /// an external crate type doesn't implement the `Default` trait.
    fn default() -> Self;
}

impl SizeOf for Ipv4Addr {
    fn size_of() -> usize {
        4
    }
}

impl ProtocolAddr for Ipv4Addr {
    fn addr_type() -> ProtocolType {
        ProtocolTypes::Ipv4
    }

    fn default() -> Self {
        Ipv4Addr::UNSPECIFIED
    }
}

/// A type alias for an IPv4 ARP packet.
pub type Arp4 = Arp<MacAddr, Ipv4Addr>;

/// ARP header.
#[allow(missing_debug_implementations)]
#[derive(Copy, SizeOf)]
#[repr(C, packed)]
struct ArpHeader<H: HardwareAddr, P: ProtocolAddr> {
    hardware_type: u16be,
    protocol_type: u16be,
    hardware_addr_len: u8,
    protocol_addr_len: u8,
    operation_code: u16be,
    src_hardware_addr: H,
    src_protocol_addr: P,
    tgt_hardware_addr: H,
    tgt_protocol_addr: P,
}

impl<H: HardwareAddr, P: ProtocolAddr> Clone for ArpHeader<H, P> {
    fn clone(&self) -> Self {
        ArpHeader {
            hardware_type: self.hardware_type,
            protocol_type: self.protocol_type,
            hardware_addr_len: self.hardware_addr_len,
            protocol_addr_len: self.protocol_addr_len,
            operation_code: self.operation_code,
            src_hardware_addr: self.src_hardware_addr,
            src_protocol_addr: self.src_protocol_addr,
            tgt_hardware_addr: self.tgt_hardware_addr,
            tgt_protocol_addr: self.tgt_protocol_addr,
        }
    }
}

impl<H: HardwareAddr, P: ProtocolAddr> Default for ArpHeader<H, P> {
    fn default() -> Self {
        ArpHeader {
            hardware_type: u16be::default(),
            protocol_type: u16be::default(),
            hardware_addr_len: 0,
            protocol_addr_len: 0,
            operation_code: u16be::default(),
            src_hardware_addr: H::default(),
            src_protocol_addr: P::default(),
            tgt_hardware_addr: H::default(),
            tgt_protocol_addr: P::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testils::byte_arrays::ARP4_PACKET;
    use crate::Mbuf;

    #[test]
    fn size_of_arp_header() {
        assert_eq!(28, ArpHeader::<MacAddr, Ipv4Addr>::size_of());
    }

    #[capsule::test]
    fn parse_arp_packet() {
        let packet = Mbuf::from_bytes(&ARP4_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let arp4 = ethernet.parse::<Arp4>().unwrap();

        assert_eq!(HardwareTypes::Ethernet, arp4.hardware_type());
        assert_eq!(ProtocolTypes::Ipv4, arp4.protocol_type());
        assert_eq!(6, arp4.hardware_addr_len());
        assert_eq!(4, arp4.protocol_addr_len());
        assert_eq!(OperationCodes::Request, arp4.operation_code());
        assert_eq!("00:00:00:00:00:01", arp4.src_hardware_addr().to_string());
        assert_eq!("139.133.217.110", arp4.src_protocol_addr().to_string());
        assert_eq!("00:00:00:00:00:00", arp4.tgt_hardware_addr().to_string());
        assert_eq!("139.133.233.2", arp4.tgt_protocol_addr().to_string());
    }

    #[capsule::test]
    fn push_arp_packet() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let mut arp4 = ethernet.push::<Arp4>().unwrap();

        assert_eq!(ArpHeader::<MacAddr, Ipv4Addr>::size_of(), arp4.len());

        // make sure types are set properly
        assert_eq!(HardwareTypes::Ethernet, arp4.hardware_type());
        assert_eq!(ProtocolTypes::Ipv4, arp4.protocol_type());
        assert_eq!(6, arp4.hardware_addr_len());
        assert_eq!(4, arp4.protocol_addr_len());

        // check the setters
        arp4.set_operation_code(OperationCodes::Reply);
        assert_eq!(OperationCodes::Reply, arp4.operation_code());
        arp4.set_src_hardware_addr(MacAddr::new(0, 0, 0, 0, 0, 1));
        assert_eq!("00:00:00:00:00:01", arp4.src_hardware_addr().to_string());
        arp4.set_src_protocol_addr(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!("10.0.0.1", arp4.src_protocol_addr().to_string());
        arp4.set_tgt_hardware_addr(MacAddr::new(0, 0, 0, 0, 0, 2));
        assert_eq!("00:00:00:00:00:02", arp4.tgt_hardware_addr().to_string());
        arp4.set_tgt_protocol_addr(Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!("10.0.0.2", arp4.tgt_protocol_addr().to_string());

        // make sure the ether type is fixed
        assert_eq!(EtherTypes::Arp, arp4.envelope().ether_type());
    }
}
