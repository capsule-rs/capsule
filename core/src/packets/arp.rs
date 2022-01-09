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

use crate::ensure;
use crate::net::MacAddr;
use crate::packets::ethernet::{EtherType, EtherTypes, Ethernet};
use crate::packets::types::u16be;
use crate::packets::{Datalink, Internal, Packet, SizeOf};
use anyhow::{anyhow, Result};
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
/// |                   Sender Hardware Address                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Sender Protocol Address                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Target Hardware Address                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Target Protocol Address                     |
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
/// - *Sender Hardware Address*: (variable)
///      Hardware address of the sender. In an ARP request this field is used
///      to indicate the address of the host sending the request. In an ARP
///      reply this field is used to indicate the address of the host that the
///      request was looking for. The address size is defined by *H Length*.
///
/// - *Sender Protocol Address*: (variable)
///      Protocol address of the sender. The address size is defined by
///      *P Length*.
///
/// - *Target Hardware Address*: (variable)
///      Hardware address of the intended receiver. In an ARP request this
///      field is ignored. In an ARP reply this field is used to indicate the
///      address of the host that originated the ARP request. The address
///      size is defined by *H Length*.
///
/// - *Target Protocol Address*: (variable)
///      Protocol address of the intended receiver. The address size is
///      defined by *P Length*.
///
/// [IETF RFC 826]: https://tools.ietf.org/html/rfc826
pub struct Arp<E: Datalink = Ethernet, H: HardwareAddr = MacAddr, P: ProtocolAddr = Ipv4Addr> {
    envelope: E,
    header: NonNull<ArpHeader<H, P>>,
    offset: usize,
}

impl<E: Datalink, H: HardwareAddr, P: ProtocolAddr> Arp<E, H, P> {
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
    ///
    /// [IANA] assigned Protocol type numbers share the same space as
    /// [`EtherTypes`].
    ///
    /// [IANA]: https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-3
    /// [`EtherTypes`]: crate::packets::ethernet::EtherTypes
    #[inline]
    pub fn protocol_type(&self) -> EtherType {
        EtherType::new(self.header().protocol_type.into())
    }

    /// Sets the protocol type.
    #[inline]
    fn set_protocol_type(&mut self, protocol_type: EtherType) {
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

    /// Returns the sender hardware address.
    #[inline]
    pub fn sender_hardware_addr(&self) -> H {
        self.header().sender_hardware_addr
    }

    /// Sets the sender hardware address.
    #[inline]
    pub fn set_sender_hardware_addr(&mut self, addr: H) {
        self.header_mut().sender_hardware_addr = addr
    }

    /// Returns the sender protocol address.
    #[inline]
    pub fn sender_protocol_addr(&self) -> P {
        self.header().sender_protocol_addr
    }

    /// Sets the sender protocol address.
    #[inline]
    pub fn set_sender_protocol_addr(&mut self, addr: P) {
        self.header_mut().sender_protocol_addr = addr
    }

    /// Returns the target hardware address.
    #[inline]
    pub fn target_hardware_addr(&self) -> H {
        self.header().target_hardware_addr
    }

    /// Sets the target hardware address.
    #[inline]
    pub fn set_target_hardware_addr(&mut self, addr: H) {
        self.header_mut().target_hardware_addr = addr
    }

    /// Returns the target protocol address.
    #[inline]
    pub fn target_protocol_addr(&self) -> P {
        self.header().target_protocol_addr
    }

    /// Sets the target protocol address.
    #[inline]
    pub fn set_target_protocol_addr(&mut self, addr: P) {
        self.header_mut().target_protocol_addr = addr
    }
}

impl<E: Datalink, H: HardwareAddr, P: ProtocolAddr> fmt::Debug for Arp<E, H, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("arp")
            .field("hardware_type", &format!("{}", self.hardware_type()))
            .field("protocol_type", &format!("{}", self.protocol_type()))
            .field("hardware_addr_len", &self.hardware_addr_len())
            .field("protocol_addr_len", &self.protocol_addr_len())
            .field("operation_code", &format!("{}", self.operation_code()))
            .field(
                "sender_hardware_addr",
                &format!("{}", self.sender_hardware_addr()),
            )
            .field(
                "sender_protocol_addr",
                &format!("{}", self.sender_protocol_addr()),
            )
            .field(
                "target_hardware_addr",
                &format!("{}", self.target_hardware_addr()),
            )
            .field(
                "target_protocol_addr",
                &format!("{}", self.target_protocol_addr()),
            )
            .field("$offset", &self.offset())
            .field("$len", &self.len())
            .field("$header_len", &self.header_len())
            .finish()
    }
}

impl<E: Datalink, H: HardwareAddr, P: ProtocolAddr> Packet for Arp<E, H, P> {
    type Envelope = E;

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

    /// Parses the payload as an ARP packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the [`ether_type`] is not set to [`EtherTypes::ARP`].
    /// Returns an error if the payload does not have sufficient data for the
    /// ARP header. Returns an error if any of the following values does not match
    /// expectation.
    ///   * hardware type
    ///   * hardware address length
    ///   * protocol type
    ///   * protocol address length
    ///
    /// [`ether_type`]: Ethernet::ether_type
    /// [`EtherTypes::Arp`]: EtherTypes::Arp
    #[inline]
    fn try_parse(envelope: Self::Envelope, _internal: Internal) -> Result<Self> {
        ensure!(
            envelope.protocol_type() == EtherTypes::Arp,
            anyhow!("not an ARP packet.")
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
            anyhow!(
                "hardware type {} does not match expected {}.",
                packet.hardware_type(),
                H::addr_type()
            )
        );
        ensure!(
            packet.protocol_type() == P::addr_type(),
            anyhow!(
                "protocol type {} does not match expected {}.",
                packet.protocol_type(),
                P::addr_type()
            )
        );
        ensure!(
            packet.hardware_addr_len() == H::size_of() as u8,
            anyhow!(
                "hardware address length {} does not match expected {}.",
                packet.hardware_addr_len(),
                H::size_of()
            )
        );
        ensure!(
            packet.protocol_addr_len() == P::size_of() as u8,
            anyhow!(
                "protocol address length {} does not match expected {}.",
                packet.protocol_addr_len(),
                P::size_of()
            )
        );

        Ok(packet)
    }

    /// Prepends an ARP packet to the beginning of the Ethernet's payload.
    ///
    /// [`ether_type`] is set to [`EtherTypes::Arp`]. `hardware_type`,
    /// `hardware_addr_len`, `protocol_type`, `protocol_addr_len` are set
    /// based on `H` and `P`.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer does not have enough free space.
    ///
    /// [`ether_type`]: Ethernet::ether_type
    /// [`EtherTypes::Arp`]: EtherTypes::Arp
    #[inline]
    fn try_push(mut envelope: Self::Envelope, _internal: Internal) -> Result<Self> {
        let offset = envelope.payload_offset();
        let mbuf = envelope.mbuf_mut();

        mbuf.extend(offset, ArpHeader::<H, P>::size_of())?;
        let header = mbuf.write_data(offset, &ArpHeader::<H, P>::default())?;

        envelope.set_protocol_type(EtherTypes::Arp);

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
    fn addr_type() -> EtherType;

    /// Returns the default value.
    ///
    /// This is synonymous with `Default::default`, but is necessary when
    /// an external crate type doesn't implement the `Default` trait.
    fn default() -> Self;
}

impl ProtocolAddr for Ipv4Addr {
    fn addr_type() -> EtherType {
        EtherTypes::Ipv4
    }

    fn default() -> Self {
        Ipv4Addr::UNSPECIFIED
    }
}

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
    sender_hardware_addr: H,
    sender_protocol_addr: P,
    target_hardware_addr: H,
    target_protocol_addr: P,
}

impl<H: HardwareAddr, P: ProtocolAddr> Clone for ArpHeader<H, P> {
    fn clone(&self) -> Self {
        ArpHeader {
            hardware_type: self.hardware_type,
            protocol_type: self.protocol_type,
            hardware_addr_len: self.hardware_addr_len,
            protocol_addr_len: self.protocol_addr_len,
            operation_code: self.operation_code,
            sender_hardware_addr: self.sender_hardware_addr,
            sender_protocol_addr: self.sender_protocol_addr,
            target_hardware_addr: self.target_hardware_addr,
            target_protocol_addr: self.target_protocol_addr,
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
            sender_hardware_addr: H::default(),
            sender_protocol_addr: P::default(),
            target_hardware_addr: H::default(),
            target_protocol_addr: P::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::Mbuf;
    use crate::testils::byte_arrays::ARP_PACKET;

    #[test]
    fn size_of_arp_header() {
        assert_eq!(28, ArpHeader::<MacAddr, Ipv4Addr>::size_of());
    }

    #[capsule::test]
    fn parse_arp_packet() {
        let packet = Mbuf::from_bytes(&ARP_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let arp = ethernet.parse::<Arp>().unwrap();

        assert_eq!(HardwareTypes::Ethernet, arp.hardware_type());
        assert_eq!(EtherTypes::Ipv4, arp.protocol_type());
        assert_eq!(6, arp.hardware_addr_len());
        assert_eq!(4, arp.protocol_addr_len());
        assert_eq!(OperationCodes::Request, arp.operation_code());
        assert_eq!("00:00:00:00:00:01", arp.sender_hardware_addr().to_string());
        assert_eq!("139.133.217.110", arp.sender_protocol_addr().to_string());
        assert_eq!("00:00:00:00:00:00", arp.target_hardware_addr().to_string());
        assert_eq!("139.133.233.2", arp.target_protocol_addr().to_string());
    }

    #[capsule::test]
    fn push_arp_packet() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let mut arp = ethernet.push::<Arp>().unwrap();

        assert_eq!(ArpHeader::<MacAddr, Ipv4Addr>::size_of(), arp.len());

        // make sure types are set properly
        assert_eq!(HardwareTypes::Ethernet, arp.hardware_type());
        assert_eq!(EtherTypes::Ipv4, arp.protocol_type());
        assert_eq!(6, arp.hardware_addr_len());
        assert_eq!(4, arp.protocol_addr_len());

        // check the setters
        arp.set_operation_code(OperationCodes::Reply);
        assert_eq!(OperationCodes::Reply, arp.operation_code());
        arp.set_sender_hardware_addr(MacAddr::new(0, 0, 0, 0, 0, 1));
        assert_eq!("00:00:00:00:00:01", arp.sender_hardware_addr().to_string());
        arp.set_sender_protocol_addr(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!("10.0.0.1", arp.sender_protocol_addr().to_string());
        arp.set_target_hardware_addr(MacAddr::new(0, 0, 0, 0, 0, 2));
        assert_eq!("00:00:00:00:00:02", arp.target_hardware_addr().to_string());
        arp.set_target_protocol_addr(Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!("10.0.0.2", arp.target_protocol_addr().to_string());

        // make sure the ether type is fixed
        assert_eq!(EtherTypes::Arp, arp.envelope().ether_type());
    }
}
