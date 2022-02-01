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

//! GPRS Tunnelling Protocol (GTPv1) (GTP-U variant)

mod ip4gtpu;

pub use self::ip4gtpu::*;

use crate::ensure;
use crate::packets::types::{u16be, u32be};
use crate::packets::{Internal, Packet, SizeOf};
use anyhow::{anyhow, Result};
use std::fmt;
use std::ptr::NonNull;

/// Option bit flags
const PT: u8 = 0b0001_0000;
const E:  u8 = 0b0000_0100;
const S:  u8 = 0b0000_0010;
const PN: u8 = 0b0000_0001;

/// GPRS Tunnelling Protocol (GTPv1) (GTP-U variant) [3GPP TS 29.281]
///
/// ```
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Ver |P| |E|S|N|    Msg Type   |           Length              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                  Tunnel Endpoint Identifier                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Sequence Number (optional)   |   NPDU (opt)  | NextExt (opt) |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// - *Version Number*: (3 bits)
///     The Version Number field MUST contain the value 1 for GTP-U.
/// 
/// - *PT - Protocol Type*: (1 bit)
///     The Protocol Type field MUST contain the value 1 for GTP-U
///     Reserved1 fields are present and the Checksum field contains valid
///     information.
///
/// - *E - Extension(s) Present*: (1 bit)
///     If the Extensions bit is set to 1, then it indicates that the Extensions
///     field is present in the GTP header.
///
/// - *S - Sequence Number Present*: (1 bit)
///     If the Sequence Number Present bit is set to 1, then it indicates
///     that the Sequence Number field is present.
///
/// - *N/PN - PDU Number Present*: (1 bit)
///     If the PDU  Number Present bit is set to 1, then it indicates
///     that the NPDU field is present.
///
/// If ANY of the three optional fields are present, all four bytes are
/// present in the header (even if only a subset are used)
///
/// A GTP-U encapsulated packet has the form
///
/// ```
///     ---------------------------------
///     |                               |
///     |       Delivery Header         |
///     |                               |
///     ---------------------------------
///     |                               |
///     |       UDP Header              |
///     |                               |
///     ---------------------------------
///     |                               |
///     |       GTP-U Header            |
///     |                               |
///     ---------------------------------
///     |                               |
///     |       Payload packet          |
///     |                               |
///     ---------------------------------
/// ```
///
/// # Remarks
///
/// The implementation of GTP-U treats the payload as opaque. It cannot be
/// parsed or manipulated with type safety. Work with the typed payload
/// packet either before encapsulation or after decapsulation like other
/// tunnel protocols.
///
/// [3GPP TS 29.281]: https://www.etsi.org/deliver/etsi_ts/129200_129299/129281/15.07.00_60/ts_129281v150700p.pdf
pub struct Gtpu<E: GtpuTunnelPacket> {
    envelope: E,
    header: NonNull<GtpuHeader>,
    sequence_number: Option<NonNull<u16be>>,
    npdu_number: Option<NonNull<u8>>,
    offset: usize,
}

/// A trait for packets that can be a GTP-U envelope (usually UDP)
pub trait GtpuTunnelPacket: Packet {
    /// Returns whether the current payload is GTP-U.
    fn gtpu_payload(&self) -> bool;

    /// Marks the envelope to be containing a GTP-U payload.
    fn mark_gtpu_payload(&mut self);
}

impl<E: GtpuTunnelPacket> Gtpu<E> {
    #[inline]
    fn header(&self) -> &GtpuHeader {
        unsafe { self.header.as_ref() }
    }

    #[inline]
    fn header_mut(&mut self) -> &mut GtpuHeader {
        unsafe { self.header.as_mut() }
    }
    /// Returns whether any of the optional fields are present (implying that the 4 additional bytes are present in the header)
    #[inline]
    fn any_optional_fields_present(&self) -> bool {
        self.sequence_number_present()
            || self.npdu_number_present()
            || self.extension_present()
    }

    /// Inserts the additional 4 header bytes required if ANY of the optional fields are present
    #[inline]
    fn extend_for_optional_fields(&mut self) -> Result<()> {
        let offset = self.offset + 8;
        self.mbuf_mut().extend(offset, 4)?;

        Ok(())
    }

    /// Removes the additional 4 header bytes present if ANY of the optional fields are present
    #[inline]
    fn shrink_optional_fields(&mut self) -> Result<()>  {
        let offset = self.offset + 8;
        self.mbuf_mut().shrink(offset, 4)?;

        Ok(())
    }

    /// Sets the length of the payload recorded in the header
    #[inline]
    pub fn set_payload_length(&mut self, len: usize) {
        let len: u16 = len as u16;
        self.header_mut().length = len.into();
    }

    /// Gets the length of the payload recorded in the header
    #[inline]
    pub fn payload_length(&self) -> usize {
        let len:u16 = self.header().length.into();
        len as usize
    }

    /// Sets the TEID (tunnel identifier)
    #[inline]
    pub fn set_teid(&mut self, teid: u32) {
        self.header_mut().teid = teid.into();
    }

    /// Gets the TEID (tunnel identifier)
    #[inline]
    pub fn teid(&self) -> u32 {
        self.header().teid.into()
    }

    /// Returns whether a sequence number is present.
    #[inline]
    pub fn sequence_number_present(&self) -> bool {
        (self.header().flags & S) != 0
    }

    /// Sets the sequence number present flag to true.
    #[inline]
    pub fn set_sequence_number_present(&mut self) -> Result<()> {
        if !self.sequence_number_present()
        {
            if !self.any_optional_fields_present() {
                self.extend_for_optional_fields()?;
            }
            self.header_mut().flags |= S;
            self.sync_optionals()?;
        }

        Ok(())
    }

    /// Sets the sequence number present flag to false and removes the field.
    #[inline]
    pub fn unset_sequence_number_present(&mut self) -> Result<()> {
        if self.sequence_number_present() {

            self.header_mut().flags &= !S;
            self.sync_optionals()?;

            if !self.any_optional_fields_present() {
                self.shrink_optional_fields()?;
            }
        }

        Ok(())
    }

    /// Returns the sequence number or `None` if the option is not set.
    #[inline]
    pub fn sequence_number(&self) -> Option<u16> {
        self.sequence_number.map(|ptr| unsafe { *ptr.as_ref() }.into())
    }

    /// Sets the sequence number field
    #[inline]
    pub fn set_sequence_number(&mut self, sequence_number: u16) {
        // no op if the sequence number present bit not set.
        if let Some(ref mut ptr) = self.sequence_number {
            unsafe { *ptr.as_mut() = sequence_number.into() };
        }
    }

    /// Returns whether a npdu number is present.
    ///
    #[inline]
    pub fn npdu_number_present(&self) -> bool {
        (self.header().flags & PN) != 0
    }

    /// Sets the npdu number present flag to true.
    #[inline]
    pub fn set_npdu_number_present(&mut self) -> Result<()> {
        if !self.npdu_number_present()
        {
            if !self.any_optional_fields_present() {
                self.extend_for_optional_fields()?;
            }
            self.header_mut().flags |= PN;
            self.sync_optionals()?;
        }

        Ok(())
    }

    /// Sets the npdu number present flag to false and removes the field.
    #[inline]
    pub fn unset_npdu_number_present(&mut self) -> Result<()> {
        if self.npdu_number_present() {

            self.header_mut().flags &= !PN;
            self.sync_optionals()?;

            if !self.any_optional_fields_present() {
                self.shrink_optional_fields()?;
            }
        }

        Ok(())
    }

    /// Returns the npdu number or `None` if the option is not set.
    #[inline]
    pub fn npdu_number(&self) -> Option<u8> {
        self.npdu_number.map(|ptr| unsafe { *ptr.as_ref() }.into())
    }

    /// Sets the npdu number field
    #[inline]
    pub fn set_npdu_number(&mut self, npdu_number: u8) {
        // no op if the npdu number present bit not set.
        if let Some(ref mut ptr) = self.npdu_number {
            unsafe { *ptr.as_mut() = npdu_number.into() };
        }
    }


    /// Returns whether at least one extension is present.
    #[inline]
    pub fn extension_present(&self) -> bool {
        (self.header().flags & E) != 0
    }

    /// Returns the number of bytes occupied by extensions, excluding the terminating null
    #[inline]
    fn extensions_len(&self) -> Result<usize> {
        if !self.extension_present() { 
            return Ok(0); 
        }

        let mut offset = self.offset() + 11;
        let start = offset;
        let ptr = self.mbuf().read_data::<u8>(offset)?;
        let mut extension_type = Some(ptr).map(|ptr| unsafe { *ptr.as_ref() }.into()).unwrap_or(0);

        while extension_type != 0 {
            let ptr = self.mbuf().read_data::<u8>(offset+1)?;
            let length = Some(ptr).map(|ptr| unsafe { *ptr.as_ref() }.into()).unwrap_or(1);
            offset = offset+length*4;
            let ptr = self.mbuf().read_data::<u8>(offset)?;
            extension_type = Some(ptr).map(|ptr| unsafe { *ptr.as_ref() }.into()).unwrap_or(0);
        }
        Ok(offset-start)
    }

    /// Returns the version number.
    ///
    /// # Remarks
    ///
    /// Version must always be 1.
    #[inline]
    pub fn version(&self) -> u8 {
        (self.header().flags & 0b1110_0000)>>5
    }

    /// Returns the GTP-U message type
    #[inline]
    pub fn message_type(&self) -> MessageType {
        MessageType::new(self.header().message_type.into())
    }

    /// Sets the GTP-U message type
    #[inline]
    pub fn set_message_type(&mut self, message_type: MessageType) {
        self.header_mut().message_type = message_type.0.into()
    }

    /// Syncs the pointers to optional fields after one of the bits was
    /// changed. The underlying buffer should be adjusted accordingly before
    /// sync or it will corrupt the packet.
    #[inline]
    fn sync_optionals(&mut self) -> Result<()> {

        self.sequence_number = None;
        if self.sequence_number_present() {
            let ptr = self.mbuf().read_data::<u16be>(self.offset + 8)?;
            self.sequence_number = Some(ptr);
        }

        self.npdu_number = None;
        if self.npdu_number_present() {
            let ptr = self.mbuf().read_data::<u8>(self.offset + 10)?;
            self.npdu_number = Some(ptr);
        }

        Ok(())
    }
}

/// The message identifier of the GTP-U message
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(C, packed)]
pub struct MessageType(pub u8);

impl MessageType {
    /// Creates an GTP-U message type identifier.
    pub fn new(value: u8) -> Self {
        MessageType(value)
    }
}

/// Supported GTP-U message types
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod MessageTypes {
    use super::MessageType;

    /// Echo Request.
    pub const EchoRequest: MessageType = MessageType(0x01);
    /// Echo Reply.
    pub const EchoReply: MessageType = MessageType(0x02);
    /// Error Indication..
    pub const ErrorIndication: MessageType = MessageType(0x1a);
    /// Protocol Data Unit (payload)
    pub const PDU: MessageType = MessageType(0xff);
}

impl<E: GtpuTunnelPacket> fmt::Debug for Gtpu<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("gtpu")
            .field("sequence_number_present", &self.sequence_number_present())
            .field("npdu_number_present", &self.npdu_number_present())
            .field("extension_present", &self.extension_present())
            .field("version", &self.version())
            .field("message_type", &self.message_type())
            .field("teid", &self.teid())
            .field(
                "sequence_number",
                &self
                    .sequence_number()
                    .map(|sequence_number| format!("0x{:02x}", sequence_number))
                    .unwrap_or_else(|| "[none]".to_string()),
            )
            .field(
                "npdu_number",
                &self
                    .npdu_number()
                    .map(|npdu_number| format!("0x{:01x}", npdu_number))
                    .unwrap_or_else(|| "[none]".to_string()),
            )
            .field("$offset", &self.offset())
            .field("$len", &self.len())
            .field("$header_len", &self.header_len())
            .finish()
    }
}

impl<E: GtpuTunnelPacket> Packet for Gtpu<E> {
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

    /// Gtpu header is dynamically sized based on the number of set optional
    /// fields.
    #[inline]
    fn header_len(&self) -> usize {
        8 
        + if self.any_optional_fields_present() { 4 } else { 0 }
        + if self.extension_present() { self.extensions_len().unwrap_or(0) } else { 0 }
    }

    #[inline]
    unsafe fn clone(&self, internal: Internal) -> Self {
        Gtpu::<E> {
            envelope: self.envelope.clone(internal),
            header: self.header,
            sequence_number: self.sequence_number,
            npdu_number: self.npdu_number,
            offset: self.offset,
        }
    }

    /// Parses the envelope's payload as a GTP-U packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the envelope's payload is not GTP-U.
    #[inline]
    fn try_parse(envelope: Self::Envelope, _internal: Internal) -> Result<Self> {
        ensure!(envelope.gtpu_payload(), anyhow!("not a GTP-U packet."));

        let mbuf = envelope.mbuf();
        let offset = envelope.payload_offset();
        let header = mbuf.read_data(offset)?;

        let mut packet = Gtpu {
            envelope,
            header,
            sequence_number: None,
            npdu_number: None,
            // seqno: None,
            offset,
        };
        packet.sync_optionals()?;

        Ok(packet)
    }

    /// Prepends a GTP-U packet to the beginning of the envelope's payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer does not have enough free space.
    #[inline]
    fn try_push(mut envelope: Self::Envelope, _internal: Internal) -> Result<Self> {
        let offset = envelope.payload_offset();
        let mbuf = envelope.mbuf_mut();

        mbuf.extend(offset, GtpuHeader::size_of())?;
        let header = mbuf.write_data(offset, &GtpuHeader::default())?;

        let mut packet = Gtpu {
            envelope,
            header,
            sequence_number: None,
            npdu_number: None,
            offset,
        };
        packet.envelope_mut().mark_gtpu_payload();

        Ok(packet)
    }

    #[inline]
    fn deparse(self) -> Self::Envelope {
        self.envelope
    }

    /// Reconciles the derivable header fields against the changes made to
    /// the packet.
    ///
    /// Nothing to do for GTP-U
    #[inline]
    fn reconcile(&mut self) {
        // Protocol Type must be GTP (as opposed to GTP prime)
        self.header_mut().flags |= PT;
        // Version bits must be 001
        self.header_mut().flags &= 0b0001_1111;
        self.header_mut().flags |= 0b0010_0000;
        self.set_payload_length(self.payload_len());
    }
}

/// GTP-U header.
#[derive(Clone, Copy, Debug, Default, SizeOf)]
#[repr(C, packed)]
struct GtpuHeader {
    flags: u8,
    message_type: u8,
    length: u16be,
    teid: u32be
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ethernet::{Ethernet};
    use crate::packets::ip::v4::Ipv4;
    use crate::packets::udp::Udp;
    use crate::packets::Mbuf;
    use crate::testils::byte_arrays::{UDP4_PACKET, IP4GTPU_PACKET, IP4GTPU_PACKET_EXT};

    #[test]
    fn size_of_gtpu_header() {
        assert_eq!(8, GtpuHeader::size_of());
    }

    #[capsule::test]
    fn parse_gtpu_packet() {
        let packet = Mbuf::from_bytes(&IP4GTPU_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ip4 = ethernet.parse::<Ipv4>().unwrap();
        let udp = ip4.parse::<Udp<Ipv4>>().unwrap();
        let gtpu = udp.parse::<Gtpu<Udp<Ipv4>>>().unwrap();

        assert!(gtpu.sequence_number_present());
        assert!(!gtpu.npdu_number_present());
        assert!(!gtpu.extension_present());
        assert_eq!(1, gtpu.version());
        assert_eq!(MessageTypes::PDU, gtpu.message_type());
        assert_eq!(10459, gtpu.sequence_number().unwrap());
        assert_eq!(None, gtpu.npdu_number());

        // for the test packet, the header length is 12.
        assert_eq!(12, gtpu.header_len());
    }

    #[capsule::test]
    fn parse_gtpu_packet_ext() {
        let packet = Mbuf::from_bytes(&IP4GTPU_PACKET_EXT).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ip4 = ethernet.parse::<Ipv4>().unwrap();
        let udp = ip4.parse::<Udp<Ipv4>>().unwrap();
        let gtpu = udp.parse::<Gtpu<Udp<Ipv4>>>().unwrap();

        assert!(gtpu.sequence_number_present());
        assert!(!gtpu.npdu_number_present());
        assert!(gtpu.extension_present());
        assert_eq!(1, gtpu.version());
        assert_eq!(MessageTypes::PDU, gtpu.message_type());
        assert_eq!(10459, gtpu.sequence_number().unwrap());
        assert_eq!(None, gtpu.npdu_number());

        // for the test packet, the header length is 16.
        assert_eq!(16, gtpu.header_len());
    }

    #[capsule::test]
    fn parse_gtpu_setter_checks() {
        let packet = Mbuf::from_bytes(&IP4GTPU_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ip4 = ethernet.parse::<Ipv4>().unwrap();
        let udp = ip4.parse::<Udp<Ipv4>>().unwrap();
        let mut gtpu = udp.parse::<Gtpu<Udp<Ipv4>>>().unwrap();

        gtpu.set_sequence_number_present().unwrap();
        gtpu.set_npdu_number_present().unwrap();
        gtpu.set_sequence_number(1);
        gtpu.set_npdu_number(2);
        gtpu.reconcile();

        assert!(gtpu.sequence_number_present());
        assert!(gtpu.npdu_number_present());
        assert_eq!(Some(1), gtpu.sequence_number());
        assert_eq!(Some(2), gtpu.npdu_number());
        assert_eq!(12, gtpu.header_len());

        gtpu.unset_sequence_number_present().unwrap();

        assert!(!gtpu.sequence_number_present());
        assert!(gtpu.npdu_number_present());
        assert_eq!(None, gtpu.sequence_number());
        assert_eq!(Some(2), gtpu.npdu_number());
        assert_eq!(12, gtpu.header_len());

        gtpu.unset_npdu_number_present().unwrap();

        assert!(!gtpu.sequence_number_present());
        assert!(!gtpu.npdu_number_present());
        assert_eq!(None, gtpu.sequence_number());
        assert_eq!(None, gtpu.npdu_number());
        assert_eq!(8, gtpu.header_len());
    }

    #[capsule::test]
    fn parse_non_gtpu_packet() {
        let packet = Mbuf::from_bytes(&UDP4_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ip4 = ethernet.parse::<Ipv4>().unwrap();
        let udp = ip4.parse::<Udp<Ipv4>>().unwrap();

        assert!(udp.parse::<Gtpu<Udp<Ipv4>>>().is_err());
    }
}
