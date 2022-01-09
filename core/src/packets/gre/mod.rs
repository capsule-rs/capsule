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

//! Generic Routing Encapsulation

mod ip4gre;

pub use self::ip4gre::*;

use crate::ensure;
use crate::packets::ethernet::EtherType;
use crate::packets::types::{u16be, u32be};
use crate::packets::{checksum, Internal, Packet, SizeOf};
use anyhow::{anyhow, Result};
use std::fmt;
use std::ptr::NonNull;

/// Option bit flags
const C: u8 = 0b1000_0000;
const K: u8 = 0b0010_0000;
const S: u8 = 0b0001_0000;
const FLAGS: u8 = C | K | S;

/// Generic Routing Encapsulation based on [IETF RFC 2784].
///
/// ```
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |C| |K|S| Reserved0       | Ver |         Protocol Type         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Checksum (optional)      |       Reserved1 (Optional)    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Key (optional)                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                 Sequence Number (Optional)                    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// - *Checksum Present*: (1 bit)
///     If the Checksum Present bit is set to one, then the Checksum and the
///     Reserved1 fields are present and the Checksum field contains valid
///     information.
///
/// - *Key Present*: (1 bit)
///     If the Key Present bit is set to 1, then it indicates that the Key
///     field is present in the GRE header. Defined in [IETF RFC 2890].
///
/// - *Sequence Number Present*: (1 bit)
///     If the Sequence Number Present bit is set to 1, then it indicates
///     that the Sequence Number field is present. Defined in [IETF RFC 2890].
///
/// - *Reserved0*: (9 bits)
///     reserved for future use. These bits MUST be sent as zero and MUST be
///     ignored on receipt.
///
/// - *Version Number*: (3 bits)
///     The Version Number field MUST contain the value zero.
///
/// - *Protocol Type*: (16 bits)
///     The Protocol Type field contains the protocol type of the payload
///     packet. These Protocol Types are defined as "ETHER TYPES".
///
/// - *Checksum*: (16 bits)
///     The Checksum field contains the IP (one's complement) checksum sum of
///     the all the 16 bit words in the GRE header and the payload packet.
///
/// - *Reserved1*: (16 bits)
///     The Reserved1 field is reserved for future use, and if present, MUST
///     be transmitted as zero.
///
/// - *Key Field*: (32 bits)
///     The Key field is intended to be used for identifying an individual
///     traffic flow within a tunnel. Defined in [IETF RFC 2890].
///
/// - *Sequence Number*: (32 bits)
///     The Sequence Number MUST be used by the receiver to establish the
///     order in which packets have been transmitted from the encapsulator to
///     the receiver. The intended use of the Sequence Field is to provide
///     unreliable but in-order delivery.
///
/// A GRE encapsulated packet has the form
///
/// ```
///     ---------------------------------
///     |                               |
///     |       Delivery Header         |
///     |                               |
///     ---------------------------------
///     |                               |
///     |       GRE Header              |
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
/// The implementation of GRE treats the payload as opaque. It cannot be
/// parsed or manipulated with type safety. Work with the typed payload
/// packet either before encapsulation or after decapsulation like other
/// tunnel protocols.
///
/// [IETF RFC 2784]: https://datatracker.ietf.org/doc/html/rfc2784
/// [IETF RFC 2890]: https://datatracker.ietf.org/doc/html/rfc2890
pub struct Gre<E: GreTunnelPacket> {
    envelope: E,
    header: NonNull<GreHeader>,
    checksum: Option<NonNull<u16be>>,
    key: Option<NonNull<u32be>>,
    seqno: Option<NonNull<u32be>>,
    offset: usize,
}

/// A trait for packets that can be a GRE envelope.
pub trait GreTunnelPacket: Packet {
    /// Returns whether the current payload is GRE.
    fn gre_payload(&self) -> bool;

    /// Marks the envelope to be containing a GRE payload.
    fn mark_gre_payload(&mut self);
}

impl<E: GreTunnelPacket> Gre<E> {
    #[inline]
    fn header(&self) -> &GreHeader {
        unsafe { self.header.as_ref() }
    }

    #[inline]
    fn header_mut(&mut self) -> &mut GreHeader {
        unsafe { self.header.as_mut() }
    }

    /// Returns whether the checksum is present.
    ///
    /// If the bit is set, `reconcile` will calculate the checksum.
    #[inline]
    pub fn checksum_present(&self) -> bool {
        (self.header().flags_to_res0 & C) != 0
    }

    /// offset of the checksum field if it were present.
    #[inline]
    fn checksum_offset(&self) -> usize {
        self.offset() + 4
    }

    /// Sets the checksum present flag to true.
    #[inline]
    pub fn set_checksum_present(&mut self) -> Result<()> {
        if !self.checksum_present() {
            // extend the buffer to add the field
            let offset = self.checksum_offset();
            self.mbuf_mut().extend(offset, u32be::size_of())?;
            self.header_mut().flags_to_res0 |= C;
            self.sync_optionals()?;
        }

        Ok(())
    }

    /// Sets the checksum present flag to false and removes the field.
    #[inline]
    pub fn unset_checksum_present(&mut self) -> Result<()> {
        if self.checksum_present() {
            // shrink the buffer to remove the field
            let offset = self.checksum_offset();
            self.mbuf_mut().shrink(offset, u32be::size_of())?;
            self.header_mut().flags_to_res0 &= !C;
            self.sync_optionals()?;
        }

        Ok(())
    }

    /// Returns the packet checksum or `None` if the option is not set.
    #[inline]
    pub fn checksum(&self) -> Option<u16> {
        self.checksum.map(|ptr| unsafe { *ptr.as_ref() }.into())
    }

    #[inline]
    fn set_checksum(&mut self, checksum: u16) {
        // no op if the checksum present bit not set.
        if let Some(ref mut ptr) = self.checksum {
            unsafe { *ptr.as_mut() = checksum.into() };
        }
    }

    #[inline]
    fn compute_checksum(&mut self) {
        self.set_checksum(0);

        if let Ok(data) = self.mbuf().read_data_slice(self.offset, self.len()) {
            let data = unsafe { data.as_ref() };
            let checksum = checksum::ones_complement(0, data);
            self.set_checksum(checksum);
        } else {
            // we are reading the entire packet, should never run out
            unreachable!()
        }
    }

    /// Returns whether the key is present.
    #[inline]
    pub fn key_present(&self) -> bool {
        (self.header().flags_to_res0 & K) != 0
    }

    /// offset of the key field if it were present.
    #[inline]
    fn key_offset(&self) -> usize {
        self.offset() + 4 + if self.checksum_present() { 4 } else { 0 }
    }

    /// Sets the key present flag to false and removes the field.
    #[inline]
    pub fn unset_key_present(&mut self) -> Result<()> {
        if self.key_present() {
            // shrink the buffer to remove the field
            let offset = self.key_offset();
            self.mbuf_mut().shrink(offset, u32be::size_of())?;
            self.header_mut().flags_to_res0 &= !K;
            self.sync_optionals()?;
        }

        Ok(())
    }

    /// Returns the key field or `None` if the option is not set.
    #[inline]
    pub fn key(&self) -> Option<u32> {
        self.key.map(|ptr| unsafe { *ptr.as_ref() }.into())
    }

    /// Sets the key field and key present flag to true.
    #[inline]
    pub fn set_key(&mut self, key: u32) -> Result<()> {
        if !self.key_present() {
            // extend the buffer to add the field
            let offset = self.key_offset();
            self.mbuf_mut().extend(offset, u32be::size_of())?;
            self.header_mut().flags_to_res0 |= K;
            self.sync_optionals()?;
        }

        // should always match
        if let Some(ref mut ptr) = self.key {
            unsafe { *ptr.as_mut() = key.into() };
        }

        Ok(())
    }

    /// Returns whether the sequence number is present.
    #[inline]
    pub fn seqno_present(&self) -> bool {
        (self.header().flags_to_res0 & S) != 0
    }

    /// offset of the sequence number field if it were present.
    #[inline]
    fn seqno_offset(&self) -> usize {
        self.offset()
            + 4
            + if self.checksum_present() { 4 } else { 0 }
            + if self.key_present() { 4 } else { 0 }
    }

    /// Sets the sequence number present flag to false and removes the field.
    #[inline]
    pub fn unset_seqno_present(&mut self) -> Result<()> {
        if self.seqno_present() {
            // shrink the buffer to remove the field
            let offset = self.seqno_offset();
            self.mbuf_mut().shrink(offset, u32be::size_of())?;
            self.header_mut().flags_to_res0 &= !S;
            self.sync_optionals()?;
        }

        Ok(())
    }

    /// Returns the sequence number or `None` if the option is not set.
    pub fn seqno(&self) -> Option<u32> {
        self.seqno.map(|ptr| unsafe { *ptr.as_ref() }.into())
    }

    /// Sets the sequence number field and sequence number present flag to true.
    #[inline]
    pub fn set_seqno(&mut self, seqno: u32) -> Result<()> {
        if !self.seqno_present() {
            // extend the buffer to add the field
            let offset = self.seqno_offset();
            self.mbuf_mut().extend(offset, u32be::size_of())?;
            self.header_mut().flags_to_res0 |= S;
            self.sync_optionals()?;
        }

        // should always match
        if let Some(ref mut ptr) = self.seqno {
            unsafe { *ptr.as_mut() = seqno.into() };
        }

        Ok(())
    }

    /// Returns the version number.
    ///
    /// # Remarks
    ///
    /// Version must always be 0.
    #[inline]
    pub fn version(&self) -> u8 {
        self.header().res0_to_ver & 0b111
    }

    /// Returns the protocol type of the payload packet.
    #[inline]
    pub fn protocol_type(&self) -> EtherType {
        EtherType::new(self.header().protocol_type.into())
    }

    /// Sets the protocol type of the payload packet.
    #[inline]
    pub fn set_protocol_type(&mut self, protocol_type: EtherType) {
        self.header_mut().protocol_type = protocol_type.0.into()
    }

    /// Syncs the pointers to optional fields after one of the bits was
    /// changed. The underlying buffer should be adjusted accordingly before
    /// sync or it will corrupt the packet.
    #[inline]
    fn sync_optionals(&mut self) -> Result<()> {
        let mut offset = self.offset + 4;

        self.checksum = None;
        if self.checksum_present() {
            let ptr = self.mbuf().read_data::<u16be>(offset)?;
            self.checksum = Some(ptr);
            offset += 4;
        }

        self.key = None;
        if self.key_present() {
            let ptr = self.mbuf().read_data::<u32be>(offset)?;
            self.key = Some(ptr);
            offset += 4;
        }

        self.seqno = None;
        if self.seqno_present() {
            let ptr = self.mbuf().read_data::<u32be>(offset)?;
            self.seqno = Some(ptr);
        }

        Ok(())
    }
}

impl<E: GreTunnelPacket> fmt::Debug for Gre<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("gre")
            .field("checksum_present", &self.checksum_present())
            .field("key_present", &self.key_present())
            .field("seqno_present", &self.seqno_present())
            .field("version", &self.version())
            .field("protocol_type", &self.protocol_type())
            .field(
                "checksum",
                &self
                    .checksum()
                    .map(|checksum| format!("0x{:04x}", checksum))
                    .unwrap_or_else(|| "[none]".to_string()),
            )
            .field(
                "key",
                &self
                    .key()
                    .map(|key| format!("{}", key))
                    .unwrap_or_else(|| "[none]".to_string()),
            )
            .field(
                "seqno",
                &self
                    .seqno()
                    .map(|seq| format!("{}", seq))
                    .unwrap_or_else(|| "[none]".to_string()),
            )
            .field("$offset", &self.offset())
            .field("$len", &self.len())
            .field("$header_len", &self.header_len())
            .finish()
    }
}

impl<E: GreTunnelPacket> Packet for Gre<E> {
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

    /// GRE header is dynamically sized based on the number of set optional
    /// fields.
    #[inline]
    fn header_len(&self) -> usize {
        let set_options = (self.header().flags_to_res0 & FLAGS).count_ones();
        (set_options as usize + 1) * 4
    }

    #[inline]
    unsafe fn clone(&self, internal: Internal) -> Self {
        Gre::<E> {
            envelope: self.envelope.clone(internal),
            header: self.header,
            checksum: self.checksum,
            key: self.key,
            seqno: self.seqno,
            offset: self.offset,
        }
    }

    /// Parses the envelope's payload as a GRE packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the envelope's payload is not GRE.
    #[inline]
    fn try_parse(envelope: Self::Envelope, _internal: Internal) -> Result<Self> {
        ensure!(envelope.gre_payload(), anyhow!("not a GRE packet."));

        let mbuf = envelope.mbuf();
        let offset = envelope.payload_offset();
        let header = mbuf.read_data(offset)?;

        let mut packet = Gre {
            envelope,
            header,
            checksum: None,
            key: None,
            seqno: None,
            offset,
        };
        packet.sync_optionals()?;

        Ok(packet)
    }

    /// Prepends a GRE packet to the beginning of the envelope's payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer does not have enough free space.
    #[inline]
    fn try_push(mut envelope: Self::Envelope, _internal: Internal) -> Result<Self> {
        let offset = envelope.payload_offset();
        let mbuf = envelope.mbuf_mut();

        mbuf.extend(offset, GreHeader::size_of())?;
        let header = mbuf.write_data(offset, &GreHeader::default())?;

        let mut packet = Gre {
            envelope,
            header,
            checksum: None,
            key: None,
            seqno: None,
            offset,
        };
        packet.envelope_mut().mark_gre_payload();

        Ok(packet)
    }

    #[inline]
    fn deparse(self) -> Self::Envelope {
        self.envelope
    }

    /// Reconciles the derivable header fields against the changes made to
    /// the packet.
    ///
    /// * [`checksum`] is computed based on payload.
    #[inline]
    fn reconcile(&mut self) {
        if self.checksum_present() {
            self.compute_checksum()
        }
    }
}

/// GRE header.
#[derive(Clone, Copy, Debug, Default, SizeOf)]
#[repr(C, packed)]
struct GreHeader {
    flags_to_res0: u8,
    res0_to_ver: u8,
    protocol_type: u16be,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ethernet::{EtherTypes, Ethernet};
    use crate::packets::ip::v4::Ipv4;
    use crate::packets::Mbuf;
    use crate::testils::byte_arrays::{IP4GRE_PACKET, TCP4_PACKET};

    #[test]
    fn size_of_gre_header() {
        assert_eq!(4, GreHeader::size_of());
    }

    #[capsule::test]
    fn parse_gre_packet() {
        let packet = Mbuf::from_bytes(&IP4GRE_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ip4 = ethernet.parse::<Ipv4>().unwrap();
        let gre = ip4.parse::<Gre<Ipv4>>().unwrap();

        assert!(!gre.checksum_present());
        assert!(!gre.key_present());
        assert!(!gre.seqno_present());
        assert_eq!(0, gre.version());
        assert_eq!(EtherTypes::Ipv4, gre.protocol_type());
        assert_eq!(None, gre.checksum());
        assert_eq!(None, gre.key());
        assert_eq!(None, gre.seqno());

        // without options, the header length is 4.
        assert_eq!(4, gre.header_len());
    }

    #[capsule::test]
    fn parse_gre_setter_checks() {
        let packet = Mbuf::from_bytes(&IP4GRE_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ip4 = ethernet.parse::<Ipv4>().unwrap();
        let mut gre = ip4.parse::<Gre<Ipv4>>().unwrap();

        gre.set_checksum_present().unwrap();
        gre.set_key(1).unwrap();
        gre.set_seqno(2).unwrap();
        gre.reconcile();

        assert!(gre.checksum_present());
        assert!(gre.key_present());
        assert!(gre.seqno_present());
        assert!(gre.checksum() != Some(0));
        assert_eq!(Some(1), gre.key());
        assert_eq!(Some(2), gre.seqno());
        assert_eq!(16, gre.header_len());

        gre.unset_checksum_present().unwrap();

        assert!(!gre.checksum_present());
        assert!(gre.key_present());
        assert!(gre.seqno_present());
        assert_eq!(None, gre.checksum());
        assert_eq!(Some(1), gre.key());
        assert_eq!(Some(2), gre.seqno());
        assert_eq!(12, gre.header_len());

        gre.unset_key_present().unwrap();

        assert!(!gre.checksum_present());
        assert!(!gre.key_present());
        assert!(gre.seqno_present());
        assert_eq!(None, gre.checksum());
        assert_eq!(None, gre.key());
        assert_eq!(Some(2), gre.seqno());
        assert_eq!(8, gre.header_len());

        gre.unset_seqno_present().unwrap();

        assert!(!gre.checksum_present());
        assert!(!gre.key_present());
        assert!(!gre.seqno_present());
        assert_eq!(None, gre.checksum());
        assert_eq!(None, gre.key());
        assert_eq!(None, gre.seqno());
        assert_eq!(4, gre.header_len());
    }

    #[capsule::test]
    fn parse_non_gre_packet() {
        let packet = Mbuf::from_bytes(&TCP4_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ip4 = ethernet.parse::<Ipv4>().unwrap();

        assert!(ip4.parse::<Gre<Ipv4>>().is_err());
    }
}
