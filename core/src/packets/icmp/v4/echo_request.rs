use crate::packets::icmp::v4::{Icmpv4, Icmpv4Packet, Icmpv4Payload, Icmpv4Type, Icmpv4Types};
use crate::packets::ip::IpPacket;
use crate::packets::Packet;
use crate::{Result, SizeOf};
use std::fmt;

/// Echo Request Message defined in [IETF RFC 792].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Identifier          |        Sequence Number        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Data ...
/// +-+-+-+-+-
/// ```
///
/// Identifier      An identifier to aid in matching Echo Replies
///                 to this Echo Request.  May be zero.
///
/// Sequence Number
///                 A sequence number to aid in matching Echo Replies
///                 to this Echo Request.  May be zero.
///
/// Data            Zero or more octets of arbitrary data.
///
/// [IETF RFC 792]: https://tools.ietf.org/html/rfc792 (page 14)
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct EchoRequest {
    identifier: u16,
    seq_no: u16,
}

impl Icmpv4Payload for EchoRequest {
    fn msg_type() -> Icmpv4Type {
        Icmpv4Types::EchoRequest
    }
}

impl<E: IpPacket> Icmpv4<E, EchoRequest> {
    /// Returns the identifier.
    #[inline]
    pub fn identifier(&self) -> u16 {
        u16::from_be(self.payload().identifier)
    }

    /// Sets the identifier.
    #[inline]
    pub fn set_identifier(&mut self, identifier: u16) {
        self.payload_mut().identifier = u16::to_be(identifier);
    }

    /// Returns the sequence number.
    #[inline]
    pub fn seq_no(&self) -> u16 {
        u16::from_be(self.payload().seq_no)
    }

    /// Sets the sequence number.
    #[inline]
    pub fn set_seq_no(&mut self, seq_no: u16) {
        self.payload_mut().seq_no = u16::to_be(seq_no);
    }

    /// Returns the offset where the data field in the message body starts.
    #[inline]
    fn data_offset(&self) -> usize {
        self.payload_offset() + EchoRequest::size_of()
    }

    /// Returns the length of the data field in the message body.
    #[inline]
    fn data_len(&self) -> usize {
        self.payload_len() - EchoRequest::size_of()
    }

    /// Returns the data as a `u8` slice.
    #[inline]
    pub fn data(&self) -> &[u8] {
        if let Ok(data) = self
            .mbuf()
            .read_data_slice(self.data_offset(), self.data_len())
        {
            unsafe { &*data.as_ptr() }
        } else {
            unreachable!()
        }
    }

    /// Sets the data.
    #[inline]
    pub fn set_data(&mut self, data: &[u8]) -> Result<()> {
        let offset = self.data_offset();
        let len = data.len() as isize - self.data_len() as isize;
        self.mbuf_mut().resize(offset, len)?;
        self.mbuf_mut().write_data_slice(offset, data)?;
        Ok(())
    }
}

impl<E: IpPacket> fmt::Debug for Icmpv4<E, EchoRequest> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("icmpv4")
            .field("type", &self.msg_type())
            .field("code", &self.code())
            .field("checksum", &format!("0x{:04x}", self.checksum()))
            .field("identifier", &self.identifier())
            .field("seq_no", &self.seq_no())
            .field("$offset", &self.offset())
            .field("$len", &self.len())
            .field("$header_len", &self.header_len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_of_echo_request() {
        assert_eq!(4, EchoRequest::size_of());
    }
}
