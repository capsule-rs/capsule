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

use crate::packets::icmp::v4::{Icmpv4, Icmpv4Message, Icmpv4Packet, Icmpv4Type, Icmpv4Types};
use crate::packets::types::u16be;
use crate::packets::{Internal, Packet};
use crate::SizeOf;
use failure::Fallible;
use std::fmt;
use std::ptr::NonNull;

/// Echo Reply Message defined in [IETF RFC 792].
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
/// *Identifier*:       The identifier from the invoking Echo Request message.
///
/// *Sequence Number*:  The sequence number from the invoking Echo Request
///                     message.
///
/// *Data*:             The data from the invoking Echo Request message.
///
/// [IETF RFC 792]: https://tools.ietf.org/html/rfc792
#[derive(Icmpv4Packet)]
pub struct EchoReply {
    icmp: Icmpv4,
    body: NonNull<EchoReplyBody>,
}

impl EchoReply {
    #[inline]
    fn body(&self) -> &EchoReplyBody {
        unsafe { self.body.as_ref() }
    }

    #[inline]
    fn body_mut(&mut self) -> &mut EchoReplyBody {
        unsafe { self.body.as_mut() }
    }

    /// Returns the identifier.
    #[inline]
    pub fn identifier(&self) -> u16 {
        self.body().identifier.into()
    }

    /// Sets the identifier.
    #[inline]
    pub fn set_identifier(&mut self, identifier: u16) {
        self.body_mut().identifier = identifier.into();
    }

    /// Returns the sequence number.
    #[inline]
    pub fn seq_no(&self) -> u16 {
        self.body().seq_no.into()
    }

    /// Sets the sequence number.
    #[inline]
    pub fn set_seq_no(&mut self, seq_no: u16) {
        self.body_mut().seq_no = seq_no.into();
    }

    /// Returns the offset where the data field in the message body starts.
    #[inline]
    fn data_offset(&self) -> usize {
        self.payload_offset() + EchoReplyBody::size_of()
    }

    /// Returns the length of the data field in the message body.
    #[inline]
    fn data_len(&self) -> usize {
        self.payload_len() - EchoReplyBody::size_of()
    }

    /// Returns the data as a `u8` slice.
    #[inline]
    pub fn data(&self) -> &[u8] {
        if let Ok(data) = self
            .icmp()
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
    pub fn set_data(&mut self, data: &[u8]) -> Fallible<()> {
        let offset = self.data_offset();
        let len = data.len() as isize - self.data_len() as isize;
        self.icmp_mut().mbuf_mut().resize(offset, len)?;
        self.icmp_mut().mbuf_mut().write_data_slice(offset, data)?;
        Ok(())
    }
}

impl fmt::Debug for EchoReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EchoReply")
            .field("type", &format!("{}", self.msg_type()))
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

impl Icmpv4Message for EchoReply {
    #[inline]
    fn msg_type() -> Icmpv4Type {
        Icmpv4Types::EchoReply
    }

    #[inline]
    fn icmp(&self) -> &Icmpv4 {
        &self.icmp
    }

    #[inline]
    fn icmp_mut(&mut self) -> &mut Icmpv4 {
        &mut self.icmp
    }

    #[inline]
    fn into_icmp(self) -> Icmpv4 {
        self.icmp
    }

    #[inline]
    unsafe fn clone(&self, internal: Internal) -> Self {
        EchoReply {
            icmp: self.icmp.clone(internal),
            body: self.body,
        }
    }

    #[inline]
    fn try_parse(icmp: Icmpv4, _internal: Internal) -> Fallible<Self> {
        let mbuf = icmp.mbuf();
        let offset = icmp.payload_offset();
        let body = mbuf.read_data(offset)?;

        Ok(EchoReply { icmp, body })
    }

    #[inline]
    fn try_push(mut icmp: Icmpv4, _internal: Internal) -> Fallible<Self> {
        let offset = icmp.payload_offset();
        let mbuf = icmp.mbuf_mut();

        mbuf.extend(offset, EchoReplyBody::size_of())?;
        let body = mbuf.write_data(offset, &EchoReplyBody::default())?;

        Ok(EchoReply { icmp, body })
    }
}

/// The ICMPv4 Echo Reply message body.
///
/// This contains only the fixed portion of the message body. data is parsed
/// separately.
#[derive(Clone, Copy, Debug, Default, SizeOf)]
#[repr(C, packed)]
struct EchoReplyBody {
    identifier: u16be,
    seq_no: u16be,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ip::v4::Ipv4;
    use crate::packets::Ethernet;
    use crate::Mbuf;

    #[test]
    fn size_of_echo_reply_body() {
        assert_eq!(4, EchoReplyBody::size_of());
    }

    #[capsule::test]
    fn push_and_set_echo_reply() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv4 = ethernet.push::<Ipv4>().unwrap();
        let mut echo = ipv4.push::<EchoReply>().unwrap();

        assert_eq!(4, echo.header_len());
        assert_eq!(EchoReplyBody::size_of(), echo.payload_len());
        assert_eq!(Icmpv4Types::EchoReply, echo.msg_type());
        assert_eq!(0, echo.code());

        echo.set_identifier(42);
        assert_eq!(42, echo.identifier());
        echo.set_seq_no(7);
        assert_eq!(7, echo.seq_no());

        let data = [0; 10];
        assert!(echo.set_data(&data).is_ok());
        assert_eq!(&data, echo.data());
        assert_eq!(EchoReplyBody::size_of() + 10, echo.payload_len());

        echo.reconcile_all();
        assert!(echo.checksum() != 0);
    }
}
