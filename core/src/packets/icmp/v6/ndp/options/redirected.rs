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

use crate::ensure;
use crate::packets::icmp::v6::ndp::{NdpOption, NdpOptionType, NdpOptionTypes};
use crate::packets::types::{u16be, u32be};
use crate::packets::{Internal, Mbuf, SizeOf};
use anyhow::{anyhow, Result};
use std::fmt;
use std::ptr::NonNull;

/// Redirected Header option defined in [IETF RFC 4861].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |    Length     |            Reserved           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Reserved                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~                       IP header + data                        ~
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// - *Type*:           4
///
/// - *Length*:         The length of the option in units of 8 octets.
///
/// - *Reserved*:       These fields are unused. They MUST be initialized
///                     to zero by the sender and MUST be ignored by the
///                     receiver.
///
/// - *IP header + data*:
///                     The original packet truncated to ensure that the
///                     size of the redirect message does not exceed 1280
///                     octets.
///
/// # Remarks
///
/// The `RedirectedHeader` is a dynamically sized option. The option, once
/// added to a [`Redirect`] message, will treat the remainder of the buffer
/// as this option's data. When constructing a `Redirect` message from an
/// existing packet, `RedirectedHeader` should be the first option added,
/// and must be pushed with [`NdpOptions::prepend`] to ensure it's before
/// the original IP header and data.
///
/// The `length` field does not account for the original IP header and data
/// when the option is first pushed. Use either [`set_length`] to set it
/// explicitly or `Redirect::reconcile` to set it as part of the
/// reconciliation.
///
/// ```
/// let ethernet = orig_ipv6.deparse();
/// let ipv6 = ethernet.push::<Ipv6>()?;
/// let mut redirect = ipv6.push::<Redirect<Ipv6>>()?;
/// let mut options = redirect.options_mut();
/// let _ = options.prepend::<RedirectedHeader<'_>>();
/// redirect.reconcile();
/// ```
///
/// [IETF RFC 4861]: https://tools.ietf.org/html/rfc2461#section-4.6.3
/// [`Redirect`]: crate::packets::icmp::v6::ndp::Redirect
/// [`NdpOptions::prepend`]: crate::packets::icmp::v6::ndp::NdpOptions::prepend
/// [`set_length`]: RedirectedHeader::set_length
pub struct RedirectedHeader<'a> {
    mbuf: &'a mut Mbuf,
    fields: NonNull<RedirectedHeaderFields>,
    offset: usize,
}

impl RedirectedHeader<'_> {
    #[inline]
    fn fields(&self) -> &RedirectedHeaderFields {
        unsafe { self.fields.as_ref() }
    }

    #[inline]
    fn fields_mut(&mut self) -> &mut RedirectedHeaderFields {
        unsafe { self.fields.as_mut() }
    }

    /// Returns the invoking packet as a `u8` slice.
    ///
    /// This option must be the last option in the [Redirect] message. The
    /// remainder of the buffer is the data.
    ///
    /// [Redirect]: crate::packets::icmp::v6::ndp::Redirect
    #[inline]
    pub fn data(&self) -> &[u8] {
        let offset = self.offset + RedirectedHeaderFields::size_of();
        let len = self.mbuf.data_len() - offset;

        if let Ok(data) = self.mbuf.read_data_slice(offset, len) {
            unsafe { &*data.as_ptr() }
        } else {
            &[]
        }
    }

    /// Sets the length of the option based on the buffer length.
    ///
    /// This option must be the last option in the [Redirect] message. The
    /// remainder of the buffer is included as part of the option. If the
    /// remaining length is not a multiple of 8 octets, the extra octets
    /// are trimmed before the length is set.
    ///
    /// [Redirect]: crate::packets::icmp::v6::ndp::Redirect
    #[inline]
    pub fn set_length(&mut self) {
        let len = self.mbuf.data_len() - self.offset;
        let rem = len % 8;
        if rem > 0 {
            let trim_to = self.mbuf.data_len() - rem;
            // should never fail to truncate
            let _ = self.mbuf.truncate(trim_to);
        }

        self.fields_mut().length = (len / 8) as u8;
    }
}

impl fmt::Debug for RedirectedHeader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedirectedHeader")
            .field("type", &self.option_type())
            .field("length", &self.length())
            .field("$offset", &self.offset)
            .finish()
    }
}

impl<'a> NdpOption<'a> for RedirectedHeader<'a> {
    /// Returns the option type. Should always be `4`.
    #[inline]
    fn option_type(&self) -> NdpOptionType {
        NdpOptionType(self.fields().option_type)
    }

    /// Returns the length of the option measured in units of 8 octets.
    /// Should always be `1`.
    #[inline]
    fn length(&self) -> u8 {
        self.fields().length
    }

    /// Parses the buffer at offset as redirected header option.
    ///
    /// # Errors
    ///
    /// Returns an error if the `option_type` is not set to `RedirectedHeader`.
    #[inline]
    fn try_parse(
        mbuf: &'a mut Mbuf,
        offset: usize,
        _internal: Internal,
    ) -> Result<RedirectedHeader<'a>> {
        let fields = mbuf.read_data::<RedirectedHeaderFields>(offset)?;
        let option = RedirectedHeader {
            mbuf,
            fields,
            offset,
        };

        ensure!(
            option.option_type() == NdpOptionTypes::RedirectedHeader,
            anyhow!("not redirected header.")
        );

        Ok(option)
    }

    /// Pushes a new redirected header option to the buffer at offset.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer does not have enough free space.
    #[inline]
    fn try_push(
        mbuf: &'a mut Mbuf,
        offset: usize,
        _internal: Internal,
    ) -> Result<RedirectedHeader<'a>> {
        mbuf.extend(offset, RedirectedHeaderFields::size_of())?;
        let fields = mbuf.write_data(offset, &RedirectedHeaderFields::default())?;
        Ok(RedirectedHeader {
            mbuf,
            fields,
            offset,
        })
    }
}

/// Redirected Header option fields.
#[derive(Clone, Copy, Debug, SizeOf)]
#[repr(C, packed)]
struct RedirectedHeaderFields {
    option_type: u8,
    length: u8,
    reserved1: u16be,
    reserved2: u32be,
}

impl Default for RedirectedHeaderFields {
    fn default() -> RedirectedHeaderFields {
        RedirectedHeaderFields {
            option_type: NdpOptionTypes::RedirectedHeader.0,
            length: 1,
            reserved1: u16be::default(),
            reserved2: u32be::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ethernet::Ethernet;
    use crate::packets::icmp::v6::ndp::{NdpPacket, Redirect};
    use crate::packets::ip::v6::Ipv6;
    use crate::packets::Packet;

    #[test]
    fn size_of_redirected_header_fields() {
        assert_eq!(8, RedirectedHeaderFields::size_of());
    }

    #[capsule::test]
    fn push_and_set_redirected_header() {
        // the data buffer length is not a multiple of 8
        let data = [42; 9];

        let packet = Mbuf::from_bytes(&data).unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv6 = ethernet.push::<Ipv6>().unwrap();
        let mut redirect = ipv6.push::<Redirect<Ipv6>>().unwrap();
        let mut options = redirect.options_mut();
        let mut header = options.prepend::<RedirectedHeader<'_>>().unwrap();

        assert_eq!(NdpOptionTypes::RedirectedHeader, header.option_type());
        assert_eq!(1, header.length());
        assert_eq!(&data, header.data());

        // this will truncate the extra data byte
        header.set_length();

        assert_eq!(2, header.length());
        assert_eq!(&data[..8], header.data());
    }
}
