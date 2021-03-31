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
use crate::net::MacAddr;
use crate::packets::icmp::v6::ndp::{NdpOption, NdpOptionType, NdpOptionTypes};
use crate::packets::{Internal, Mbuf, SizeOf};
use anyhow::{anyhow, Result};
use std::fmt;
use std::ptr::NonNull;

/// Source/Target Link-layer Address option defined in [IETF RFC 4861].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |    Length     |    Link-Layer Address ...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// - *Type*:           1 for Source Link-layer Address.
///                     2 for Target Link-layer Address.
///
/// - *Length*:         The length of the option (including the type and
///                     length fields) in units of 8 octets. For example,
///                     the length for IEEE 802 addresses is 1.
///
/// - *Link-Layer Address*:
///                     The variable length link-layer address.
///
/// [IETF RFC 4861]: https://tools.ietf.org/html/rfc4861#section-4.6.1
pub struct LinkLayerAddress<'a> {
    _mbuf: &'a mut Mbuf,
    fields: NonNull<LinkLayerAddressFields>,
    offset: usize,
}

impl LinkLayerAddress<'_> {
    #[inline]
    fn fields(&self) -> &LinkLayerAddressFields {
        unsafe { self.fields.as_ref() }
    }

    #[inline]
    fn fields_mut(&mut self) -> &mut LinkLayerAddressFields {
        unsafe { self.fields.as_mut() }
    }

    /// Sets the option type to source link-layer address.
    #[inline]
    pub fn set_option_type_source(&mut self) {
        self.fields_mut().option_type = NdpOptionTypes::SourceLinkLayerAddress.0;
    }

    /// Sets the option type to target link-layer address.
    #[inline]
    pub fn set_option_type_target(&mut self) {
        self.fields_mut().option_type = NdpOptionTypes::TargetLinkLayerAddress.0;
    }

    /// Returns the link-layer address.
    #[inline]
    pub fn addr(&self) -> MacAddr {
        self.fields().addr
    }

    /// Sets the link-layer address.
    #[inline]
    pub fn set_addr(&mut self, addr: MacAddr) {
        self.fields_mut().addr = addr;
    }
}

impl fmt::Debug for LinkLayerAddress<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkLayerAddress")
            .field("type", &self.option_type())
            .field("length", &self.length())
            .field("addr", &self.addr())
            .field("$offset", &self.offset)
            .finish()
    }
}

impl<'a> NdpOption<'a> for LinkLayerAddress<'a> {
    /// Returns the option type. `1` for source link-layer address and `2`
    /// for target link-layer address.
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

    /// Parses the buffer at offset as link layer address option.
    ///
    /// # Errors
    ///
    /// Returns an error if the `option_type` is not set to either
    /// `SourceLinkLayerAddress` or `TargetLinkLayerAddress`. Returns an
    /// error if the option length is incorrect.
    #[inline]
    fn try_parse(
        mbuf: &'a mut Mbuf,
        offset: usize,
        _internal: Internal,
    ) -> Result<LinkLayerAddress<'a>> {
        let fields = mbuf.read_data::<LinkLayerAddressFields>(offset)?;
        let option = LinkLayerAddress {
            _mbuf: mbuf,
            fields,
            offset,
        };

        ensure!(
            option.option_type() == NdpOptionTypes::SourceLinkLayerAddress
                || option.option_type() == NdpOptionTypes::TargetLinkLayerAddress,
            anyhow!("not source/target link-layer address.")
        );

        ensure!(
            option.length() * 8 == LinkLayerAddressFields::size_of() as u8,
            anyhow!("invalid link-layer address option length.")
        );

        Ok(option)
    }

    /// Pushes a new link layer address option to the buffer at offset.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer does not have enough free space.
    #[inline]
    fn try_push(
        mbuf: &'a mut Mbuf,
        offset: usize,
        _internal: Internal,
    ) -> Result<LinkLayerAddress<'a>> {
        mbuf.extend(offset, LinkLayerAddressFields::size_of())?;
        let fields = mbuf.write_data(offset, &LinkLayerAddressFields::default())?;
        Ok(LinkLayerAddress {
            _mbuf: mbuf,
            fields,
            offset,
        })
    }
}

/// Link-layer address option fields.
#[derive(Clone, Copy, Debug, SizeOf)]
#[repr(C, packed)]
struct LinkLayerAddressFields {
    option_type: u8,
    length: u8,
    addr: MacAddr,
}

impl Default for LinkLayerAddressFields {
    fn default() -> LinkLayerAddressFields {
        LinkLayerAddressFields {
            option_type: NdpOptionTypes::SourceLinkLayerAddress.0,
            length: 1,
            addr: MacAddr::UNSPECIFIED,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::ethernet::Ethernet;
    use crate::packets::icmp::v6::ndp::{NdpPacket, RouterAdvertisement};
    use crate::packets::ip::v6::Ipv6;
    use crate::packets::Packet;
    use crate::testils::byte_arrays::ROUTER_ADVERT_PACKET;

    #[test]
    fn size_of_link_layer_address_fields() {
        assert_eq!(8, LinkLayerAddressFields::size_of());
    }

    #[capsule::test]
    fn parse_link_layer_address() {
        let packet = Mbuf::from_bytes(&ROUTER_ADVERT_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let mut advert = ipv6.parse::<RouterAdvertisement<Ipv6>>().unwrap();
        let mut options = advert.options_mut();
        let mut iter = options.iter();

        let mut pass = false;
        while let Some(mut option) = iter.next().unwrap() {
            if let Ok(lla) = option.downcast::<LinkLayerAddress<'_>>() {
                assert_eq!(NdpOptionTypes::SourceLinkLayerAddress, lla.option_type());
                assert_eq!(1, lla.length());
                assert_eq!(MacAddr::new(0x70, 0x3a, 0xcb, 0x1b, 0xf9, 0x7a), lla.addr());

                pass = true;
                break;
            }
        }

        assert!(pass);
    }

    #[capsule::test]
    fn push_and_set_link_layer_address() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv6 = ethernet.push::<Ipv6>().unwrap();
        let mut advert = ipv6.push::<RouterAdvertisement<Ipv6>>().unwrap();
        let mut options = advert.options_mut();
        let mut lla = options.append::<LinkLayerAddress<'_>>().unwrap();

        assert_eq!(NdpOptionTypes::SourceLinkLayerAddress, lla.option_type());
        assert_eq!(1, lla.length());
        assert_eq!(MacAddr::UNSPECIFIED, lla.addr());

        lla.set_option_type_target();
        assert_eq!(NdpOptionTypes::TargetLinkLayerAddress, lla.option_type());
        lla.set_option_type_source();
        assert_eq!(NdpOptionTypes::SourceLinkLayerAddress, lla.option_type());
        lla.set_addr(MacAddr::new(1, 1, 1, 1, 1, 1));
        assert_eq!(MacAddr::new(1, 1, 1, 1, 1, 1), lla.addr());
    }
}
