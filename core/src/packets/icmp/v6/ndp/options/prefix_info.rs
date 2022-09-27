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
use crate::packets::types::u32be;
use crate::packets::{Internal, Mbuf, SizeOf};
use anyhow::{anyhow, Result};
use std::fmt;
use std::net::Ipv6Addr;
use std::ptr::NonNull;

/// Masks.
const ONLINK: u8 = 0b1000_0000;
const AUTO: u8 = 0b0100_0000;

/// Prefix Information option defined in [IETF RFC 4861].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |    Length     | Prefix Length |L|A| Reserved1 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Valid Lifetime                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Preferred Lifetime                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Reserved2                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                Prefix (128 bits IPv6 address)                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// - *Type*:           3
///
/// - *Length*:         4
///
/// - *Prefix Length*:  8-bit unsigned integer. The number of leading bits
///                     in the Prefix that are valid. The value ranges
///                     from 0 to 128.
///
/// - *L*:              1-bit on-link flag. When set, indicates that this
///                     prefix can be used for on-link determination.
///
/// - *A*:              1-bit autonomous address-configuration flag. When
///                     set indicates that this prefix can be used for
///                     stateless address configuration.
///
/// - *Reserved1*:      6-bit unused field. It MUST be initialized to zero
///                     by the sender and MUST be ignored by the receiver.
///
/// - *Valid Lifetime*:
///                     32-bit unsigned integer. The length of time in
///                     seconds (relative to the time the packet is sent)
///                     that the prefix is valid for the purpose of on-link
///                     determination.
///
/// - *Preferred Lifetime*:
///                     32-bit unsigned integer. The length of time in
///                     seconds (relative to the time the packet is sent)
///                     that addresses generated from the prefix via
///                     stateless address autoconfiguration remain
///                     preferred.
///
/// - *Reserved2*:      This field is unused. It MUST be initialized to
///                     zero by the sender and MUST be ignored by the
///                     receiver.
///
/// - *Prefix*:         An IP address or a prefix of an IP address. The
///                     Prefix Length field contains the number of valid
///                     leading bits in the prefix.
///
/// [IETF RFC 4861]: https://tools.ietf.org/html/rfc4861#section-4.6.2
pub struct PrefixInformation<'a> {
    _mbuf: &'a mut Mbuf,
    fields: NonNull<PrefixInformationFields>,
    offset: usize,
}

impl PrefixInformation<'_> {
    #[inline]
    fn fields(&self) -> &PrefixInformationFields {
        unsafe { self.fields.as_ref() }
    }

    #[inline]
    fn fields_mut(&mut self) -> &mut PrefixInformationFields {
        unsafe { self.fields.as_mut() }
    }

    /// Returns the number of leading bits in the prefix that are valid.
    #[inline]
    pub fn prefix_length(&self) -> u8 {
        self.fields().prefix_length
    }

    /// Sets the prefix length.
    #[inline]
    pub fn set_prefix_length(&mut self, prefix_length: u8) {
        self.fields_mut().prefix_length = prefix_length
    }

    /// Returns a flag indicating that this prefix can be used for on-link
    /// determination.
    #[inline]
    pub fn on_link(&self) -> bool {
        self.fields().flags & ONLINK > 0
    }

    /// Sets the on-link flag.
    #[inline]
    pub fn set_on_link(&mut self) {
        self.fields_mut().flags |= ONLINK;
    }

    /// Unsets the on-link flag.
    #[inline]
    pub fn unset_on_link(&mut self) {
        self.fields_mut().flags &= !ONLINK;
    }

    /// Returns a flag indicating that this prefix can be used for stateless
    /// address configuration.
    #[inline]
    pub fn autonomous(&self) -> bool {
        self.fields().flags & AUTO > 0
    }

    /// Sets the autonomous flag.
    #[inline]
    pub fn set_autonomous(&mut self) {
        self.fields_mut().flags |= AUTO;
    }

    /// Unsets the autonomous flag.
    #[inline]
    pub fn unset_autonomous(&mut self) {
        self.fields_mut().flags &= !AUTO;
    }

    /// Returns the length of time in seconds that the prefix is valid for
    /// the purpose of on-link determination.
    #[inline]
    pub fn valid_lifetime(&self) -> u32 {
        self.fields().valid_lifetime.into()
    }

    /// Sets the prefix valid lifetime.
    #[inline]
    pub fn set_valid_lifetime(&mut self, valid_lifetime: u32) {
        self.fields_mut().valid_lifetime = valid_lifetime.into();
    }

    /// Returns the length of time in seconds that addresses generated from
    /// the prefix via stateless address autoconfiguration remain preferred.
    #[inline]
    pub fn preferred_lifetime(&self) -> u32 {
        self.fields().preferred_lifetime.into()
    }

    /// Sets the preferred lifetime.
    #[inline]
    pub fn set_preferred_lifetime(&mut self, preferred_lifetime: u32) {
        self.fields_mut().preferred_lifetime = preferred_lifetime.into();
    }

    /// Returns the IPv6 prefix.
    #[inline]
    pub fn prefix(&self) -> Ipv6Addr {
        self.fields().prefix
    }

    /// Sets the IPv6 prefix.
    #[inline]
    pub fn set_prefix(&mut self, prefix: Ipv6Addr) {
        self.fields_mut().prefix = prefix;
    }
}

impl fmt::Debug for PrefixInformation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrefixInformation")
            .field("type", &self.option_type())
            .field("length", &self.length())
            .field("prefix_length", &self.prefix_length())
            .field("on_link", &self.on_link())
            .field("autonomous", &self.autonomous())
            .field("valid_lifetime", &self.valid_lifetime())
            .field("preferred_lifetime", &self.preferred_lifetime())
            .field("prefix", &self.prefix())
            .field("$offset", &self.offset)
            .finish()
    }
}

impl<'a> NdpOption<'a> for PrefixInformation<'a> {
    /// Returns the option type. Should always be `3`.
    #[inline]
    fn option_type(&self) -> NdpOptionType {
        NdpOptionType(self.fields().option_type)
    }

    /// Returns the length of the option measured in units of 8 octets.
    /// Should always be `4`.
    #[inline]
    fn length(&self) -> u8 {
        self.fields().length
    }

    /// Parses the buffer at offset as prefix information option.
    ///
    /// # Errors
    ///
    /// Returns an error if the `option_type` is not set to `PrefixInformation`.
    /// Returns an error if the option length is incorrect.
    #[inline]
    fn try_parse(
        mbuf: &'a mut Mbuf,
        offset: usize,
        _internal: Internal,
    ) -> Result<PrefixInformation<'a>> {
        let fields = mbuf.read_data::<PrefixInformationFields>(offset)?;
        let option = PrefixInformation {
            _mbuf: mbuf,
            fields,
            offset,
        };

        ensure!(
            option.option_type() == NdpOptionTypes::PrefixInformation,
            anyhow!("not prefix information.")
        );

        ensure!(
            option.length() * 8 == PrefixInformationFields::size_of() as u8,
            anyhow!("invalid prefix information option length.")
        );

        Ok(option)
    }

    /// Pushes a new prefix information option to the buffer at offset.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer does not have enough free space.
    #[inline]
    fn try_push(
        mbuf: &'a mut Mbuf,
        offset: usize,
        _internal: Internal,
    ) -> Result<PrefixInformation<'a>> {
        mbuf.extend(offset, PrefixInformationFields::size_of())?;
        let fields = mbuf.write_data(offset, &PrefixInformationFields::default())?;
        Ok(PrefixInformation {
            _mbuf: mbuf,
            fields,
            offset,
        })
    }
}

/// Prefix option fields.
#[derive(Clone, Copy, Debug, SizeOf)]
#[repr(C)]
struct PrefixInformationFields {
    option_type: u8,
    length: u8,
    prefix_length: u8,
    flags: u8,
    valid_lifetime: u32be,
    preferred_lifetime: u32be,
    reserved: u32be,
    prefix: Ipv6Addr,
}

impl Default for PrefixInformationFields {
    fn default() -> PrefixInformationFields {
        PrefixInformationFields {
            option_type: NdpOptionTypes::PrefixInformation.0,
            length: 4,
            prefix_length: 0,
            flags: 0,
            valid_lifetime: u32be::default(),
            preferred_lifetime: u32be::default(),
            reserved: u32be::default(),
            prefix: Ipv6Addr::UNSPECIFIED,
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
    fn size_of_prefix_information_fields() {
        assert_eq!(32, PrefixInformationFields::size_of());
    }

    #[capsule::test]
    fn parse_prefix_information() {
        let packet = Mbuf::from_bytes(&ROUTER_ADVERT_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let mut advert = ipv6.parse::<RouterAdvertisement<Ipv6>>().unwrap();
        let mut options = advert.options_mut();
        let mut iter = options.iter();

        let mut pass = false;
        while let Some(mut option) = iter.next().unwrap() {
            if let Ok(prefix) = option.downcast::<PrefixInformation<'_>>() {
                assert_eq!(NdpOptionTypes::PrefixInformation, prefix.option_type());
                assert_eq!(4, prefix.length());
                assert_eq!(64, prefix.prefix_length());
                assert!(prefix.on_link());
                assert!(prefix.autonomous());
                assert_eq!(2366, prefix.valid_lifetime());
                assert_eq!(2366, prefix.preferred_lifetime());
                assert_eq!(
                    Ipv6Addr::new(0x2607, 0xfcc8, 0xf142, 0xb0f0, 0, 0, 0, 0),
                    prefix.prefix()
                );

                pass = true;
                break;
            }
        }

        assert!(pass);
    }

    #[capsule::test]
    fn push_and_set_prefix_information() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv6 = ethernet.push::<Ipv6>().unwrap();
        let mut advert = ipv6.push::<RouterAdvertisement<Ipv6>>().unwrap();
        let mut options = advert.options_mut();
        let mut prefix = options.append::<PrefixInformation<'_>>().unwrap();

        assert_eq!(NdpOptionTypes::PrefixInformation, prefix.option_type());
        assert_eq!(4, prefix.length());
        assert_eq!(0, prefix.prefix_length());
        assert!(!prefix.on_link());
        assert!(!prefix.autonomous());
        assert_eq!(0, prefix.valid_lifetime());
        assert_eq!(0, prefix.preferred_lifetime());
        assert_eq!(Ipv6Addr::UNSPECIFIED, prefix.prefix());

        prefix.set_prefix_length(64);
        assert_eq!(64, prefix.prefix_length());
        prefix.set_on_link();
        assert!(prefix.on_link());
        prefix.unset_on_link();
        assert!(!prefix.on_link());
        prefix.set_autonomous();
        assert!(prefix.autonomous());
        prefix.unset_autonomous();
        assert!(!prefix.autonomous());
        prefix.set_valid_lifetime(255);
        assert_eq!(255, prefix.valid_lifetime());
        prefix.set_preferred_lifetime(600);
        assert_eq!(600, prefix.preferred_lifetime());
        prefix.set_prefix(Ipv6Addr::LOCALHOST);
        assert_eq!(Ipv6Addr::LOCALHOST, prefix.prefix());
    }
}
