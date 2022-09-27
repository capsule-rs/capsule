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

/// MTU option defined in [IETF RFC 4861].
///
/// ```
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |    Length     |           Reserved            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              MTU                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// - *Type*:            5
///
/// - *Length*:          1
///
/// - *Reserved*:        This field is unused. It MUST be initialized to
///                      zero by the sender and MUST be ignored by the
///                      receiver.
///
/// - *MTU*:             32-bit unsigned integer. The recommended MTU for
///                      the link.
///
/// [IETF RFC 4861]: https://tools.ietf.org/html/rfc4861#section-4.6.4
pub struct Mtu<'a> {
    _mbuf: &'a mut Mbuf,
    fields: NonNull<MtuFields>,
    offset: usize,
}

impl Mtu<'_> {
    #[inline]
    fn fields(&self) -> &MtuFields {
        unsafe { self.fields.as_ref() }
    }

    #[inline]
    fn fields_mut(&mut self) -> &mut MtuFields {
        unsafe { self.fields.as_mut() }
    }

    /// Returns the recommended MTU for the link.
    pub fn mtu(&self) -> u32 {
        self.fields().mtu.into()
    }

    /// Sets the recommended MTU for the link.
    pub fn set_mtu(&mut self, mtu: u32) {
        self.fields_mut().mtu = mtu.into();
    }
}

impl fmt::Debug for Mtu<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mtu")
            .field("type", &self.option_type())
            .field("length", &self.length())
            .field("mtu", &self.mtu())
            .field("$offset", &self.offset)
            .finish()
    }
}

impl<'a> NdpOption<'a> for Mtu<'a> {
    /// Returns the option type. Should always be `5`.
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

    /// Parses the buffer at offset as MTU option.
    ///
    /// # Errors
    ///
    /// Returns an error if the `option_type` is not set to `MTU`. Returns
    /// an error if the option length is incorrect.
    #[inline]
    fn try_parse(mbuf: &'a mut Mbuf, offset: usize, _internal: Internal) -> Result<Mtu<'a>> {
        let fields = mbuf.read_data::<MtuFields>(offset)?;
        let option = Mtu {
            _mbuf: mbuf,
            fields,
            offset,
        };

        ensure!(
            option.option_type() == NdpOptionTypes::Mtu,
            anyhow!("not MTU.")
        );

        ensure!(
            option.length() * 8 == MtuFields::size_of() as u8,
            anyhow!("invalid MTU option length.")
        );

        Ok(option)
    }

    /// Pushes a new MTU option to the buffer at offset.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer does not have enough free space.
    #[inline]
    fn try_push(mbuf: &'a mut Mbuf, offset: usize, _internal: Internal) -> Result<Mtu<'a>> {
        mbuf.extend(offset, MtuFields::size_of())?;
        let fields = mbuf.write_data(offset, &MtuFields::default())?;
        Ok(Mtu {
            _mbuf: mbuf,
            fields,
            offset,
        })
    }
}

/// MTU option fields.
#[derive(Clone, Copy, Debug, SizeOf)]
#[repr(C, packed)]
struct MtuFields {
    option_type: u8,
    length: u8,
    reserved: u16be,
    mtu: u32be,
}

impl Default for MtuFields {
    fn default() -> MtuFields {
        MtuFields {
            option_type: NdpOptionTypes::Mtu.0,
            length: 1,
            reserved: u16be::default(),
            mtu: u32be::default(),
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
    fn size_of_mtu_fields() {
        assert_eq!(8, MtuFields::size_of());
    }

    #[capsule::test]
    fn parse_mtu() {
        let packet = Mbuf::from_bytes(&ROUTER_ADVERT_PACKET).unwrap();
        let ethernet = packet.parse::<Ethernet>().unwrap();
        let ipv6 = ethernet.parse::<Ipv6>().unwrap();
        let mut advert = ipv6.parse::<RouterAdvertisement<Ipv6>>().unwrap();
        let mut options = advert.options_mut();
        let mut iter = options.iter();

        let mut pass = false;
        while let Some(mut option) = iter.next().unwrap() {
            if let Ok(mtu) = option.downcast::<Mtu<'_>>() {
                assert_eq!(NdpOptionTypes::Mtu, mtu.option_type());
                assert_eq!(1, mtu.length());
                assert_eq!(1500, mtu.mtu());

                pass = true;
                break;
            }
        }

        assert!(pass);
    }

    #[capsule::test]
    fn push_and_set_mtu() {
        let packet = Mbuf::new().unwrap();
        let ethernet = packet.push::<Ethernet>().unwrap();
        let ipv6 = ethernet.push::<Ipv6>().unwrap();
        let mut advert = ipv6.push::<RouterAdvertisement<Ipv6>>().unwrap();
        let mut options = advert.options_mut();
        let mut mtu = options.append::<Mtu<'_>>().unwrap();

        assert_eq!(NdpOptionTypes::Mtu, mtu.option_type());
        assert_eq!(1, mtu.length());
        assert_eq!(0, mtu.mtu());

        mtu.set_mtu(1280);
        assert_eq!(1280, mtu.mtu());
    }
}
