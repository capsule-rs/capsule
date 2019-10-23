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

use super::{NdpOption, PREFIX_INFORMATION};
use crate::packets::ParseError;
use crate::{ensure, Mbuf, Result, SizeOf};
use std::fmt;
use std::net::Ipv6Addr;
use std::ptr::NonNull;

/*  From https://tools.ietf.org/html/rfc4861#section-4.6.2
    Prefix Information

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |    Length     | Prefix Length |L|A| Reserved1 |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Valid Lifetime                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Preferred Lifetime                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           Reserved2                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                                                               +
    |                                                               |
    +                            Prefix                             +
    |                                                               |
    +                                                               +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Type            3

    Length          4

    Prefix Length   8-bit unsigned integer.  The number of leading bits
                    in the Prefix that are valid.  The value ranges
                    from 0 to 128.  The prefix length field provides
                    necessary information for on-link determination
                    (when combined with the L flag in the prefix
                    information option).  It also assists with address
                    autoconfiguration as specified in [ADDRCONF], for
                    which there may be more restrictions on the prefix
                    length.

    L               1-bit on-link flag.  When set, indicates that this
                    prefix can be used for on-link determination.  When
                    not set the advertisement makes no statement about
                    on-link or off-link properties of the prefix.  In
                    other words, if the L flag is not set a host MUST
                    NOT conclude that an address derived from the
                    prefix is off-link.  That is, it MUST NOT update a
                    previous indication that the address is on-link.

    A               1-bit autonomous address-configuration flag.  When
                    set indicates that this prefix can be used for
                    stateless address configuration as specified in
                    [ADDRCONF].

    Reserved1       6-bit unused field.  It MUST be initialized to zero
                    by the sender and MUST be ignored by the receiver.

    Valid Lifetime
                    32-bit unsigned integer.  The length of time in
                    seconds (relative to the time the packet is sent)
                    that the prefix is valid for the purpose of on-link
                    determination.  A value of all one bits
                    (0xffffffff) represents infinity.  The Valid
                    Lifetime is also used by [ADDRCONF].

    Preferred Lifetime
                    32-bit unsigned integer.  The length of time in
                    seconds (relative to the time the packet is sent)
                    that addresses generated from the prefix via
                    stateless address autoconfiguration remain
                    preferred [ADDRCONF].  A value of all one bits
                    (0xffffffff) represents infinity.  See [ADDRCONF].
                    Note that the value of this field MUST NOT exceed
                    the Valid Lifetime field to avoid preferring
                    addresses that are no longer valid.

    Reserved2       This field is unused.  It MUST be initialized to
                    zero by the sender and MUST be ignored by the
                    receiver.

    Prefix          An IP address or a prefix of an IP address.  The
                    Prefix Length field contains the number of valid
                    leading bits in the prefix.  The bits in the prefix
                    after the prefix length are reserved and MUST be
                    initialized to zero by the sender and ignored by
                    the receiver.  A router SHOULD NOT send a prefix
                    option for the link-local prefix and a host SHOULD
                    ignore such a prefix option.
*/

const ONLINK: u8 = 0b1000_0000;
const AUTO: u8 = 0b0100_0000;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct PrefixInformationFields {
    option_type: u8,
    length: u8,
    prefix_length: u8,
    flags: u8,
    valid_lifetime: u32,
    preferred_lifetime: u32,
    reserved: u32,
    prefix: Ipv6Addr,
}

impl Default for PrefixInformationFields {
    fn default() -> PrefixInformationFields {
        PrefixInformationFields {
            option_type: PREFIX_INFORMATION,
            length: 4,
            prefix_length: 0,
            flags: 0,
            valid_lifetime: 0,
            preferred_lifetime: 0,
            reserved: 0,
            prefix: Ipv6Addr::UNSPECIFIED,
        }
    }
}

/// Prefix information option.
pub struct PrefixInformation {
    fields: NonNull<PrefixInformationFields>,
    offset: usize,
}

impl PrefixInformation {
    /// Parses the prefix information option from the message buffer at offset.
    #[inline]
    pub fn parse(mbuf: &Mbuf, offset: usize) -> Result<PrefixInformation> {
        let fields = mbuf.read_data::<PrefixInformationFields>(offset)?;

        ensure!(
            unsafe { fields.as_ref().length } == (PrefixInformationFields::size_of() as u8 / 8),
            ParseError::new("Invalid prefix information option length.")
        );

        Ok(PrefixInformation { fields, offset })
    }

    /// Returns the message buffer offset for this option.
    pub fn offset(&self) -> usize {
        self.offset
    }

    #[inline]
    fn fields(&self) -> &PrefixInformationFields {
        unsafe { self.fields.as_ref() }
    }

    #[inline]
    fn fields_mut(&mut self) -> &mut PrefixInformationFields {
        unsafe { self.fields.as_mut() }
    }

    #[inline]
    pub fn option_type(&self) -> u8 {
        self.fields().option_type
    }

    #[inline]
    pub fn length(&self) -> u8 {
        self.fields().length
    }

    #[inline]
    pub fn prefix_length(&self) -> u8 {
        self.fields().prefix_length
    }

    #[inline]
    pub fn set_prefix_length(&mut self, prefix_length: u8) {
        self.fields_mut().prefix_length = prefix_length
    }

    #[inline]
    pub fn on_link(&self) -> bool {
        self.fields().flags & ONLINK > 0
    }

    #[inline]
    pub fn set_on_link(&mut self) {
        self.fields_mut().flags |= ONLINK;
    }

    #[inline]
    pub fn unset_on_link(&mut self) {
        self.fields_mut().flags &= !ONLINK;
    }

    #[inline]
    pub fn autonomous(&self) -> bool {
        self.fields().flags & AUTO > 0
    }

    #[inline]
    pub fn set_autonomous(&mut self) {
        self.fields_mut().flags |= AUTO;
    }

    #[inline]
    pub fn unset_autonomous(&mut self) {
        self.fields_mut().flags &= !AUTO;
    }

    #[inline]
    pub fn valid_lifetime(&self) -> u32 {
        u32::from_be(self.fields().valid_lifetime)
    }

    #[inline]
    pub fn set_valid_lifetime(&mut self, valid_lifetime: u32) {
        self.fields_mut().valid_lifetime = u32::to_be(valid_lifetime);
    }

    #[inline]
    pub fn preferred_lifetime(&self) -> u32 {
        u32::from_be(self.fields().preferred_lifetime)
    }

    #[inline]
    pub fn set_preferred_lifetime(&mut self, preferred_lifetime: u32) {
        self.fields_mut().preferred_lifetime = u32::to_be(preferred_lifetime);
    }

    #[inline]
    pub fn prefix(&self) -> Ipv6Addr {
        self.fields().prefix
    }

    #[inline]
    pub fn set_prefix(&mut self, prefix: Ipv6Addr) {
        self.fields_mut().prefix = prefix;
    }
}

impl fmt::Debug for PrefixInformation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("prefix information")
            .field("type", &self.option_type())
            .field("length", &self.length())
            .field("prefix_length", &self.prefix_length())
            .field("on_link", &self.on_link())
            .field("autonomous", &self.autonomous())
            .field("valid_lifetime", &self.valid_lifetime())
            .field("preferred_lifetime", &self.preferred_lifetime())
            .field("prefix", &self.prefix())
            .finish()
    }
}

impl NdpOption for PrefixInformation {
    #[inline]
    fn do_push(mbuf: &mut Mbuf) -> Result<Self>
    where
        Self: Sized,
    {
        let offset = mbuf.data_len();
        mbuf.extend(offset, PrefixInformationFields::size_of())?;
        let fields = mbuf.write_data(offset, &PrefixInformationFields::default())?;
        Ok(PrefixInformation { fields, offset })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_of_prefix_information() {
        assert_eq!(32, PrefixInformationFields::size_of());
    }
}
