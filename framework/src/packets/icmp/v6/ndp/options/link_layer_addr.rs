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

#![allow(clippy::not_unsafe_ptr_arg_deref, clippy::mut_from_ref)]

use packets::{buffer, Fixed, MacAddr, ParseError};
use std::fmt;

/*  From https://tools.ietf.org/html/rfc4861#section-4.6.1
    Source/Target Link-layer Address

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |    Length     |    Link-Layer Address ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Type            1 for Source Link-layer Address
                    2 for Target Link-layer Address

    Length          The length of the option (including the type and
                    length fields) in units of 8 octets.  For example,
                    the length for IEEE 802 addresses is 1.

    Link-Layer Address
                    The variable length link-layer address.

                    The content and format of this field (including
                    byte and bit ordering) is expected to be specified
                    in specific documents that describe how IPv6
                    operates over different link layers.
*/

#[derive(Debug)]
#[repr(C, packed)]
struct LinkLayerAddressFields {
    option_type: u8,
    length: u8,
    addr: MacAddr,
}

/// Link-layer address option
pub struct LinkLayerAddress {
    fields: *mut LinkLayerAddressFields,
    offset: usize,
}

impl LinkLayerAddress {
    /// Parses the link-layer address option from the message buffer at offset
    #[inline]
    pub fn parse(mbuf: *mut MBuf, offset: usize) -> Result<LinkLayerAddress> {
        let fields = buffer::read_item::<LinkLayerAddressFields>(mbuf, offset)?;
        if unsafe { (*fields).length } != (LinkLayerAddressFields::size() as u8 / 8) {
            Err(ParseError::new("Invalid link-layer address option length").into())
        } else {
            Ok(LinkLayerAddress { fields, offset })
        }
    }

    /// Returns the message buffer offset for this option
    pub fn offset(&self) -> usize {
        self.offset
    }

    #[inline]
    fn fields(&self) -> &mut LinkLayerAddressFields {
        unsafe { &mut (*self.fields) }
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
    pub fn addr(&self) -> MacAddr {
        self.fields().addr
    }

    #[inline]
    pub fn set_addr(&mut self, addr: MacAddr) {
        self.fields().addr = addr;
    }
}

impl fmt::Display for LinkLayerAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "type: {}, length: {}, addr: {}",
            self.option_type(),
            self.length(),
            self.addr()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_of_link_layer_address() {
        assert_eq!(8, LinkLayerAddressFields::size());
    }
}
