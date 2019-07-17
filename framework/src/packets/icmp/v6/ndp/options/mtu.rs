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

#![allow(clippy::mut_from_ref)]

use super::MTU;
use crate::packets::icmp::v6::ndp::NdpOption;
use crate::packets::{buffer, Fixed, ParseError};
use std::fmt;

/*  From https://tools.ietf.org/html/rfc4861#section-4.6.4
    MTU

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |    Length     |           Reserved            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                              MTU                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Type            5

    Length          1

    Reserved        This field is unused.  It MUST be initialized to
                    zero by the sender and MUST be ignored by the
                    receiver.

    MTU             32-bit unsigned integer.  The recommended MTU for
                    the link.
*/

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct MtuFields {
    option_type: u8,
    length: u8,
    reserved: u16,
    mtu: u32,
}

impl Default for MtuFields {
    fn default() -> MtuFields {
        MtuFields {
            option_type: MTU,
            length: 1,
            reserved: 0,
            mtu: 0,
        }
    }
}

/// Maximum transmission unit option
pub struct Mtu {
    fields: *mut MtuFields,
    offset: usize,
}

impl Mtu {
    /// Parses the MTU option from the message buffer at offset
    #[inline]
    pub fn parse(mbuf: *mut MBuf, offset: usize) -> Result<Mtu> {
        let fields = buffer::read_item::<MtuFields>(mbuf, offset)?;
        if unsafe { (*fields).length } != (MtuFields::size() as u8 / 8) {
            Err(ParseError::new("Invalid MTU option length").into())
        } else {
            Ok(Mtu { fields, offset })
        }
    }

    /// Returns the message buffer offset for this option
    pub fn offset(&self) -> usize {
        self.offset
    }

    #[inline]
    fn fields(&self) -> &MtuFields {
        unsafe { &(*self.fields) }
    }

    #[inline]
    fn fields_mut(&mut self) -> &mut MtuFields {
        unsafe { &mut (*self.fields) }
    }

    #[inline]
    pub fn option_type(&self) -> u8 {
        self.fields().option_type
    }

    pub fn length(&self) -> u8 {
        self.fields().length
    }

    pub fn mtu(&self) -> u32 {
        u32::from_be(self.fields().mtu)
    }

    pub fn set_mtu(&mut self, mtu: u32) {
        self.fields_mut().mtu = u32::to_be(mtu);
    }
}

impl fmt::Display for Mtu {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "type: {}, length: {}, mtu: {}",
            self.option_type(),
            self.length(),
            self.mtu()
        )
    }
}

impl NdpOption for Mtu {
    #![allow(clippy::not_unsafe_ptr_arg_deref)]
    #[inline]
    fn do_push(mbuf: *mut MBuf) -> Result<Self>
    where
        Self: Sized,
    {
        let offset = unsafe { (*mbuf).data_len() };

        buffer::alloc(mbuf, offset, MtuFields::size())?;

        let fields = buffer::write_item::<MtuFields>(mbuf, offset, &Default::default())?;
        Ok(Mtu { fields, offset })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_of_mtu() {
        assert_eq!(8, MtuFields::size());
    }

}
