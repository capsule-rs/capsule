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

use super::{NdpOption, MTU};
use crate::packets::ParseError;
use crate::{ensure, Mbuf, Result, SizeOf};
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
/// Type            5
///
/// Length          1
///
/// Reserved        This field is unused.  It MUST be initialized to
///                 zero by the sender and MUST be ignored by the
///                 receiver.
///
/// MTU             32-bit unsigned integer.  The recommended MTU for
///                 the link.
///
/// [IETF RFC 4861]: https://tools.ietf.org/html/rfc4861#section-4.6.4
pub struct Mtu {
    fields: NonNull<MtuFields>,
    offset: usize,
}

impl Mtu {
    /// Parses the MTU option from the message buffer at offset.
    #[inline]
    pub fn parse(mbuf: &Mbuf, offset: usize) -> Result<Mtu> {
        let fields = mbuf.read_data::<MtuFields>(offset)?;

        ensure!(
            unsafe { fields.as_ref().length } == (MtuFields::size_of() as u8 / 8),
            ParseError::new("Invalid MTU option length.")
        );

        Ok(Mtu { fields, offset })
    }

    /// Returns the message buffer offset for this option.
    pub fn offset(&self) -> usize {
        self.offset
    }

    #[inline]
    fn fields(&self) -> &MtuFields {
        unsafe { self.fields.as_ref() }
    }

    #[inline]
    fn fields_mut(&mut self) -> &mut MtuFields {
        unsafe { self.fields.as_mut() }
    }

    /// Returns the option type. Should always be `5`.
    #[inline]
    pub fn option_type(&self) -> u8 {
        self.fields().option_type
    }

    /// Returns the length of the option measured in units of 8 octets.
    /// Should always be `1`.
    pub fn length(&self) -> u8 {
        self.fields().length
    }

    /// Returns the recommended MTU for the link.
    pub fn mtu(&self) -> u32 {
        u32::from_be(self.fields().mtu)
    }

    /// Sets the recommended MTU for the link.
    pub fn set_mtu(&mut self, mtu: u32) {
        self.fields_mut().mtu = u32::to_be(mtu);
    }
}

impl fmt::Debug for Mtu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("link layer address")
            .field("type", &self.option_type())
            .field("length", &self.length())
            .field("mtu", &self.mtu())
            .finish()
    }
}

impl NdpOption for Mtu {
    #[inline]
    fn do_push(mbuf: &mut Mbuf) -> Result<Self>
    where
        Self: Sized,
    {
        let offset = mbuf.data_len();
        mbuf.extend(offset, MtuFields::size_of())?;
        let fields = mbuf.write_data(offset, &MtuFields::default())?;
        Ok(Mtu { fields, offset })
    }
}

/// MTU option fields.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_of_mtu() {
        assert_eq!(8, MtuFields::size_of());
    }
}
