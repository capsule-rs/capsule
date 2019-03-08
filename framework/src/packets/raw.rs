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

use std::ptr;
use packets::{Packet, Header};

/// empty header
pub struct NullHeader;

impl Header for NullHeader {
    fn size() -> usize {
        0
    }
}

/// raw network packet
///
/// simply a wrapper around the underlying buffer
pub struct RawPacket<> {
    mbuf: *mut MBuf
}

impl RawPacket {
    /// allocates a new packet
    pub fn new() -> Result<Self> {
        unsafe {
            let mbuf = mbuf_alloc();
            if mbuf.is_null() {
                Err(NetBricksError::FailedAllocation.into())
            } else {
                Ok(RawPacket { mbuf })
            }
        }
    }

    /// new packet from a byte array
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let packet = RawPacket::new()?;
        packet.extend(bytes.len())?;
        unsafe {
            ptr::copy_nonoverlapping(
                &bytes[0] as *const u8,
                (*packet.mbuf).data_address(0) as *mut u8,
                bytes.len()
            )
        }
        Ok(packet)
    }
}

impl Packet for RawPacket {
    type Header = NullHeader;
    type PreviousPacket = RawPacket;

    #[inline]
    fn from_packet(previous: Self::PreviousPacket,
                   _mbuf: *mut MBuf,
                   _offset: usize,
                   _header: *mut Self::Header) -> Self {
        previous
    }

    #[inline]
    fn mbuf(&self) -> *mut MBuf {
        self.mbuf
    }

    #[inline]
    fn offset(&self) -> usize {
        0
    }

    #[inline]
    fn header(&self) -> &mut Self::Header {
        unsafe {
            &mut (*self.get_mut_item::<Self::Header>(0))
        }
    }

    #[inline]
    fn header_len(&self) -> usize {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dpdk_test;
    use tests::V6_BYTES;

    #[test]
    fn new_raw_packet() {
        dpdk_test! {
            assert!(RawPacket::new().is_ok());
        }
    }

    #[test]
    fn raw_packet_from_bytes() {
        dpdk_test! {
            assert!(RawPacket::from_bytes(&V6_BYTES).is_ok());
        }
    }

    #[test]
    fn extend_packet() {
        dpdk_test! {
            let packet = RawPacket::new().unwrap();
            packet.extend(200).unwrap();
            assert_eq!(packet.len(), 200);
        }
    }

    #[test]
    fn exceed_mbuf_tailroom() {
        dpdk_test! {
            let packet = RawPacket::new().unwrap();
            assert!(packet.extend(999999).is_err());
        }
    }
}
