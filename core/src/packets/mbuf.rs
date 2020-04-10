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

use crate::packets::Packet;
use crate::Mbuf;
use failure::Fallible;

// make the message buffer behave like a packet.
impl Packet for Mbuf {
    #[doc(hidden)]
    #[inline]
    fn mbuf(&self) -> &Mbuf {
        self
    }

    #[doc(hidden)]
    #[inline]
    fn mbuf_mut(&mut self) -> &mut Mbuf {
        self
    }

    #[inline]
    fn envelope(&self) -> &Self::Envelope {
        self
    }

    #[inline]
    fn envelope_mut(&mut self) -> &mut Self::Envelope {
        self
    }

    #[doc(hidden)]
    #[inline]
    fn header(&self) -> &Self::Header {
        unreachable!("raw packet has no defined header!");
    }

    #[doc(hidden)]
    #[inline]
    fn header_mut(&mut self) -> &mut Self::Header {
        unreachable!("raw packet has no defined header!");
    }

    #[inline]
    fn offset(&self) -> usize {
        0
    }

    #[inline]
    fn header_len(&self) -> usize {
        0
    }

    #[inline]
    fn remove(self) -> Fallible<Self::Envelope> {
        Ok(self)
    }

    #[inline]
    fn cascade(&mut self) {
        // noop
    }

    #[inline]
    fn deparse(self) -> Self::Envelope {
        self
    }

    #[inline]
    fn reset(self) -> Mbuf {
        self
    }
}
