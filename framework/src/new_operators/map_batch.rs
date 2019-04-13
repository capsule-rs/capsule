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

use super::{Batch, PacketError};
use failure::Error;
use packets::Packet;

/// Lazily-evaluate map operator
///
/// On error, the packet is marked as aborted and will short-circuit the
/// remainder of the pipeline.
pub struct MapBatch<B: Batch, T: Packet, M>
where
    M: FnMut(B::Item) -> Result<T, Error>,
{
    source: B,
    map: M,
}

impl<B: Batch, T: Packet, M> MapBatch<B, T, M>
where
    M: FnMut(B::Item) -> Result<T, Error>,
{
    #[inline]
    pub fn new(source: B, map: M) -> Self {
        MapBatch { source, map }
    }
}

impl<B: Batch, T: Packet, M> Batch for MapBatch<B, T, M>
where
    M: FnMut(B::Item) -> Result<T, Error>,
{
    type Item = T;

    #[inline]
    fn next(&mut self) -> Option<Result<Self::Item, PacketError>> {
        self.source.next().map(|item| {
            match item {
                Ok(packet) => {
                    // TODO: can this be more efficient?
                    let mbuf = packet.mbuf();
                    (self.map)(packet).map_err(|e| PacketError::Abort(mbuf, e))
                }
                Err(e) => Err(e),
            }
        })
    }

    #[inline]
    fn receive(&mut self) {
        self.source.receive();
    }
}
