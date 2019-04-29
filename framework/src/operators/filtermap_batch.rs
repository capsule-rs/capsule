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

/// Lazily-evaluate filter_map operator
///
/// On error, the packet is marked as aborted and will short-circuit the
/// remainder of the pipeline.
pub struct FilterMapBatch<B: Batch, T: Packet, F>
where
    F: FnMut(B::Item) -> Result<Option<T>, Error>,
{
    source: B,
    f: F,
}

impl<B: Batch, T: Packet, F> FilterMapBatch<B, T, F>
where
    F: FnMut(B::Item) -> Result<Option<T>, Error>,
{
    #[inline]
    pub fn new(source: B, f: F) -> Self {
        FilterMapBatch { source, f }
    }
}

impl<B: Batch, T: Packet, F> Batch for FilterMapBatch<B, T, F>
where
    F: FnMut(B::Item) -> Result<Option<T>, Error>,
{
    type Item = T;

    #[inline]
    fn next(&mut self) -> Option<Result<Self::Item, PacketError>> {
        self.source.next().map(|item| match item {
            Ok(packet) => {
                let mbuf = packet.mbuf();
                match (self.f)(packet) {
                    Ok(Some(p)) => Ok(p),
                    Ok(None) => Err(PacketError::Drop(mbuf)),
                    Err(e) => Err(PacketError::Abort(mbuf, e)),
                }
            }
            Err(e) => Err(e),
        })
    }

    #[inline]
    fn receive(&mut self) {
        self.source.receive();
    }
}
