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
use crate::packets::Packet;

/// Lazily-evaluated filter operator
///
/// If the predicate evaluates to `false`, the packet is marked as
/// dropped and will short-circuit the remainder of the pipeline.
pub struct FilterBatch<B: Batch, P>
where
    P: FnMut(&B::Item) -> bool,
{
    source: B,
    predicate: P,
}

impl<B: Batch, P> FilterBatch<B, P>
where
    P: FnMut(&B::Item) -> bool,
{
    #[inline]
    pub fn new(source: B, predicate: P) -> Self {
        FilterBatch { source, predicate }
    }
}

impl<B: Batch, P> Batch for FilterBatch<B, P>
where
    P: FnMut(&B::Item) -> bool,
{
    type Item = B::Item;

    #[inline]
    fn next(&mut self) -> Option<Result<Self::Item, PacketError>> {
        self.source.next().map(|item| match item {
            Ok(packet) => {
                if (self.predicate)(&packet) {
                    Ok(packet)
                } else {
                    Err(PacketError::Drop(packet.mbuf()))
                }
            }
            e @ Err(_) => e,
        })
    }

    #[inline]
    fn receive(&mut self) {
        self.source.receive();
    }
}
