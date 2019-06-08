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
use failure::Error;

/// Lazily-evaluate foreach operator
///
/// Works on reference of packet for side-effects.
///
/// On error, the packet is marked as aborted and will short-circuit the
/// remainder of the pipeline.
pub struct ForEachBatch<B: Batch, F>
where
    F: FnMut(&B::Item) -> Result<(), Error>,
{
    source: B,
    fun: F,
}

impl<B: Batch, F> ForEachBatch<B, F>
where
    F: FnMut(&B::Item) -> Result<(), Error>,
{
    #[inline]
    pub fn new(source: B, fun: F) -> Self {
        ForEachBatch { source, fun }
    }
}

impl<B: Batch, F> Batch for ForEachBatch<B, F>
where
    F: FnMut(&B::Item) -> Result<(), Error>,
{
    type Item = B::Item;

    #[inline]
    fn next(&mut self) -> Option<Result<Self::Item, PacketError>> {
        self.source.next().map(|item| match item {
            Ok(packet) => match (self.fun)(&packet) {
                Ok(_) => Ok(packet),
                Err(e) => Err(PacketError::Abort(packet.mbuf(), e)),
            },
            Err(e) => Err(e),
        })
    }

    #[inline]
    fn receive(&mut self) {
        self.source.receive();
    }
}
